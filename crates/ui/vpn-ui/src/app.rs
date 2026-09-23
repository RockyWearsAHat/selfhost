//! The window: its state, the actions its controls fire, and the one description
//! of everything on screen.
//!
//! The state a handler mutates is [`Panel`]. The tunnel and the slow actions
//! (rotating a key, opening the console) run off this thread and report back
//! through a shared [`Activity`]; the view reads both once per frame, so the
//! window never blocks on the network or a password prompt.

use crate::keys::{self, Identity};
use crate::tunnel::{Endpoint, Link, Phase, Tunnel};
use crate::style::{SPACE_L, SPACE_M, SPACE_S, SPACE_XL, SPACE_XS};
use crate::{actions, hero, style, surface};
use rui::style::Radius;
use rui::{
    Align, App, El, Key, Modifiers, Size, Status, Tone, button, caption, code, col, field_row, heading, micro, row,
    spacer, text,
};
use rui::tray::{Tray, TrayEvent, TrayMenuItem};
use rui::{PanelWindow, panel_window::{PanelOptions, Widget}};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// The tag a mini-panel button reports itself back with when clicked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MiniAction {
    /// Connect, Disconnect, or Cancel, whichever the tunnel's current phase calls for.
    Primary,
    /// Open the admin console.
    Console,
    /// Quit, after confirming the tunnel will be torn down.
    Quit,
}

impl MiniAction {
    fn from_tag(tag: i64) -> Option<Self> {
        match tag {
            1 => Some(MiniAction::Primary),
            2 => Some(MiniAction::Console),
            3 => Some(MiniAction::Quit),
            _ => None,
        }
    }
}

/// The compact dropdown panel a tray click opens: the real controls, just
/// small — not the placeholder empty window this replaces, and not the
/// full-size main window either.
struct MiniPanel {
    window: PanelWindow,
    status: Widget,
    detail: Widget,
    primary: Widget,
    quit: Widget,
    last_word: std::cell::Cell<&'static str>,
}

/// The mini panel's fixed footprint, in points.
const MINI_WIDTH: f64 = 248.0;
const MINI_HEIGHT: f64 = 156.0;

/// Builds the mini panel's controls once. Actions are reported through
/// `actions` rather than captured directly: the click arrives on an AppKit
/// callback with no reference to the running [`Panel`], so it is queued and
/// drained on the next frame exactly as tray clicks already are.
fn build_mini_panel(actions: Arc<Mutex<Vec<MiniAction>>>) -> Result<MiniPanel, String> {
    let options = PanelOptions::new(0.0, 0.0, MINI_WIDTH, MINI_HEIGHT);
    let window = PanelWindow::new(options).map_err(|e| format!("{e:?}"))?;
    // The main window's own palette (style.rs), not a fresh guess — this is
    // the same dark ground and cyan accent the full window uses, so the
    // dropdown reads as the same app rather than a generic system panel.
    let _ = window.style(NIGHT, 14.0, BORDER, 1.0);

    let pad = 14.0;
    let inner = MINI_WIDTH - pad * 2.0;

    if let Ok(title) = window.add_label(pad, MINI_HEIGHT - 30.0, inner - 14.0, 18.0, "SELFHOST VPN") {
        let _ = window.set_text_color(&title, INK);
    }
    let status = window
        .add_label(pad, MINI_HEIGHT - 52.0, inner, 20.0, "OFFLINE")
        .map_err(|e| format!("{e:?}"))?;
    let detail = window
        .add_label(pad, MINI_HEIGHT - 72.0, inner, 16.0, &endpoint_label())
        .map_err(|e| format!("{e:?}"))?;
    let _ = window.set_text_color(&detail, MUTED);

    let primary = window
        .add_button(pad, 44.0, inner, 28.0, "Connect", 1)
        .map_err(|e| format!("{e:?}"))?;
    let _ = window.set_button_tint(&primary, ACCENT, true);
    let half = (inner - 8.0) / 2.0;
    if let Ok(console) = window.add_button(pad, 12.0, half, 26.0, "Console", 2) {
        let _ = window.set_button_tint(&console, RAISED, false);
    }
    let quit =
        window.add_button(pad + half + 8.0, 12.0, half, 26.0, "Quit", 3).map_err(|e| format!("{e:?}"))?;
    let _ = window.set_button_tint(&quit, RED, false);

    window
        .on_action(move |tag| {
            if let Some(action) = MiniAction::from_tag(tag) {
                if let Ok(mut queue) = actions.lock() {
                    queue.push(action);
                }
            }
        })
        .map_err(|e| format!("{e:?}"))?;
    let mini = MiniPanel { window, status, detail, primary, quit, last_word: std::cell::Cell::new("") };
    // The status label's own tint needs setting once outside refresh (which
    // only runs on a state *change*, and a freshly built panel has none yet).
    let _ = mini.window.set_text_color(&mini.status, SLATE);
    Ok(mini)
}

/// The main window's own palette (`style.rs`), as plain sRGB — the mini
/// panel's controls are native AppKit, not `rui` elements, so they take raw
/// color rather than a `rui::Color`/`Tone`. Converted from the very same
/// constants rather than copied, so the two surfaces cannot drift apart.
const NIGHT: (f32, f32, f32) = srgb(style::NIGHT);
const ACCENT: (f32, f32, f32) = srgb(style::ACCENT);
const RAISED: (f32, f32, f32) = srgb(style::RAISED);
const BORDER: (f32, f32, f32) = srgb(style::BORDER);
const CYAN: (f32, f32, f32) = srgb(style::CYAN);
const AMBER: (f32, f32, f32) = srgb(style::AMBER);
const RED: (f32, f32, f32) = srgb(style::RED);
const SLATE: (f32, f32, f32) = srgb(style::SLATE);
const INK: (f32, f32, f32) = srgb(style::INK);
const MUTED: (f32, f32, f32) = srgb(style::MUTED);

/// A palette colour as the plain sRGB triple AppKit takes, evaluable in a
/// `const` so the triples above are constants.
const fn srgb(color: rui::Color) -> (f32, f32, f32) {
    (color.r as f32 / 255.0, color.g as f32 / 255.0, color.b as f32 / 255.0)
}

/// Redraws the mini panel's status line and primary button for the current
/// link state.
///
/// Every `set_text`/`set_text_color` call round-trips into AppKit, so this
/// skips them entirely once the state word stops changing — the common case,
/// since the panel is only ever open a few seconds at a time and the tunnel's
/// phase rarely flips within that window.
fn refresh_mini_panel(mini: &MiniPanel, link: &Link) {
    let word = state_word(link);
    if mini.last_word.get() == word {
        return;
    }
    mini.last_word.set(word);

    let up = link.phase.is_up();
    let reaching = link.phase.is_reaching();
    let _ = mini.window.set_text(&mini.status, word);
    let _ = mini.window.set_text_color(&mini.status, status_rgb(link));
    let primary_label = if up { "Disconnect" } else if reaching { "Cancel" } else { "Connect" };
    let _ = mini.window.set_text(&mini.primary, primary_label);
    let _ = mini.window.set_enabled(&mini.quit, true);
    let _ = mini.window.set_text(&mini.detail, &endpoint_label());
}

/// The status word's color, matching the main window's [`status_of`]/[`Tone`]
/// mapping (and [`style::hue`]'s) but as plain sRGB.
fn status_rgb(link: &Link) -> (f32, f32, f32) {
    match link.phase {
        Phase::Off => SLATE,
        Phase::Dialling | Phase::Authenticated => AMBER,
        Phase::Up => CYAN,
        Phase::Failed(_) => RED,
    }
}

/// Asks, via a native dialog, whether the user really wants to quit — quitting
/// tears the tunnel down, unlike the old detach-and-leave-it-running Quit.
/// Returns `true` only if the user picked the destructive button.
///
/// A real `NSAlert` (see [`crate::macos_native::confirm_quit_native`]) rather
/// than `osascript -e 'display dialog ...'`: the old call needed nothing from
/// the system beyond drawing a window either, but any `osascript` failure —
/// including one this app never diagnosed — read as `Ok(status) if
/// status.success()` being false, which this function silently treated as
/// "Cancel". That is exactly the reported "Quit does nothing".
fn confirm_quit() -> bool {
    #[cfg(target_os = "macos")]
    {
        crate::macos_native::confirm_quit_native()
    }
    #[cfg(not(target_os = "macos"))]
    {
        true
    }
}

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
    /// Track the previous visibility state to avoid redundant macOS calls.
    previous_visible: bool,
    /// The mini dropdown panel, built lazily the first time it is shown.
    mini: Option<MiniPanel>,
    /// Whether the panel should be shown or hidden.
    panel_should_show: bool,
    /// The tray icon's screen position from the last event.
    panel_anchor_pos: Option<(f64, f64)>,
    /// Button presses from the mini panel, queued by its `on_action`
    /// callback (an AppKit thread with no reference to this `Panel`) and
    /// drained on the next frame.
    mini_actions: Arc<Mutex<Vec<MiniAction>>>,
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
        let mut tunnel = Tunnel::new(endpoint);

        // If a tunnel was already running and we adopted it, connect() to
        // start reading its state. If managed, it was created in Off state.
        if !tunnel.is_managed() {
            tunnel.connect();
        }

        Self {
            tunnel,
            activity,
            auto_rotate: Arc::new(AtomicBool::new(true)),
            running,
            tray: None,
            window_visible: true,
            tray_created: false,
            previous_visible: true,
            mini: None,
            panel_should_show: false,
            panel_anchor_pos: None,
            mini_actions: Arc::new(Mutex::new(Vec::new())),
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
            previous_visible: true,
            mini: None,
            panel_should_show: false,
            panel_anchor_pos: None,
            mini_actions: Arc::new(Mutex::new(Vec::new())),
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

    /// Hide the main window: a direct AppKit call, not a shell-out.
    ///
    /// Used to run `osascript -e 'tell application "System Events" ...'`,
    /// which needs Automation permission this app has likely never been
    /// granted — a permission prompt the button should never need at all,
    /// since this is the app's own window, in its own process.
    /// [`crate::macos_native::set_main_window_visible`] asks `NSApplication`
    /// directly instead.
    fn hide_window(&self, title: &str) {
        #[cfg(target_os = "macos")]
        {
            crate::macos_native::set_main_window_visible(title, false);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = title;
        }
    }

    /// Show the main window: a direct AppKit call, not a shell-out. See
    /// [`Panel::hide_window`].
    fn show_window(&self, title: &str) {
        #[cfg(target_os = "macos")]
        {
            crate::macos_native::set_main_window_visible(title, true);
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = title;
        }
    }

    /// Create and store the system tray icon.
    ///
    /// Called from [`Panel::drain_tray_events`] on the first frame rather than
    /// before `panel.run()` starts: AppKit's run loop and `NSApplication`
    /// are not actually active until the pump loop begins, so an
    /// `NSStatusItem` created any earlier reports success but is never drawn
    /// or registered — confirmed live (an `osascript` accessibility check
    /// found no status item at all) before this was moved here.
    pub fn create_tray(&mut self) -> Result<(), String> {
        let icon_data = include_bytes!("../assets/tray-icon.png");
        let tray = Tray::new_with_panel(icon_data, "SelfHost VPN")
            .map_err(|e| format!("Tray creation failed: {:?}", e))?;
        // Tray::new creates the status item with a blank placeholder image.
        let _ = tray.set_icon(icon_data);

        self.tray = Some(tray);

        // Always update the tray menu with current state (before enabling panel mode)
        self.update_tray_menu();

        // Enable panel mode for the tray icon AFTER setting the menu
        if let Some(ref mut tray) = self.tray {
            let _ = tray.set_panel_mode(true);
            eprintln!("TRAY: Panel mode enabled");
        }

        Ok(())
    }

    /// Drain and dispatch tray events each frame.
    ///
    /// Called from the `on_frame` callback, so a click reaches
    /// [`Self::handle_tray_event`] on the same thread and the same cadence as
    /// every other state change the window's own buttons already produce —
    /// there is no second, parallel update path for tray-driven actions.
    pub fn drain_tray_events(&mut self) {
        if !self.tray_created {
            let _ = self.create_tray();
            self.tray_created = true;
        }

        if let Some(ref tray) = self.tray {
            let events = tray.drain_events();
            if !events.is_empty() {
                eprintln!("TRAY: Received {} events", events.len());
            }
            for event in events {
                eprintln!("TRAY: Event: {:?}", event);
                self.handle_tray_event(event);
            }
        }
    }

    /// Handle a single tray event, dispatching to the same handlers as UI buttons.
    fn handle_tray_event(&mut self, event: TrayEvent) {
        match event {
            TrayEvent::IconActivated => {
                eprintln!("TRAY: IconActivated event received");
                // In panel mode, convert to panel activation
                if self.mini.is_some() || self.panel_should_show {
                    eprintln!("TRAY: Converting IconActivated to panel activation");
                    self.panel_should_show = !self.panel_should_show;
                } else {
                    // Clicking tray icon toggles main window visibility.
                    // The window serves as the dropdown panel.
                    self.window_visible = !self.window_visible;
                }
            }
            TrayEvent::IconActivatedForPanel { screen_position } => {
                // Panel mode activated: toggle the panel window
                self.panel_should_show = !self.panel_should_show;
                self.panel_anchor_pos = Some(screen_position);
                eprintln!("TRAY: IconActivatedForPanel event received, panel_should_show={}", self.panel_should_show);
            }
            TrayEvent::MenuItemClicked(id) => {
                match id {
                    1 => self.tunnel.connect(),
                    2 => self.tunnel.disconnect(),
                    3 => actions::open_console(self.activity_handle()),
                    4 => actions::open_sara(self.activity_handle()),
                    5 => actions::open_ai_studio(self.activity_handle()),
                    6 => self.quit_with_confirmation(),
                    9999 => {
                        // Panel trigger: toggle panel visibility
                        eprintln!("TRAY: Panel trigger (id=9999) clicked");
                        self.panel_should_show = !self.panel_should_show;
                    }
                    _ => {}
                }
            }
        }
    }

    /// Warns that quitting ends the VPN session, and only on an explicit
    /// "Quit" actually disconnects the tunnel and stops the app.
    ///
    /// Unlike the old detach-and-leave-running Quit, a confirmed quit here
    /// tears the tunnel down: the operator asked for "upon accept, exit and
    /// terminate session", so this Quit is no longer the same button as the
    /// managed-tunnel survival feature — it is a deliberate end of the session.
    fn quit_with_confirmation(&mut self) {
        if !confirm_quit() {
            return;
        }
        self.tunnel.disconnect();
        self.running.store(false, Ordering::Relaxed);
    }

    /// Drain and dispatch mini-panel button presses, queued off-thread by
    /// [`build_mini_panel`]'s `on_action` callback.
    fn drain_mini_actions(&mut self) {
        let pending: Vec<MiniAction> = match self.mini_actions.lock() {
            Ok(mut queue) => queue.drain(..).collect(),
            Err(_) => Vec::new(),
        };
        for action in pending {
            match action {
                MiniAction::Primary => {
                    let link = self.tunnel.link();
                    if link.phase.is_up() || link.phase.is_reaching() {
                        self.tunnel.disconnect();
                    } else {
                        self.tunnel.connect();
                    }
                }
                MiniAction::Console => actions::open_console(self.activity_handle()),
                MiniAction::Quit => self.quit_with_confirmation(),
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
        // Cloned before `title` moves into `application(title, self)` below;
        // the window's title is how hide/show finds the right `NSWindow`
        // among `NSApplication.windows` (see `macos_native::set_main_window_visible`).
        let frame_title = title.clone();

        // on_frame callback: drain and dispatch tray events each frame before rendering.
        // The tray is created on the first frame when the pump loop is active.
        // Also applies window visibility changes when the window_visible flag changes,
        // and manages the panel window lifecycle.
        let on_frame = move |panel: &mut Panel| {
            panel.drain_tray_events();
            panel.drain_mini_actions();
            // Not panel.update_tray_menu() here: that rebuilds the tray's real
            // NSMenu (Connect/Disconnect/Quit as text items), which is exactly
            // the old dropdown the mini panel now replaces. Calling it every
            // frame was clobbering panel mode's single-item menu right back to
            // the full list moments after create_tray() set panel mode up,
            // which is why the tray kept showing the text menu instead of
            // opening the mini panel.

            // Apply window visibility changes
            if panel.window_visible != panel.previous_visible {
                if panel.window_visible {
                    panel.show_window(&frame_title);
                } else {
                    panel.hide_window(&frame_title);
                }
                panel.previous_visible = panel.window_visible;
            }

            // Manage the mini panel's lifecycle: built once on first show,
            // then just shown/hidden/repositioned/refreshed after that.
            if panel.panel_should_show {
                if panel.mini.is_none() {
                    match build_mini_panel(Arc::clone(&panel.mini_actions)) {
                        Ok(mini) => panel.mini = Some(mini),
                        Err(error) => eprintln!("PANEL: failed to build the mini panel: {error}"),
                    }
                }
                if let Some(mini) = &panel.mini {
                    if let Some((x, y)) = panel.panel_anchor_pos {
                        let _ = mini.window.set_position(x - MINI_WIDTH / 2.0, y - MINI_HEIGHT - 8.0);
                    }
                    refresh_mini_panel(mini, &panel.tunnel.link());
                    let _ = mini.window.show();
                }
            } else if let Some(mini) = &panel.mini {
                let _ = mini.window.hide();
            }
        };

        application(title, self)
            .size(WINDOW_WIDTH, WINDOW_HEIGHT)
            .min_size(MIN_WIDTH, MIN_HEIGHT)
            // The red close button hides the window, not the app: the tray
            // icon and the tunnel it supervises must survive it. Only a
            // confirmed Quit (see quit_with_confirmation) clears `running`.
            .close_hides(true)
            // rui's animated frames now replay only the hero's own small
            // canvas (see its fast path: App::has_animated_draws /
            // Surface::draw) instead of repainting the whole window, so this
            // is a genuine smoothness dial rather than a CPU one — a real
            // 120fps ask, not a compromise against cost.
            .animation_fps(120)
            // This is what governs how promptly a background-thread change
            // (the tunnel's Activity, the UP duration's own clock) reaches the
            // screen when nothing else is asking for a frame — every idle_due
            // tick draws one, whether or not anything actually changed, so it
            // is this app's whole idle CPU floor once the hero has nothing to
            // animate. A once-a-second "6m 04s" clock does not need better
            // than one-second resolution; 900ms keeps it looking live without
            // paying for a redraw it can't show anyone yet.
            .idle_timeout(std::time::Duration::from_millis(900))
            .while_running(move |_| running.load(Ordering::Relaxed))
            .on_frame(on_frame)
            .run()
    }
}

/// The panel as an application, in its own theme and ground.
pub fn application(title: impl Into<String>, panel: Panel) -> App<Panel> {
    App::new(title, panel, view).theme(style::theme).ground(style::ground)
}

/// The window's size when it opens, in points.
pub const WINDOW_WIDTH: f32 = 430.0;
/// The window's height when it opens, in points.
pub const WINDOW_HEIGHT: f32 = 640.0;
/// The narrowest the window may be dragged: every label still fits.
pub const MIN_WIDTH: f32 = 380.0;
/// The shortest the window may be dragged: the footer is still on screen.
/// The same as it opens at — the window holds a fixed column of instruments,
/// and there is nothing in it to give up.
pub const MIN_HEIGHT: f32 = WINDOW_HEIGHT;

/// The height of the one primary control, in every state.
const PRIMARY_HEIGHT: f32 = 40.0;
/// The width of the one primary control, in every state.
const PRIMARY_WIDTH: f32 = 220.0;
/// The height of a destination row.
const DESTINATION_HEIGHT: f32 = 38.0;
/// The height of a metric cell.
const METRIC_HEIGHT: f32 = 52.0;
/// The height of the one-line notes the window reserves room for.
const NOTE_HEIGHT: f32 = 14.0;

/// The endpoint as the window says it: host and port.
fn endpoint_label() -> String {
    let endpoint = Endpoint::default();
    format!("{}:{}", endpoint.server_host, endpoint.server_port)
}

/// The whole window, as one description.
///
/// Top to bottom: the light with the state in it, the one primary control,
/// the three destinations, the three readings, the keys, and a footer line
/// for whatever an action last said. Every block holds its geometry across
/// states — a reading that is not there yet shows a dash, a note that does
/// not apply keeps its line — so nothing below the hero ever moves when the
/// tunnel changes.
pub fn view(ui: &Panel) -> El<Panel> {
    let link = ui.tunnel.link();
    let activity = ui.activity();
    let auto = ui.auto_rotate.load(Ordering::Relaxed);
    col((
        hero::hero(&link, &endpoint_label()),
        col((
            primary(&link),
            destinations(&link),
            metrics(&link),
            keys_card(&activity, auto),
            spacer().grow(),
            footer(&activity),
        ))
        .pad_each(SPACE_L, SPACE_XL, SPACE_S, SPACE_XL)
        .gap(SPACE_L)
        .grow(),
    ))
    // The root answers the keyboard (Escape, below), so it states what it is
    // and what it is called rather than being an anonymous group that acts.
    .role(rui::Role::Dialog)
    .label("SelfHost VPN")
    .on_key(|panel: &mut Panel, key: Key, _modifiers: Modifiers| {
        // Escape key hides the window or closes the panel (same as clicking tray icon to toggle)
        if key == Key::Escape {
            if panel.panel_should_show {
                panel.panel_should_show = false;
            } else {
                panel.window_visible = false;
            }
        }
    })
}

/// The one primary control: Connect, Cancel, or Disconnect, whichever the
/// tunnel's phase calls for — one oversized pill, centred, in the same place
/// and at the same size in every state.
///
/// Only Connect wears the accent: it is the action the window is mostly for.
/// Disconnecting a healthy tunnel is routine, so Disconnect is quiet, and red
/// belongs to Failed alone.
fn primary(link: &Link) -> El<Panel> {
    let up = link.phase.is_up();
    let reaching = link.phase.is_reaching();
    let control = if up {
        button("Disconnect").on_click(|panel: &mut Panel| panel.tunnel.disconnect())
    } else if reaching {
        button("Cancel").on_click(|panel: &mut Panel| panel.tunnel.disconnect())
    } else {
        button("Connect").primary().on_click(|panel: &mut Panel| panel.tunnel.connect())
    };
    row((
        spacer().grow(),
        control.pill().w(PRIMARY_WIDTH).h(PRIMARY_HEIGHT).text_size(14.0).bold(),
        spacer().grow(),
    ))
    .h(PRIMARY_HEIGHT)
}

/// The three places the tunnel reaches, as a list: a lamp, the name, the host.
///
/// Each row is a button. They are greyed until the tunnel is up, and the one
/// note under the card says why — on a line the card reserves in every state,
/// so the readings below never shift when the tunnel comes up.
fn destinations(link: &Link) -> El<Panel> {
    let up = status_of(link) == Status::Ok;
    let note = if up { "Open in your browser, through the tunnel." } else { "Connect to open these." };
    col((
        surface::card((
            destination("Admin Console", CONSOLE_HOST, up, |panel| actions::open_console(panel.activity_handle())),
            surface::rule(),
            destination("SARA", SARA_HOST, up, |panel| actions::open_sara(panel.activity_handle())),
            surface::rule(),
            destination("AI Studio", AI_HOST, up, |panel| actions::open_ai_studio(panel.activity_handle())),
        ))
        .pad_y(SPACE_XS),
        row(caption(note).color(Tone::Muted)).pad_x(SPACE_M).h(NOTE_HEIGHT),
    ))
    .gap(SPACE_S)
}

/// One destination row: a lamp lit when it can be opened, the name, and the
/// host in the machine's own face.
fn destination(
    name: &'static str,
    host: &'static str,
    up: bool,
    open: impl Fn(&mut Panel) + 'static,
) -> El<Panel> {
    row((surface::lamp(up), text(name), spacer().grow(), code(host).color(Tone::Muted)))
        .h(DESTINATION_HEIGHT)
        .pad_x(SPACE_M)
        .gap(SPACE_M)
        .align(Align::Center)
        .round(Radius::Control)
        .hover_fill(Tone::Raised)
        .role(rui::Role::Button)
        .label(format!("Open {name}"))
        .disabled(!up)
        .on_click(open)
}

/// The three readings: bytes up, bytes down, how long the tunnel has been up.
///
/// Three equal cells, each a small label over a figure. The figures are set
/// in the fixed-width face so a count crossing from nine to ten does not
/// shuffle the row, and a reading that is not there yet shows a dash in the
/// same place.
fn metrics(link: &Link) -> El<Panel> {
    let uptime = match link.since {
        Some(since) => duration(since.elapsed()),
        None => "—".into(),
    };
    row((metric("UP", bytes(link.tx)), metric("DOWN", bytes(link.rx)), metric("UPTIME", uptime))).gap(SPACE_S)
}

/// One metric cell.
fn metric(label: &'static str, value: String) -> El<Panel> {
    surface::card((heading(label), code(value).text_size(15.0).color(Tone::Text)))
        .pad_each(SPACE_S, SPACE_M, SPACE_S, SPACE_M)
        .gap(SPACE_XS)
        .h(METRIC_HEIGHT)
        .grow()
}

/// The keys card: which identities are live, when the client's last rotated,
/// the rotate control, and the automatic-rotation switch.
fn keys_card(activity: &Activity, auto: bool) -> El<Panel> {
    let client = activity.client.as_ref().map(|id| id.fingerprint.clone()).unwrap_or_else(|| "—".into());
    let server = activity.server.as_ref().map(|id| id.fingerprint.clone()).unwrap_or_else(|| "—".into());
    let busy = activity.busy.is_some();

    surface::card((
        row((heading("KEYS"), spacer().grow(), micro("ed25519"))).align(Align::Center),
        col((
            field_row("CLIENT", code(client).color(Tone::Text)),
            field_row("SERVER", code(server).color(Tone::Text)),
            field_row("ROTATED", rotated_reading(activity.last_rotation.as_deref())),
        ))
        .gap(SPACE_XS),
        row((
            button("Rotate now")
                .disabled(busy)
                .on_click(|panel: &mut Panel| {
                    actions::rotate(panel.activity_handle());
                }),
            spacer().grow(),
            caption("Auto-rotate weekly").color(Tone::Muted),
            switch(auto),
        ))
        .gap(SPACE_S)
        .align(Align::Center),
    ))
    .pad(SPACE_M)
    .gap(SPACE_S)
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
            .gap(SPACE_S)
            .align(Align::Center)
        }
        None => caption(raw.to_string()).color(Tone::Muted),
    }
}

/// A small two-state switch bound to the auto-rotation flag.
///
/// `on` is read by the view and captured here, because a custom-drawn element
/// cannot reach the application state itself; the click flips the real flag.
fn switch(on: bool) -> El<Panel> {
    rui::draw(Size::new(36.0, 20.0), move |painter, rect| surface::paint_switch(painter, rect, on))
        .w(36.0)
        .h(20.0)
        .role(rui::Role::Button)
        .selected(on)
        .label("Automatic key rotation")
        .on_click(|panel: &mut Panel| {
            let now = !panel.auto_rotate.load(Ordering::Relaxed);
            panel.auto_rotate.store(now, Ordering::Relaxed);
        })
}

/// The footer: what an action is doing, or what it last said. Blank when idle,
/// on a line the window reserves so a notice never pushes anything.
fn footer(activity: &Activity) -> El<Panel> {
    let line = if let Some(busy) = &activity.busy {
        caption(format!("{busy}")).color(Tone::ink(Status::Warn))
    } else if let Some((ok, message)) = &activity.notice {
        let status = if *ok { Status::Ok } else { Status::Bad };
        caption(message.clone()).color(Tone::ink(status))
    } else {
        caption(String::new()).color(Tone::Muted)
    };
    row((line, spacer().grow())).h(NOTE_HEIGHT)
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

    // -----------------------------------------------------------------------
    // What the window means, for anything that cannot see it
    // -----------------------------------------------------------------------

    use rui::testing::Harness;
    use std::time::{Duration, Instant};

    /// Every state the window can be in, driven through a real frame.
    ///
    /// Named so a failure says which one, since [`Harness::assert_accessible`]
    /// reports the offending element and not the screen it was on.
    fn states() -> Vec<(&'static str, Link)> {
        vec![
            ("offline", Link::default()),
            ("dialling", Link { phase: Phase::Dialling, ..Link::default() }),
            ("authenticated", Link { phase: Phase::Authenticated, ..Link::default() }),
            (
                "connected",
                Link {
                    phase: Phase::Up,
                    since: Instant::now().checked_sub(Duration::from_secs(384)),
                    tx: 51_314,
                    rx: 1_283_004,
                    last: String::new(),
                },
            ),
            ("failed", Link { phase: Phase::Failed("Connection refused".into()), ..Link::default() }),
        ]
    }

    /// A window showing `link`, at the size it opens at.
    fn window(link: Link, width: f32, height: f32) -> Harness<Panel> {
        Harness::with_app(application("SelfHost VPN", Panel::demo(link))).size(width, height)
    }

    #[test]
    fn every_state_is_accessible_and_tabs_in_reading_order() {
        for (name, link) in states() {
            println!("auditing the window {name}");
            let mut harness = window(link, WINDOW_WIDTH, WINDOW_HEIGHT);
            harness.frame();
            harness.assert_accessible();
            harness.assert_tab_order();
        }
    }

    #[test]
    fn the_primary_control_never_moves_between_states() {
        // The one control a person reaches for is in the same place at the
        // same size whatever the tunnel is doing: Connect, Cancel, and
        // Disconnect share one rectangle.
        let mut rects = Vec::new();
        for (name, link) in states() {
            let mut harness = window(link.clone(), WINDOW_WIDTH, WINDOW_HEIGHT);
            harness.frame();
            let up = link.phase.is_up();
            let reaching = link.phase.is_reaching();
            let label = if up { "Disconnect" } else if reaching { "Cancel" } else { "Connect" };
            let rect = harness.rect_of(label).unwrap_or_else(|| panic!("{name} shows no {label}"));
            rects.push((name, rect));
        }
        let (first, reference) = rects[0];
        for (name, rect) in &rects[1..] {
            assert_eq!(*rect, reference, "{name}'s primary control sits elsewhere than {first}'s");
        }
    }

    #[test]
    fn destinations_open_only_once_the_tunnel_is_up() {
        let mut harness = window(Link::default(), WINDOW_WIDTH, WINDOW_HEIGHT);
        harness.frame();
        let names = harness.accessible_names();
        for destination in ["Open Admin Console", "Open SARA", "Open AI Studio"] {
            assert!(names.iter().any(|name| name == destination), "{destination} is missing from {names:?}");
        }
        let probe = harness.find("Admin Console").expect("the console row is drawn");
        let parent = probe.parent.expect("the row's name sits inside the row");
        let row = harness.probes().iter().find(|p| p.id == parent).cloned().expect("the row is a probe");
        assert!(!row.focusable, "a destination must be greyed, and out of the tab order, until the tunnel is up");
        assert!(harness.shows("Connect to open these."));

        let mut harness = window(states()[3].1.clone(), WINDOW_WIDTH, WINDOW_HEIGHT);
        harness.frame();
        assert!(!harness.shows("Connect to open these."));
    }

    #[test]
    fn the_smallest_window_still_shows_everything() {
        // Every label the window draws is still found at the narrowest size
        // the window allows — the footer line included, which is the last
        // thing to fall off the bottom.
        let mut harness = window(states()[3].1.clone(), MIN_WIDTH, MIN_HEIGHT);
        harness.frame();
        for label in ["Admin Console", "admin.rockywearsahat.com", "UPTIME", "ROTATED", "Rotate now", "Auto-rotate weekly"]
        {
            let rect = harness.rect_of(label).unwrap_or_else(|| panic!("{label} is not drawn at the minimum size"));
            assert!(
                rect.max_y() <= MIN_HEIGHT && rect.max_x() <= MIN_WIDTH,
                "{label} at {rect:?} falls outside the {MIN_WIDTH}x{MIN_HEIGHT} window"
            );
        }
    }
}
