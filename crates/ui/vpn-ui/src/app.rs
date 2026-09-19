//! The window: its state, the actions its controls fire, and the one description
//! of everything on screen.
//!
//! The state a handler mutates is [`Panel`]. The tunnel and the slow actions
//! (rotating a key, opening the console) run off this thread and report back
//! through a shared [`Activity`]; the view reads both once per frame, so the
//! window never blocks on the network or a password prompt.

use crate::keys::{self, Identity};
use crate::style::space;
use crate::tunnel::{Endpoint, Link, Phase, Tunnel};
use crate::{actions, hero, hud, style};
use rui::style::Length;
use rui::{
    App, El, Key, Modifiers, Role, Size, Status, Tone, button, caption, code, col, dot, field_row, micro, row,
    section, spacer, text, title,
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
    let _ = window.style(VOID, 14.0, EDGE, 1.0);

    let pad = 14.0;
    let inner = MINI_WIDTH - pad * 2.0;

    if let Ok(title) = window.add_label(pad, MINI_HEIGHT - 30.0, inner - 14.0, 18.0, "SELFHOST VPN") {
        let _ = window.set_text_color(&title, INK);
    }
    let status = window
        .add_label(pad, MINI_HEIGHT - 52.0, inner, 20.0, "OFFLINE")
        .map_err(|e| format!("{e:?}"))?;
    let detail = window
        .add_label(pad, MINI_HEIGHT - 72.0, inner, 16.0, "rockywearsahat.com:8500")
        .map_err(|e| format!("{e:?}"))?;
    let _ = window.set_text_color(&detail, MUTED);

    let primary = window
        .add_button(pad, 44.0, inner, 28.0, "Connect", 1)
        .map_err(|e| format!("{e:?}"))?;
    let _ = window.set_button_tint(&primary, CYAN_DEEP, true);
    let half = (inner - 8.0) / 2.0;
    if let Ok(console) = window.add_button(pad, 12.0, half, 26.0, "Console", 2) {
        let _ = window.set_button_tint(&console, EDGE, false);
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
/// color rather than a `rui::Color`/`Tone`. Kept numerically identical to
/// `style.rs` so the two surfaces never drift apart by feel.
const VOID: (f32, f32, f32) = (0x04 as f32 / 255.0, 0x07 as f32 / 255.0, 0x0d as f32 / 255.0);
const CYAN: (f32, f32, f32) = (0x3a as f32 / 255.0, 0xe1 as f32 / 255.0, 0xff as f32 / 255.0);
const CYAN_DEEP: (f32, f32, f32) = (0x0b as f32 / 255.0, 0x4f as f32 / 255.0, 0x66 as f32 / 255.0);
const AMBER: (f32, f32, f32) = (0xff as f32 / 255.0, 0xb4 as f32 / 255.0, 0x54 as f32 / 255.0);
const RED: (f32, f32, f32) = (0xff as f32 / 255.0, 0x4d as f32 / 255.0, 0x5a as f32 / 255.0);
const SLATE: (f32, f32, f32) = (0x54 as f32 / 255.0, 0x64 as f32 / 255.0, 0x72 as f32 / 255.0);
const INK: (f32, f32, f32) = (0xe3 as f32 / 255.0, 0xf1 as f32 / 255.0, 0xf7 as f32 / 255.0);
const MUTED: (f32, f32, f32) = (0x6d as f32 / 255.0, 0x84 as f32 / 255.0, 0x91 as f32 / 255.0);
const EDGE: (f32, f32, f32) = (0x49 as f32 / 255.0, 0xc7 as f32 / 255.0, 0xe6 as f32 / 255.0);

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

    let _ = mini.window.set_text(&mini.status, word);
    let _ = mini.window.set_text_color(&mini.status, status_rgb(link));
    let _ = mini.window.set_text(&mini.primary, primary_label(link));
    let _ = mini.window.set_enabled(&mini.quit, true);
    let _ = mini.window.set_text(&mini.detail, &endpoint_label());
}

/// What the one primary control says, in the window, the mini panel and the
/// tray alike: Connect when nothing is asked for, Disconnect once the tunnel
/// is up, and Cancel for every phase in between — dialling, authenticating,
/// and a failure the supervisor is about to retry (see [`Phase::is_wanted`]).
fn primary_label(link: &Link) -> &'static str {
    if link.phase.is_up() {
        "Disconnect"
    } else if link.phase.is_wanted() {
        "Cancel"
    } else {
        "Connect"
    }
}

/// The endpoint as the window says it: host and port, as machine text.
fn endpoint_label() -> String {
    let endpoint = Endpoint::default();
    format!("{}:{}", endpoint.server_host, endpoint.server_port)
}

/// The status word's color, matching the main window's [`status_of`]/[`Tone`]
/// mapping (and [`hero::hue`]'s) but as plain sRGB.
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
    /// The signed-in account's human-facing name, if any (see
    /// [`keys::account_label`]) — shown in the masthead as "@name".
    pub account: Option<String>,
    /// A peer identity a background sign-in just bound this install to,
    /// waiting for the next frame to hand it to `self.tunnel.set_identity`
    /// (see [`Panel::drain_pending_identity`]) — the tunnel is owned by the
    /// UI thread, so a background thread cannot set it directly.
    pub pending_identity: Option<String>,
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
    pub fn new(mut endpoint: Endpoint, running: Arc<AtomicBool>) -> Self {
        let peer = keys::account();
        if let Some(name) = &peer {
            endpoint.identity = name.clone();
        }
        let (client, server) = keys::identities(peer.as_deref());
        let activity = Arc::new(Mutex::new(Activity {
            client,
            server,
            last_rotation: keys::last_rotation(),
            account: keys::account_label(),
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
        let peer = keys::account();
        let (client, server) = keys::identities(peer.as_deref());
        let activity = Arc::new(Mutex::new(Activity {
            client,
            server,
            last_rotation: keys::last_rotation(),
            account: keys::account_label(),
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

    /// Starts the console's own OAuth-with-PKCE sign-in (see [`crate::oauth`])
    /// off the UI thread: opens the browser, waits for its loopback callback,
    /// and redeems the code. Runs through [`actions::sign_in`] the same way
    /// every other slow action here does, since it makes a network round
    /// trip and waits on the browser — the window must stay responsive
    /// through both.
    fn sign_in(&mut self) {
        actions::sign_in(self.activity_handle());
    }

    /// Hands a peer identity a background sign-in just bound this install to
    /// over to the tunnel, which only the UI thread may touch.
    ///
    /// Mirrors [`Self::drain_tray_events`]/[`Self::drain_mini_actions`]: work
    /// queued off-thread is applied here, once a frame, rather than the
    /// background thread reaching into `self.tunnel` directly.
    fn drain_pending_identity(&mut self) {
        let pending = { self.activity().pending_identity.clone() };
        if let Some(peer) = pending {
            self.tunnel.set_identity(peer);
            self.activity().pending_identity = None;
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
                    6 => {
                        self.quit_with_confirmation();
                    }
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
    /// "Quit" actually disconnects the tunnel and stops the app. Answers
    /// whether it did.
    ///
    /// Unlike the old detach-and-leave-running Quit, a confirmed quit here
    /// tears the tunnel down: the operator asked for "upon accept, exit and
    /// terminate session", so this Quit is no longer the same button as the
    /// managed-tunnel survival feature — it is a deliberate end of the session.
    ///
    /// The one shutdown, behind three doors: the tray menu's Quit, the mini
    /// panel's Quit, and the platform's own — Command-Q, the Dock's Quit, an
    /// AppleEvent — which rui hands to [`App::on_quit`] (see [`Panel::run`]).
    /// Before that seam existed, Command-Q closed the window from inside
    /// AppKit's `applicationShouldTerminate:`, and under `close_hides` a
    /// closed window is only a hidden one: Quit behaved exactly like the red
    /// button, and the tray, the tunnel and the process all stayed.
    fn quit_with_confirmation(&mut self) -> bool {
        if !confirm_quit() {
            return false;
        }
        self.tunnel.disconnect();
        self.running.store(false, Ordering::Relaxed);
        true
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
                    if self.tunnel.link().phase.is_wanted() {
                        self.tunnel.disconnect();
                    } else {
                        self.tunnel.connect();
                    }
                }
                MiniAction::Console => actions::open_console(self.activity_handle()),
                MiniAction::Quit => {
                    self.quit_with_confirmation();
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
            let wanted = link.phase.is_wanted();

            let menu = vec![
                TrayMenuItem {
                    id: 1,
                    label: "Connect".into(),
                    enabled: !wanted,
                    selected: false,
                },
                TrayMenuItem {
                    id: 2,
                    label: if up { "Disconnect".into() } else { "Cancel".into() },
                    enabled: wanted,
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
            panel.drain_pending_identity();
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
            // No Dock icon, no Cmd-Tab entry: a menu-bar app, not a regular
            // foreground one. Not only cosmetic — the mini panel's window
            // level and collection behavior (panel_window/macos.rs) are
            // necessary but not sufficient for it to appear over a
            // *different* app's fullscreen Space: macOS's window server
            // isolates a regular app's windows from another app's fullscreen
            // Space regardless of what the window itself asks for. Confirmed
            // live: the mini panel stayed pinned to the current desktop and
            // never appeared over a fullscreened app until this was set.
            .accessory(true)
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
            // Command-Q, the Dock's Quit and an AppleEvent quit all arrive
            // here, on the loop's thread, and take the same door the tray and
            // mini-panel Quit buttons do — the dialog, then the teardown —
            // instead of the close-every-window path that `close_hides` above
            // had quietly turned into "hide". `true` only once the person
            // confirmed and the tunnel is down; Cancel leaves everything up.
            .on_quit(|panel: &mut Panel| panel.quit_with_confirmation())
            .run()
    }
}

/// The panel as an application, in its own theme and ground.
///
/// The ground is painted before the frame's tree exists, so it reads the
/// tunnel's state through a handle of its own ([`Tunnel::watch`]) and tints
/// its reactor-bloom by it: the window is lit by the same light the hero gives
/// off.
pub fn application(title: impl Into<String>, panel: Panel) -> App<Panel> {
    let watched = panel.tunnel.watch();
    App::new(title, panel, view).theme(style::theme).ground(move |canvas, theme| {
        let kind = match watched.lock() {
            Ok(link) => style::Hue::of(&link.phase),
            Err(poisoned) => style::Hue::of(&poisoned.into_inner().phase),
        };
        style::ground(canvas, theme, kind)
    })
}

/// The window's width when it opens, in points.
pub const WINDOW_WIDTH: f32 = 430.0;
/// The window's height when it opens: the content plus a generous field for
/// the hero, which is the one block that grows.
pub const WINDOW_HEIGHT: f32 = 660.0;
/// The narrowest the window may be dragged: every label still fits, proven by
/// the frame tests below.
pub const MIN_WIDTH: f32 = 380.0;
/// The shortest the window may be dragged: every row of every section is still
/// whole, with the hero at exactly [`hero::HERO_MIN`].
pub const MIN_HEIGHT: f32 = 620.0;

/// The whole window, as one description.
///
/// Top to bottom, in the order the eye is meant to travel: the instrument (the
/// hero and, under it, the state word, the endpoint and one line of plain
/// words), the one thing to do about it (the primary control), where the
/// tunnel leads (the routes), how it is doing (the readouts), and — demoted to
/// the foot — the keys it runs on. Every block holds its geometry across the
/// four states: the hero's height depends on the window alone, the primary
/// control never moves, and the route rows stay where they are, dimmed rather
/// than gone.
pub fn view(ui: &Panel) -> El<Panel> {
    let link = ui.tunnel.link();
    let activity = ui.activity();
    let auto = ui.auto_rotate.load(Ordering::Relaxed);
    col((
        masthead(&link, activity.account.as_deref()),
        instrument(&link),
        primary(&link),
        routes(&link),
        readouts(&link),
        keys_panel(&activity, auto),
        footer(&activity),
    ))
    .pad(space::L)
    .gap(space::M)
    // The window answers Escape, so it states what it is for anything that
    // cannot see it — a group that takes the keyboard is not allowed to stay
    // an anonymous group.
    .role(Role::Dialog)
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

/// The bar across the top: the mark, the wordmark, who is signed in, and the
/// state at a glance.
fn masthead(link: &Link, account: Option<&str>) -> El<Panel> {
    row((
        hud::mark(),
        title("SELFHOST").bold().tracking(1.0),
        caption("VPN").color(Tone::Exact(style::CYAN)).tracking(2.0),
        spacer().grow(),
        sign_in_control(account),
        dot(status_of(link), 4.0),
        micro(state_word(link)).color(word_tone(link)).tracking(1.5),
    ))
    .gap(space::S)
    .h(22.0)
    .align(rui::Align::Center)
}

/// The one account control: "Sign in" when no identity is bound yet, or
/// "@name" once one is — clicking either opens the console in the browser
/// for the same OAuth-with-PKCE flow, so switching accounts later needs no
/// separate control to find.
fn sign_in_control(account: Option<&str>) -> El<Panel> {
    let label = match account {
        Some(name) => format!("@{name}"),
        None => "Sign in".into(),
    };
    button(label)
        .h(20.0)
        .label("Sign in through the admin console")
        .on_click(|panel: &mut Panel| panel.sign_in())
}

/// The instrument: the hero in a glass panel lit by the tunnel's hue, and
/// directly under it the state block — the state word set large and lit like
/// a reactor core, the endpoint in machine text on the same line, and one
/// line of plain words saying what the state means right now (a failure's own
/// reason, in red, when it has one). The one block that grows: whatever height
/// the window has beyond its content opens up in the hero.
fn instrument(link: &Link) -> El<Panel> {
    let hue = style::hue(style::Hue::of(&link.phase));
    let lit = !matches!(link.phase, Phase::Off);
    let word_color = if lit { hue } else { style::INK };
    hud::glass_panel_lit(
        col((
            hero::tunnel_hero(link).grow(),
            col((
                row((
                    hud::state_word(state_title(link), word_color, lit),
                    spacer().grow(),
                    code(endpoint_label()).color(Tone::Muted),
                ))
                .gap(space::S)
                .align(rui::Align::Center),
                caption(explanation(link)).color(explanation_tone(link)),
            ))
            .gap(2.0)
            .pad_x(space::XS),
        ))
        .gap(space::XS),
        hue,
    )
    .align(rui::Align::Stretch)
    .grow()
}

/// The one control the window is mostly for, full width, in the same place
/// in every state.
///
/// Connect wears the accent: it is the action the window exists to offer.
/// Disconnect and Cancel are quiet: taking a healthy tunnel down is routine,
/// and red belongs to Failed alone. A failed tunnel offers Cancel, not
/// Connect, because the supervisor is still retrying it (see
/// [`Phase::is_wanted`]) and a Connect that did nothing would be a lie.
fn primary(link: &Link) -> El<Panel> {
    let control = if link.phase.is_wanted() {
        button(primary_label(link)).on_click(|panel: &mut Panel| panel.tunnel.disconnect())
    } else {
        // The one lit control: filled with the accent and casting its own
        // halo, the way the reactor cores do, so the thing to press is the
        // thing that glows.
        button(primary_label(link))
            .primary()
            .glow(7.0, Tone::Exact(style::CYAN.fade(0.2)))
            .on_click(|panel: &mut Panel| panel.tunnel.connect())
    };
    control.h(space::PRIMARY_HEIGHT).w(Length::Fill(1.0))
}

/// Where the tunnel leads: one glass row per gated site, each a full-width
/// control with a reactor tick, the name, the host it answers at, and a
/// chevron.
///
/// The rows are drawn in every state and dimmed when the tunnel is down — the
/// list is a fact about the tunnel, not a menu that appears when it is up —
/// and the section's own note says why they wait. The note names no button:
/// while dialling, and after a failure, the only control on screen is Cancel.
fn routes(link: &Link) -> El<Panel> {
    let up = link.phase.is_up();
    let note = if up { "through the tunnel" } else { "available once connected" };
    col((
        section("ROUTES", Some(note.into())),
        col((
            route("Admin Console", CONSOLE_HOST, up, |panel| actions::open_console(panel.activity_handle())),
            route("SARA", SARA_HOST, up, |panel| actions::open_sara(panel.activity_handle())),
            route("AI Studio", AI_HOST, up, |panel| actions::open_ai_studio(panel.activity_handle())),
        ))
        .gap(3.0),
    ))
    .gap(space::S)
}

/// One route row. Named "Open …" for anything that cannot see the chevron.
///
/// The ink is the same ink in every state, faded when the route cannot be
/// opened — unavailable means dimmer, not a different grey — and the tick and
/// chevron dim by the same amount, so the whole row goes quiet as one thing.
fn route(name: &str, host: &str, up: bool, open: fn(&mut Panel)) -> El<Panel> {
    hud::glass_row((
        hud::reactor_tick(up),
        text(name).color(hud::ink(style::INK, up)),
        spacer().grow(),
        code(host).color(hud::ink(style::MUTED, up)),
        hud::chevron(up),
    ))
    .reactive()
    .role(Role::Button)
    .label(format!("Open {name}"))
    .disabled(!up)
    .on_click(open)
}

/// The readout strip: bytes each way and how long the link has been up, in
/// three hairline-separated glass cells that keep their places in every
/// state. A value the window does not have yet is "—", never a number.
fn readouts(link: &Link) -> El<Panel> {
    let uptime = match link.since {
        Some(since) => duration(since.elapsed()),
        None => "—".into(),
    };
    row((
        hud::readout("SENT", bytes(link.tx)),
        hud::seam(),
        hud::readout("RECEIVED", bytes(link.rx)),
        hud::seam(),
        hud::readout("UPTIME", uptime),
    ))
    .h(space::STRIP_HEIGHT)
    .fill(Tone::Exact(style::GLASS))
    .border(1.0, Tone::Exact(style::EDGE.fade(0.22)))
    .round(rui::style::Radius::Cut(6.0))
    .clip()
}

/// The keys panel: which identities are live, when they last rotated, the
/// rotate control, and the weekly-rotation switch.
fn keys_panel(activity: &Activity, auto: bool) -> El<Panel> {
    let client = activity.client.as_ref().map(|id| id.fingerprint.clone()).unwrap_or_else(|| "—".into());
    let server = activity.server.as_ref().map(|id| id.fingerprint.clone()).unwrap_or_else(|| "—".into());
    let busy = activity.busy.is_some();

    hud::glass_panel(col((
        section("KEYS", Some("ed25519".into())),
        col((
            field_row("CLIENT", code(client).color(Tone::Text)),
            field_row("SERVER", code(server).color(Tone::Text)),
            field_row("ROTATED", rotated_reading(activity.last_rotation.as_deref())),
        ))
        .gap(2.0)
        // Held at three rows' height, so a short window cannot fold a row.
        .min_h(3.0 * space::FIELD_HEIGHT + 4.0),
        row((
            button("Rotate now")
                .disabled(busy)
                .on_click(|panel: &mut Panel| {
                    actions::rotate(panel.activity_handle());
                })
                .h(26.0),
            spacer().grow(),
            caption("Auto-rotate weekly"),
            switch(auto),
        ))
        .gap(space::S)
        .min_h(26.0)
        .align(rui::Align::Center),
    ))
    .gap(6.0))
    .align(rui::Align::Stretch)
}

/// The ROTATED reading: the age up front in human units, with the raw record
/// demoted to a dim line beside it. Amber only with its cause on screen: once
/// the weekly rotation is overdue the reading says so, in the same breath.
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
            let age = keys::rotation_age(then, now);
            let (reading, tone) = if keys::rotation_stale(then, now) {
                (format!("{age} · overdue"), Tone::ink(Status::Warn))
            } else {
                (age, Tone::Text)
            };
            row((caption(reading).color(tone), micro(raw.to_string()).color(Tone::Idle), spacer().grow()))
                .gap(space::S)
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
    rui::draw(Size::new(space::SWITCH_WIDTH, space::SWITCH_HEIGHT), move |painter, rect| {
        hud::paint_switch(painter, rect, on)
    })
    .w(space::SWITCH_WIDTH)
    .h(space::SWITCH_HEIGHT)
    .role(rui::Role::Button)
    .selected(on)
    .label("Auto-rotate weekly")
    .on_click(|panel: &mut Panel| {
        let now = !panel.auto_rotate.load(Ordering::Relaxed);
        panel.auto_rotate.store(now, Ordering::Relaxed);
    })
}

/// The footer: what an action is doing, or what it last said. Blank when idle —
/// the routes section carries its own note. One line is reserved in every
/// state, so a notice arriving never shifts the window.
fn footer(activity: &Activity) -> El<Panel> {
    let line = if let Some(busy) = &activity.busy {
        micro(format!("• {busy}")).color(Tone::ink(Status::Warn))
    } else if let Some((ok, message)) = &activity.notice {
        let status = if *ok { Status::Ok } else { Status::Bad };
        micro(message.clone()).color(Tone::ink(status))
    } else {
        micro(String::new()).color(Tone::Muted)
    };
    row((line, spacer().grow())).h(space::FOOTER_HEIGHT)
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

/// The state word in capitals, as the masthead, the tray and the mini panel
/// show it.
fn state_word(link: &Link) -> &'static str {
    match link.phase {
        Phase::Off => "OFFLINE",
        Phase::Dialling => "DIALLING",
        Phase::Authenticated => "AUTHENTICATED",
        Phase::Up => "CONNECTED",
        Phase::Failed(_) => "FAILED",
    }
}

/// The state word as the instrument sets it: one word, sentence case, large.
fn state_title(link: &Link) -> &'static str {
    match link.phase {
        Phase::Off => "Offline",
        Phase::Dialling => "Dialling",
        Phase::Authenticated => "Authenticated",
        Phase::Up => "Connected",
        Phase::Failed(_) => "Failed",
    }
}

/// The line under the state word: what the state means, in plain words. It
/// does not repeat the word above it — the word says *what*, the endpoint
/// says *where*, and this line says what is happening about it. A failure's
/// own reason is the line, with the one word that explains why the control
/// under it says Cancel: the supervisor is still retrying (see
/// [`Phase::is_wanted`]).
fn explanation(link: &Link) -> String {
    match &link.phase {
        Phase::Off => "Not connected".into(),
        Phase::Dialling => "Reaching the box…".into(),
        Phase::Authenticated => "Box verified — bringing the tunnel up…".into(),
        Phase::Up => "Secure tunnel to the box".into(),
        Phase::Failed(reason) => format!("{reason} · retrying"),
    }
}

/// The explanation's ink: muted prose, except a failure's reason, which is
/// red — the one line in the window that is a cause, set in the colour of
/// the state it explains.
fn explanation_tone(link: &Link) -> Tone {
    match link.phase {
        Phase::Failed(_) => Tone::ink(Status::Bad),
        _ => Tone::Muted,
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

    #[test]
    fn every_way_of_naming_the_primary_control_agrees() {
        // The window, the mini panel and the tray all take their word from
        // one function, and that function follows the tunnel's own idea of
        // "wanted": Failed is a tunnel still being tried, so it offers Cancel.
        assert_eq!(primary_label(&Link::default()), "Connect");
        assert_eq!(primary_label(&Link { phase: Phase::Dialling, ..Link::default() }), "Cancel");
        assert_eq!(primary_label(&Link { phase: Phase::Authenticated, ..Link::default() }), "Cancel");
        assert_eq!(primary_label(&Link { phase: Phase::Failed("x".into()), ..Link::default() }), "Cancel");
        assert_eq!(primary_label(&Link { phase: Phase::Up, ..Link::default() }), "Disconnect");
    }

    // -----------------------------------------------------------------------
    // The window, driven through a real frame
    // -----------------------------------------------------------------------

    use rui::testing::Harness;

    /// The window's default size and the smallest it may be resized to, as
    /// `Panel::run` sets them. Every frame test runs at both, because a label
    /// that fits at 430 units is not a label that fits.
    const SIZES: [(f32, f32); 2] = [(WINDOW_WIDTH, WINDOW_HEIGHT), (MIN_WIDTH, MIN_HEIGHT)];

    /// The five phases the window is ever in, named so a failure says which.
    fn states() -> Vec<(&'static str, Link)> {
        vec![
            ("offline", Link::default()),
            ("dialling", Link { phase: Phase::Dialling, ..Link::default() }),
            ("authenticated", Link { phase: Phase::Authenticated, ..Link::default() }),
            (
                "connected",
                Link {
                    phase: Phase::Up,
                    since: std::time::Instant::now().checked_sub(std::time::Duration::from_secs(384)),
                    tx: 51_314,
                    rx: 1_283_004,
                    ..Link::default()
                },
            ),
            ("failed", Link { phase: Phase::Failed("Connection refused".into()), ..Link::default() }),
        ]
    }

    /// One of [`states`], by name.
    fn state(name: &str) -> Link {
        states().into_iter().find(|(n, _)| *n == name).map(|(_, link)| link).expect("a named state")
    }

    /// A harness on the window as it is actually built — its own theme and
    /// ground — rather than the same tree under the library's defaults.
    fn window(link: Link, (width, height): (f32, f32)) -> Harness<Panel> {
        Harness::with_app(application("SelfHost VPN", Panel::demo(link))).size(width, height)
    }

    #[test]
    fn every_state_is_reachable_named_and_ordered() {
        for (name, link) in states() {
            for size in SIZES {
                println!("auditing {name} at {size:?}");
                let mut harness = window(link.clone(), size);
                harness.assert_accessible();
                harness.assert_tab_order();
            }
        }
    }

    #[test]
    fn the_primary_control_never_moves_between_states() {
        // The one control the window is for keeps its place and its size
        // whatever the tunnel is doing, so a hand that has learned where it
        // is finds it there whether it now says Connect, Cancel or Disconnect.
        for size in SIZES {
            let mut rects = Vec::new();
            for (name, link) in states() {
                let label = primary_label(&link);
                let mut harness = window(link, size);
                harness.frame();
                let rect = harness.rect_of(label).unwrap_or_else(|| panic!("{name} draws no {label}"));
                rects.push((name, rect));
            }
            let (first, reference) = rects[0];
            for (name, rect) in &rects[1..] {
                assert_eq!(
                    (rect.x, rect.y, rect.w, rect.h),
                    (reference.x, reference.y, reference.w, reference.h),
                    "at {size:?} the primary control moved between {first} and {name}"
                );
            }
        }
    }

    #[test]
    fn a_failure_says_why_and_offers_cancel() {
        for size in SIZES {
            let mut harness = window(state("failed"), size);
            harness.frame();
            assert!(harness.shows("Failed"), "the state word");
            assert!(harness.shows("Connection refused · retrying"), "and the reason under it, with why Cancel");
            assert!(harness.shows("Cancel"), "the primary control is Cancel");
            assert!(!harness.shows("Connect"), "and not a Connect that does nothing");
            assert!(harness.shows("available once connected"), "the routes carry one shared note");
        }
    }

    #[test]
    fn the_instrument_carries_the_endpoint_and_the_captions_in_every_state() {
        for (name, link) in states() {
            let mut harness = window(link, SIZES[1]);
            harness.frame();
            assert!(harness.shows("rockywearsahat.com:8500"), "{name} shows the endpoint");
            assert!(harness.shows("THE BOX"), "{name} keeps the far caption");
            assert!(harness.shows("Auto-rotate weekly"), "{name} names the switch in plain words");
        }
        let mut harness = window(state("connected"), SIZES[0]);
        harness.frame();
        assert!(harness.shows("through the tunnel"));
        assert!(!harness.shows("available once connected"));
    }

    #[test]
    fn every_route_and_key_control_is_drawn_in_every_state() {
        // Rows reserve their slots: a route that cannot be opened is dimmed,
        // not gone, so the list is the same list in every state.
        for (name, link) in states() {
            let mut harness = window(link, SIZES[1]);
            harness.frame();
            for label in ["Admin Console", "SARA", "AI Studio", CONSOLE_HOST, SARA_HOST, AI_HOST, "Rotate now", "ROUTES", "KEYS"] {
                assert!(harness.shows(label), "{name} at the smallest window draws {label}");
            }
            for label in ["SENT", "RECEIVED", "UPTIME", "CLIENT", "SERVER", "ROTATED"] {
                assert!(harness.shows(label), "{name} at the smallest window draws {label}");
            }
        }
    }

    #[test]
    fn nothing_is_drawn_outside_the_window_at_its_smallest() {
        // Every probe on every state, at the minimum size, sits inside the
        // page margin — a label that only fits because a longer neighbour
        // happened to be short at 430 units is caught here.
        let (width, height) = SIZES[1];
        for (name, link) in states() {
            let mut harness = window(link, (width, height));
            harness.frame();
            for probe in harness.probes() {
                if probe.rect.w >= width {
                    continue;
                }
                assert!(
                    probe.rect.x + probe.rect.w <= width - space::L + 0.5,
                    "{name} draws {:?} into the right margin: {:?}",
                    probe.text,
                    probe.rect
                );
                assert!(
                    probe.rect.y + probe.rect.h <= height + 0.5,
                    "{name} draws {:?} below the window: {:?}",
                    probe.text,
                    probe.rect
                );
            }
        }
    }

    #[test]
    fn no_two_labels_collide_at_the_smallest_window() {
        // A window shorter than its content takes the missing height off
        // content-sized blocks, and two labels end up drawn through each
        // other — which the margin test above cannot see, since both are
        // still inside the page.
        for (name, link) in states() {
            let mut harness = window(link, SIZES[1]);
            harness.frame();
            let labels: Vec<(String, rui::Rect)> = harness
                .probes()
                .iter()
                .filter_map(|probe| {
                    let text = probe.text.as_deref()?.trim();
                    (!text.is_empty()).then(|| (text.to_string(), probe.rect))
                })
                .collect();
            for (i, (a, ra)) in labels.iter().enumerate() {
                for (b, rb) in &labels[i + 1..] {
                    let apart = ra.x + ra.w <= rb.x
                        || rb.x + rb.w <= ra.x
                        || ra.y + ra.h <= rb.y
                        || rb.y + rb.h <= ra.y;
                    assert!(apart, "{name} at the smallest window draws {a:?} through {b:?}: {ra:?} vs {rb:?}");
                }
            }
        }
    }

    #[test]
    fn the_hero_is_the_block_that_grows() {
        // The instrument is taller at the default size than at the smallest,
        // and everything under it keeps its own height: the extra room the
        // window has goes to the hero and nowhere else.
        let mut small = window(state("connected"), SIZES[1]);
        small.frame();
        let mut large = window(state("connected"), SIZES[0]);
        large.frame();
        let routes_small = small.rect_of("ROUTES").expect("routes");
        let routes_large = large.rect_of("ROUTES").expect("routes");
        let keys_small = small.rect_of("KEYS").expect("keys");
        let keys_large = large.rect_of("KEYS").expect("keys");
        let grew = routes_large.y - routes_small.y;
        assert!(grew > 20.0, "the hero took the window's extra height ({grew})");
        assert!(
            ((keys_large.y - routes_large.y) - (keys_small.y - routes_small.y)).abs() < 0.5,
            "the blocks under the hero kept their spacing"
        );
    }
}
