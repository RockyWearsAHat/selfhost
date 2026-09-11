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
    App, El, Key, Modifiers, Size, Status, Tone, button, caption, code, col, dot, field_row, micro, row, section,
    spacer, tag, title,
};
use rui::tray::{Tray, TrayEvent, TrayMenuItem};
use std::ffi::CStr;
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
    /// Whether to use panel mode (dropdown window) instead of NSMenu.
    use_panel_mode: bool,
    /// Track the previous visibility state to avoid redundant macOS calls.
    previous_visible: bool,
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
            use_panel_mode: true,  // Enable panel dropdown instead of NSMenu
            previous_visible: true,
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
            use_panel_mode: true,
            previous_visible: true,
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

    /// Hide the main window using AppleScript (via osascript).
    fn hide_window(&self) {
        #[cfg(target_os = "macos")]
        {
            // Use osascript to hide the window - more reliable than raw Objective-C
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg("tell application \"System Events\" to tell process \"selfhost-vpn-ui\" to set visible to false")
                .output();
        }
    }

    /// Show the main window using AppleScript (via osascript).
    fn show_window(&self) {
        #[cfg(target_os = "macos")]
        {
            // Use osascript to show the window - more reliable than raw Objective-C
            let _ = std::process::Command::new("osascript")
                .arg("-e")
                .arg("tell application \"System Events\" to tell process \"selfhost-vpn-ui\" to set visible to true")
                .output();
        }
    }

    /// Helper to get an Objective-C class by name.
    #[cfg(target_os = "macos")]
    unsafe fn objc_class(name: &CStr) -> *mut std::ffi::c_void {
        unsafe extern "C" {
            fn objc_getClass(name: *const u8) -> *mut std::ffi::c_void;
        }
        unsafe { objc_getClass(name.as_ptr() as *const u8) }
    }

    /// Helper to get an Objective-C selector by name.
    #[cfg(target_os = "macos")]
    unsafe fn objc_selector(name: &CStr) -> *mut std::ffi::c_void {
        unsafe extern "C" {
            fn sel_registerName(name: *const u8) -> *mut std::ffi::c_void;
        }
        unsafe { sel_registerName(name.as_ptr() as *const u8) }
    }

    /// Helper to send an Objective-C message (no arguments).
    #[cfg(target_os = "macos")]
    unsafe fn objc_send(receiver: *mut std::ffi::c_void, selector: *mut std::ffi::c_void) -> *mut std::ffi::c_void {
        unsafe extern "C" {
            fn objc_msgSend();
        }
        let send: unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void) -> *mut std::ffi::c_void =
            unsafe { std::mem::transmute(objc_msgSend as *const ()) };
        unsafe { send(receiver, selector) }
    }

    /// Helper to send an Objective-C message (one argument).
    #[cfg(target_os = "macos")]
    unsafe fn objc_send_with_arg(receiver: *mut std::ffi::c_void, selector: *mut std::ffi::c_void, arg: *mut std::ffi::c_void) {
        unsafe extern "C" {
            fn objc_msgSend();
        }
        let send: unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, *mut std::ffi::c_void) =
            unsafe { std::mem::transmute(objc_msgSend as *const ()) };
        unsafe { send(receiver, selector, arg) };
    }

    /// Helper to send an Objective-C message with an index argument (usize).
    #[cfg(target_os = "macos")]
    unsafe fn objc_send_with_index(receiver: *mut std::ffi::c_void, selector: *mut std::ffi::c_void, index: usize) -> *mut std::ffi::c_void {
        unsafe extern "C" {
            fn objc_msgSend();
        }
        let send: unsafe extern "C" fn(*mut std::ffi::c_void, *mut std::ffi::c_void, usize) -> *mut std::ffi::c_void =
            unsafe { std::mem::transmute(objc_msgSend as *const ()) };
        unsafe { send(receiver, selector, index) }
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
        let tray = Tray::new(icon_data, "SelfHost VPN")
            .map_err(|e| format!("Tray creation failed: {:?}", e))?;
        // Tray::new creates the status item with a blank placeholder image.
        let _ = tray.set_icon(icon_data);
        self.tray = Some(tray);

        // Always update the tray menu with current state
        self.update_tray_menu();

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
            for event in tray.drain_events() {
                self.handle_tray_event(event);
            }
        }
    }

    /// Handle a single tray event, dispatching to the same handlers as UI buttons.
    fn handle_tray_event(&mut self, event: TrayEvent) {
        match event {
            TrayEvent::IconActivated => {
                // Clicking tray icon toggles main window visibility.
                // The window serves as the dropdown panel.
                self.window_visible = !self.window_visible;
            }
            TrayEvent::IconActivatedForPanel { .. } => {
                // Panel mode activated (for platforms that show a panel on click).
                // This is similar to IconActivated but explicitly for panel display.
                self.window_visible = true;
            }
            TrayEvent::MenuItemClicked(id) => {
                match id {
                    1 => self.tunnel.connect(),
                    2 => self.tunnel.disconnect(),
                    3 => actions::open_console(self.activity_handle()),
                    4 => actions::open_sara(self.activity_handle()),
                    5 => actions::open_ai_studio(self.activity_handle()),
                    6 => {
                        // Quit: exit the GUI without killing the tunnel.
                        // If the tunnel is managed (we spawned it), it will be detached and survive.
                        // If it's unmanaged (adopted), it's already detached from us.
                        // The Drop impl handles cleanup appropriately for each case.
                        self.running.store(false, Ordering::Relaxed);
                    }
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
        // Also applies window visibility changes when the window_visible flag changes.
        let on_frame = |panel: &mut Panel| {
            panel.drain_tray_events();
            panel.update_tray_menu();

            // Apply window visibility changes
            if panel.window_visible != panel.previous_visible {
                if panel.window_visible {
                    panel.show_window();
                } else {
                    panel.hide_window();
                }
                panel.previous_visible = panel.window_visible;
            }
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
    .on_key(|panel: &mut Panel, key: Key, _modifiers: Modifiers| {
        // Escape key hides the window (same as clicking tray icon to toggle)
        if key == Key::Escape {
            panel.window_visible = false;
        }
    })
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
