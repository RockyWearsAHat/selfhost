//! The desktop VPN panel: one window to bring up the Secure-VPN tunnel and reach
//! the admin console.
//!
//! It runs on your machine, beside the browser. The tunnel is the project's own
//! Secure-VPN client; this window starts it, says what it is doing, opens the
//! console once it is up, and keeps the identity key rotating. Everything slow
//! runs off the window thread, so it never sits unresponsive.

// `deny` rather than `forbid`: `tunnel.rs`'s process-detachment path needs one
// explicit, `#[allow]`ed `unsafe` block (`pre_exec` to call `setsid()`, the
// only way to make the Secure-VPN client survive this app's own process
// exiting) — `forbid` can never be locally overridden, so it would have
// meant either no detachment or a silently-dropped guarantee elsewhere.
#![deny(unsafe_code)]
#![warn(missing_docs)]

mod actions;
mod app;
mod dns;
mod hero;
mod hostname;
mod hud;
mod keys;
#[cfg(target_os = "macos")]
mod macos_native;
mod oauth;
mod style;
mod tunnel;

use app::Panel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tunnel::{Endpoint, Link, Phase};

/// How often the auto-rotation thread wakes to check whether a week has passed.
const ROTATE_CHECK: Duration = Duration::from_secs(3600);

/// How old the identity key may get before automatic rotation replaces it.
const ROTATE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);

/// How often the KEYS panel's on-disk reading is refreshed, independent of
/// whether this app itself is the one rotating. A rotation triggered any
/// other way — `rotate-keys.sh` run by hand, a script, another instance —
/// used to leave the window showing a stale "N ago" until this app happened
/// to perform (or be restarted into re-reading) its own rotation, because
/// `Activity.last_rotation` was set once at launch and otherwise only ever
/// updated by this app's own `actions::rotate()` callback.
const DISPLAY_REFRESH: Duration = Duration::from_secs(2);

fn main() -> std::process::ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("selfhost-vpn-ui: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Parses the arguments and either renders the window's looks or opens it.
fn run(args: Vec<String>) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("--help" | "-h") => {
            print!(
                "selfhost-vpn-ui — the desktop VPN panel\n\n\
                 Usage:\n  \
                 selfhost-vpn-ui                 open the window\n  \
                 selfhost-vpn-ui --render <dir>  draw its looks to PNGs and exit\n"
            );
            Ok(())
        }
        Some("--render") => {
            let dir = args.get(1).cloned().unwrap_or_else(|| ".".into());
            render(&dir)
        }
        _ => open(),
    }
}

/// Opens the window, keeps the key rotating and the console's name answered,
/// and runs until it is closed.
fn open() -> Result<(), String> {
    // Installs/refreshes the Secure-VPN Mac auto-updater's login/boot
    // LaunchAgent. This needs no privileged prompt (a per-user LaunchAgent,
    // not a LaunchDaemon), so it runs unconditionally and silently on every
    // launch rather than behind a button — see actions::ensure_updater_agent.
    actions::ensure_updater_agent();

    let running = Arc::new(AtomicBool::new(true));
    let panel = Panel::new(Endpoint::default(), Arc::clone(&running));

    // The weekly rotation runs off the window thread and honours the switch.
    let rotor = spawn_auto_rotation(
        panel.auto_rotate_flag(),
        panel.activity_handle(),
        Arc::clone(&running),
    );

    // The split-DNS responder backs the /etc/resolver file for the console host.
    let responder = dns::spawn(Arc::clone(&running), panel.activity_handle());

    // Run the window. Tray is created inside on_ready callback, events dispatched
    // each frame by on_frame callback. Window can close while tray remains active.
    let _outcome = panel.run("SelfHost VPN".into()).map_err(|error| error.to_string());

    running.store(false, Ordering::Relaxed);
    let _ = rotor.join();
    let _ = responder.join();
    Ok(())
}

/// The real on-disk key age, as an `Instant` an hour, a day, or five weeks in
/// the past — so `Instant::elapsed()` from process start reads the key's true
/// staleness instead of resetting to zero every time this app relaunches.
/// Falls back to "now" (treats the key as freshly rotated) when there is no
/// recorded rotation yet, or it cannot be parsed — the same as before this
/// fix, which is the safe default: never rotate unexpectedly on faith in an
/// unreadable timestamp.
fn last_rotation_instant() -> Instant {
    let now = Instant::now();
    let Some(recorded) = keys::last_rotation() else {
        return now;
    };
    let Some(recorded_epoch) = keys::parse_epoch(&recorded) else {
        return now;
    };
    let Ok(now_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return now;
    };
    let age_secs = now_epoch.as_secs().saturating_sub(recorded_epoch.max(0) as u64);
    now.checked_sub(Duration::from_secs(age_secs)).unwrap_or(now)
}

/// The background thread that keeps the identity key fresh.
///
/// It rotates when the key is older than a week and the switch is on. A rotation
/// is lock-out-proof on its own, so the worst a failure does is leave the
/// current key in place until the next check.
fn spawn_auto_rotation(
    auto: Arc<AtomicBool>,
    activity: Arc<std::sync::Mutex<app::Activity>>,
    running: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut last = last_rotation_instant();
        refresh_activity_from_disk(&activity);
        let mut since_refresh = Duration::ZERO;
        while running.load(Ordering::Relaxed) {
            // Checked first, before the hour-long wait below: `last` is
            // already backdated to the key's real age, so a key that is
            // already overdue when this thread starts (the common case —
            // this only runs while the app is open, not continuously) must
            // rotate now rather than sit overdue for up to another hour
            // before the loop first looks.
            if auto.load(Ordering::Relaxed) && last.elapsed() >= ROTATE_AFTER {
                actions::rotate(Arc::clone(&activity));
                last = Instant::now();
            }
            // Sleep in short steps so closing the window does not wait an hour.
            let mut waited = Duration::ZERO;
            while waited < ROTATE_CHECK && running.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
                waited += Duration::from_millis(500);
                since_refresh += Duration::from_millis(500);
                if since_refresh >= DISPLAY_REFRESH {
                    since_refresh = Duration::ZERO;
                    if refresh_activity_from_disk(&activity) {
                        // Someone else already rotated since this thread's
                        // own `last` baseline was set — re-derive it from
                        // the record that just changed, so this thread does
                        // not also fire its own redundant rotation on top.
                        last = last_rotation_instant();
                    }
                }
            }
        }
    })
}

/// Re-reads the identities and rotation record from disk and, if either
/// changed, writes them into `activity` for the window to redraw. Returns
/// whether anything changed — the caller uses that to know its own idea of
/// the key's age just went stale.
fn refresh_activity_from_disk(activity: &Arc<std::sync::Mutex<app::Activity>>) -> bool {
    let account = keys::account();
    let (client, server) = keys::identities(account.as_deref());
    let last_rotation = keys::last_rotation();
    let mut guard = match activity.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let changed = guard.client != client || guard.server != server || guard.last_rotation != last_rotation;
    if changed {
        guard.client = client;
        guard.server = server;
        guard.last_rotation = last_rotation;
    }
    changed
}

/// Draws the window in each of its states to PNGs, with no window open.
///
/// The renderer is pure — a frame drawn to a bitmap is the frame a window shows
/// — so this is how the panel's looks are reviewed.
fn render(dir: &str) -> Result<(), String> {
    let mut fonts = rui::shell::load_system_fonts().map_err(|error| error.to_string())?;
    let states: [(&str, Link); 4] = [
        ("offline", Link::default()),
        ("dialling", Link { phase: Phase::Dialling, ..Link::default() }),
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
        (
            "failed",
            Link { phase: Phase::Failed("Connection refused".into()), ..Link::default() },
        ),
    ];

    for (name, link) in states {
        // Every state at the window's default size, and the busiest one at
        // the smallest size it can be resized to — the frame where a label
        // that was going to truncate does.
        let mut frames = vec![(name.to_string(), app::WINDOW_WIDTH as u32, app::WINDOW_HEIGHT as u32)];
        if link.phase.is_up() {
            frames.push((format!("{name}-min"), app::MIN_WIDTH as u32, app::MIN_HEIGHT as u32));
        }
        for (name, width, height) in frames {
            write_frame(dir, &name, Panel::demo(link.clone()), width, height, &mut fonts)?;
        }
    }
    Ok(())
}

/// Draws one frame of `panel` at `width`×`height` (2× for the review) to
/// `<dir>/vpn-<name>.png`.
fn write_frame(
    dir: &str,
    name: &str,
    panel: Panel,
    width: u32,
    height: u32,
    fonts: &mut rui::shell::LoadedFonts,
) -> Result<(), String> {
    let mut application = app::application("SelfHost VPN", panel);
    let canvas = application.render(width, height, 2.0, rui::Appearance::Dark, fonts);
    let pixels = rui::image::rgba(&canvas);
    let png = rui::image::png(canvas.width(), canvas.height(), &pixels).ok_or("the frame could not be encoded")?;
    let path = format!("{dir}/vpn-{name}.png");
    std::fs::write(&path, png).map_err(|error| format!("cannot write {path}: {error}"))?;
    println!("wrote {path}");
    Ok(())
}
