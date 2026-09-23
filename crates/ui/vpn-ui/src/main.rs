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
mod surface;
mod keys;
#[cfg(target_os = "macos")]
mod macos_native;
mod style;
mod tunnel;

use app::Panel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tunnel::{Endpoint, Link, Phase};

/// How often the auto-rotation thread wakes to check whether a week has passed.
const ROTATE_CHECK: Duration = Duration::from_secs(3600);

/// How old the identity key may get before automatic rotation replaces it.
const ROTATE_AFTER: Duration = Duration::from_secs(7 * 24 * 3600);

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
        let mut last = Instant::now();
        while running.load(Ordering::Relaxed) {
            // Sleep in short steps so closing the window does not wait an hour.
            let mut waited = Duration::ZERO;
            while waited < ROTATE_CHECK && running.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(500));
                waited += Duration::from_millis(500);
            }
            if !running.load(Ordering::Relaxed) {
                break;
            }
            if auto.load(Ordering::Relaxed) && last.elapsed() >= ROTATE_AFTER {
                actions::rotate(Arc::clone(&activity));
                last = Instant::now();
            }
        }
    })
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

    let (width, height) = (app::WINDOW_WIDTH as u32, app::WINDOW_HEIGHT as u32);
    for (name, link) in &states {
        write_frame(dir, name, Panel::demo(link.clone()), width, height, &mut fonts)?;
    }
    // The smallest window the app allows, in the state with the most on
    // screen: what proves no label truncates when the window is dragged down.
    let (name, link) = &states[2];
    let (min_w, min_h) = (app::MIN_WIDTH as u32, app::MIN_HEIGHT as u32);
    write_frame(dir, &format!("{name}-min"), Panel::demo(link.clone()), min_w, min_h, &mut fonts)
}

/// Draws one state at one size to `<dir>/vpn-<name>.png`, at 2x.
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
