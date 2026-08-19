//! Acceptance tests that need a real Android Fire TV with ADB enabled.
//!
//! The unit suite proves the RSA signature, the ADB wire format, and the
//! keycode mapping against fixed vectors; only a run against the hardware proves
//! a television accepts the signature and runs the keyevent. These are the tests
//! that close that gap, and they are the deliberate bring-up step the driver was
//! written blind against.
//!
//! Every test is `#[ignore]`d and run by hand:
//!
//! ```text
//! cargo test -p selfhost-home --test live_firetv -- --ignored --nocapture --test-threads=1
//! ```
//!
//! # What the operator must do first, once
//!
//! 1. On the Fire TV: **Settings → My Fire TV → Developer options → ADB
//!    debugging → On**. (Only the Android-based sticks have this. A Vega Fire
//!    TV has no ADB and these tests will correctly find no controllable
//!    television.)
//! 2. Run the control test below. The **first** connection makes the television
//!    show an "Allow USB debugging?" dialog naming `selfhost@home` — tap
//!    **Allow** (and "always allow" so it is not asked again). The handshake
//!    waits up to thirty seconds for that tap.
//!
//! After that the television remembers the key and every later connection is
//! silent. The key is written to a temp file for the duration of these tests so
//! the allow is remembered between them.
//!
//! **The control test visibly drives a real television**: it wakes the screen
//! and presses HOME. Run it when that is acceptable. The reachability test
//! changes nothing.

use std::path::PathBuf;
use std::time::Duration;

use selfhost_home::device::{Capability, Command, Key, Kind};
use selfhost_home::{dial, discovery, firetv};

/// The window the SSDP sweep listens for — generous, as in the DIAL suite, so a
/// missed answer does not read as "no television here".
const SWEEP: Duration = Duration::from_secs(4);

/// A stable key path for the duration of a manual test run, so the television's
/// one-time "allow" is remembered from the first test to the next.
fn key_path() -> PathBuf {
    std::env::temp_dir().join("selfhost-firetv-test.adbkey")
}

/// Every television the sweep found that also answers ADB, or an early return.
macro_rules! adb_televisions_or_skip {
    () => {{
        let found = discovery::sweep(SWEEP).await;
        let mut televisions = Vec::new();
        for entry in found.iter().filter(|f| f.kind == discovery::FoundKind::Dial) {
            match dial::television(entry).await {
                Ok(mut device) => {
                    dial::refresh(&mut device).await;
                    firetv::probe(&mut device).await;
                    if device.can(Capability::Keys) {
                        televisions.push(device);
                    } else {
                        eprintln!(
                            "  {} answers DIAL but not ADB (Vega, or ADB debugging is off)",
                            device.name
                        );
                    }
                }
                Err(error) => eprintln!("  {} did not describe itself: {error}", entry.address),
            }
        }
        if televisions.is_empty() {
            eprintln!("skipped: no Fire TV with ADB enabled answered on this network");
            return;
        }
        televisions
    }};
}

/// Read-only: the probe promotes a television to power-and-key control exactly
/// when its ADB port is open, which is what makes the dashboard's controls
/// appear the moment the operator enables debugging.
#[tokio::test]
#[ignore = "needs a real Fire TV with ADB debugging enabled"]
async fn a_fire_tv_with_adb_enabled_gains_power_and_key_control() {
    let televisions = adb_televisions_or_skip!();
    for tv in &televisions {
        eprintln!(
            "  {} — {} — power:{} keys:{} apps:{}",
            tv.name,
            tv.address.as_deref().unwrap_or("?"),
            tv.can(Capability::Power),
            tv.can(Capability::Keys),
            tv.can(Capability::Apps),
        );
        assert_eq!(tv.kind, Kind::Television);
        // DIAL's app control and ADB's key control coexist on the one device.
        assert!(tv.can(Capability::Apps), "{} must keep DIAL apps", tv.name);
        assert!(tv.can(Capability::Power), "{} must gain power", tv.name);
        assert!(tv.can(Capability::Keys), "{} must gain keys", tv.name);
    }
}

/// **Drives a real television**: wakes it and presses HOME. The first run also
/// provokes the one-time "allow" dialog — tap Allow on the screen. This is the
/// end-to-end proof the pure suite cannot give: a signature a real Fire TV
/// accepts, and a keyevent it runs.
#[tokio::test]
#[ignore = "wakes a real Fire TV and presses HOME — run when that is acceptable"]
async fn a_fire_tv_wakes_and_takes_a_key() {
    let televisions = adb_televisions_or_skip!();
    let path = key_path();
    let Some(tv) = televisions.into_iter().next() else {
        return;
    };
    eprintln!("  driving {} at {}", tv.name, tv.address.as_deref().unwrap_or("?"));
    eprintln!("  (if the TV shows an 'allow' dialog, tap Allow within 30s)");

    firetv::perform(&tv, &Command::Power(true), &path)
        .await
        .expect("wake the television");
    tokio::time::sleep(Duration::from_secs(1)).await;
    firetv::perform(&tv, &Command::Key(Key::Home), &path)
        .await
        .expect("press HOME");
    eprintln!("  woke and pressed HOME on {}", tv.name);
}
