//! Acceptance tests that need a real DIAL television on the real network.
//!
//! The same arrangement as `live_wiz.rs`, for the same reasons: the unit suite
//! proves the parsers and request builders against the captured responses, and
//! only a run against the hardware proves a television still says those bytes.
//!
//! Every test is `#[ignore]`d and run deliberately:
//!
//! ```text
//! cargo test -p selfhost-home --test live_dial -- --ignored --nocapture --test-threads=1
//! ```
//!
//! On a network with no DIAL device they skip rather than fail.
//!
//! **The launch test puts Netflix on a real screen in somebody's living room
//! and then stops it.** It restores what it found — a television that was
//! showing nothing shows nothing again — but the screen does visibly change
//! for a few seconds, so it is a separate test from the read-only ones and
//! should be run when nobody is watching that television. The read-only tests
//! change nothing anywhere.

use std::time::Duration;

use selfhost_home::device::{Capability, Command, Kind};
use selfhost_home::{dial, discovery};

/// The window the SSDP sweep listens for. Generous for the same reason the
/// WiZ suite's is: a missed answer reads as "no television on this network".
const SWEEP: Duration = Duration::from_secs(4);

/// Every television the sweep found, as devices, or an early return.
macro_rules! televisions_or_skip {
    () => {{
        let found = discovery::sweep(SWEEP).await;
        let mut televisions = Vec::new();
        for entry in found.iter().filter(|f| f.kind == discovery::FoundKind::Dial) {
            match dial::television(entry).await {
                Ok(device) => televisions.push(device),
                Err(error) => eprintln!("  {} did not describe itself: {error}", entry.address),
            }
        }
        if televisions.is_empty() {
            eprintln!("skipped: no DIAL television answered on this network");
            return;
        }
        televisions
    }};
}

#[tokio::test]
#[ignore = "needs a real DIAL television on the network"]
async fn a_television_answers_the_dial_search_and_describes_itself() {
    let televisions = televisions_or_skip!();
    for tv in &televisions {
        eprintln!(
            "  {} — {} — {} — apps at {}",
            tv.id,
            tv.name,
            tv.address.as_deref().unwrap_or("?"),
            tv.location.as_deref().unwrap_or("?"),
        );
        assert_eq!(tv.kind, Kind::Television);
        assert!(tv.can(Capability::Apps), "{} must advertise apps", tv.name);
        assert!(tv.reachable);
        assert!(tv.location.is_some(), "{} must state its Application-URL", tv.name);
    }
}

/// Read-only: asks each television which of the known applications is on the
/// screen, which is exactly what the hub's refresh does every two seconds.
#[tokio::test]
#[ignore = "needs a real DIAL television on the network"]
async fn a_television_reports_its_application_states() {
    let televisions = televisions_or_skip!();
    for mut tv in televisions {
        dial::refresh(&mut tv).await;
        eprintln!(
            "  {} — reachable {} — running {}",
            tv.name,
            tv.reachable,
            tv.state.app.as_deref().unwrap_or("nothing"),
        );
        assert!(tv.reachable, "{} answered discovery but not a status", tv.name);
    }
}

/// **Puts Netflix on the screen and stops it again.** The full measured round
/// trip — POST answers 201, the state reads running, DELETE answers 200, the
/// state reads stopped — as the one live proof the pure halves cannot give.
/// Run it when nobody is watching the television.
#[tokio::test]
#[ignore = "launches Netflix on a real screen — run when nobody is watching"]
async fn an_app_launches_and_stops_and_the_screen_is_left_as_found() {
    let televisions = televisions_or_skip!();
    let Some(mut tv) = televisions.into_iter().next() else {
        return;
    };

    dial::refresh(&mut tv).await;
    if tv.state.app.is_some() {
        eprintln!("skipped: {} is showing {:?} — not interrupting it", tv.name, tv.state.app);
        return;
    }

    dial::perform(&tv, &Command::Launch("Netflix".into())).await.expect("the launch");
    tokio::time::sleep(Duration::from_secs(6)).await;
    dial::refresh(&mut tv).await;
    let launched = tv.state.app.as_deref() == Some("Netflix");

    // Restore before asserting, so a failed assertion still clears the screen.
    let stopped = dial::perform(&tv, &Command::Stop).await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    dial::refresh(&mut tv).await;

    assert!(launched, "Netflix did not report running after the launch");
    stopped.expect("the stop");
    assert_eq!(tv.state.app, None, "the screen was not left as found");
}
