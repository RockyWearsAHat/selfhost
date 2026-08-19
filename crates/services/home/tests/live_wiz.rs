//! Acceptance tests that need the real WiZ bulbs on the real network.
//!
//! The same arrangement as `live_sonos.rs`, for the same reasons: the unit
//! suite proves the parsers against datagrams captured from these bulbs, and
//! only a run against the hardware proves a bulb says those bytes, that UDP
//! loss is survived, and that a write moves a real light in a real room.
//!
//! Every test is `#[ignore]`d and run deliberately:
//!
//! ```text
//! cargo test -p selfhost-home --test live_wiz -- --ignored --nocapture --test-threads=1
//! ```
//!
//! On a network with no WiZ bulbs they skip rather than fail.
//!
//! **These tests touch real lights in somebody's house.** The write test
//! restores the exact state it found — power, brightness, temperature —
//! including when an assertion fails, because a suite that leaves a bedroom
//! light on at full brightness has done more harm than the coverage was
//! worth. The light it drives does flicker briefly; that is the test working.

use std::time::Duration;

use selfhost_home::device::{Capability, Command, Kind, Power};
use selfhost_home::wiz;

/// The window discovery listens for. Generous, because a missed bulb here
/// reads as "no WiZ on this network" and skips every test below it.
const SWEEP: Duration = Duration::from_secs(4);

macro_rules! bulbs_or_skip {
    () => {
        match wiz::discover(SWEEP).await {
            bulbs if bulbs.is_empty() => {
                eprintln!("skipped: no WiZ bulb answered on this network");
                return;
            }
            bulbs => bulbs,
        }
    };
}

#[tokio::test]
#[ignore = "needs a real WiZ bulb on the network"]
async fn a_bulb_answers_discovery() {
    let bulbs = bulbs_or_skip!();
    for bulb in &bulbs {
        eprintln!(
            "  {} — {} — {}",
            bulb.id,
            bulb.name,
            bulb.address.as_deref().unwrap_or("?")
        );
    }
    assert!(!bulbs.is_empty());
}

#[tokio::test]
#[ignore = "needs a real WiZ bulb on the network"]
async fn a_bulb_is_a_light_with_light_capabilities() {
    let bulbs = bulbs_or_skip!();
    for bulb in &bulbs {
        assert!(matches!(bulb.kind, Kind::Light | Kind::Plug));
        assert!(bulb.can(Capability::Power), "{} must advertise power", bulb.name);
        assert!(bulb.reachable);
    }
}

#[tokio::test]
#[ignore = "needs a real WiZ bulb on the network"]
async fn a_bulb_reports_real_state() {
    let mut bulbs = bulbs_or_skip!();
    for bulb in &mut bulbs {
        wiz::refresh(bulb).await;
        eprintln!(
            "  {} — reachable={} power={:?} brightness={:?} temp={:?} color={:?}",
            bulb.name,
            bulb.reachable,
            bulb.state.power,
            bulb.state.brightness,
            bulb.state.color_temp,
            bulb.state.color
        );
        assert!(bulb.reachable, "{} answered discovery moments ago", bulb.name);
        assert!(bulb.state.power.is_some(), "a refreshed bulb knows whether it is on");
    }
}

/// The write round trip: power and brightness set, read back from the bulb,
/// and restored to exactly what was found — the restore runs even when an
/// assertion fails.
#[tokio::test]
#[ignore = "needs a real WiZ bulb on the network; FLICKERS A REAL LIGHT BRIEFLY"]
async fn a_write_is_a_read_back_and_the_light_is_restored() {
    let bulbs = bulbs_or_skip!();
    let mut bulb = bulbs.into_iter().next().expect("at least one");
    wiz::refresh(&mut bulb).await;
    let before_power = bulb.state.power;
    let before_brightness = bulb.state.brightness;
    let before_temp = bulb.state.color_temp;
    eprintln!(
        "  {} found at power={before_power:?} brightness={before_brightness:?} temp={before_temp:?}",
        bulb.name
    );

    let outcome = async {
        wiz::perform(&bulb, &Command::Power(true)).await?;
        wiz::perform(&bulb, &Command::Brightness(37)).await?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        wiz::refresh(&mut bulb).await;
        eprintln!(
            "  set to on/37, read back power={:?} brightness={:?}",
            bulb.state.power, bulb.state.brightness
        );
        if bulb.state.power != Some(Power::On) {
            return Err("the bulb did not read back as on".to_owned());
        }
        if bulb.state.brightness != Some(37) {
            return Err(format!("brightness read back as {:?}, not 37", bulb.state.brightness));
        }
        Ok(())
    }
    .await;

    // The restore is unconditional: whatever the assertions said, the light
    // goes back to exactly what it was.
    if let Some(temp) = before_temp {
        let _ = wiz::perform(&bulb, &Command::ColorTemp(temp)).await;
    }
    if let Some(brightness) = before_brightness {
        let _ = wiz::perform(&bulb, &Command::Brightness(brightness)).await;
    }
    let _ = wiz::perform(&bulb, &Command::Power(before_power == Some(Power::On))).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    wiz::refresh(&mut bulb).await;
    eprintln!(
        "  restored to power={:?} brightness={:?} temp={:?}",
        bulb.state.power, bulb.state.brightness, bulb.state.color_temp
    );

    outcome.expect("the write round trip");
    assert_eq!(bulb.state.power, before_power, "the restore must land");
    assert_eq!(bulb.state.brightness, before_brightness);
}

/// An absent bulb fails within the answer budget rather than hanging — the
/// property that keeps one unscrewed bulb from stalling the whole refresh.
#[tokio::test]
#[ignore = "needs the network, though not a bulb"]
async fn an_absent_bulb_fails_quickly_rather_than_hanging() {
    let mut ghost = selfhost_home::Device::new(
        wiz::id_of("000000000000"),
        "Ghost",
        Kind::Light,
    );
    ghost.address = Some("192.0.2.1".to_owned());
    let started = std::time::Instant::now();
    wiz::refresh(&mut ghost).await;
    let elapsed = started.elapsed();
    eprintln!("  failed after {elapsed:?}: {:?}", ghost.note);
    assert!(!ghost.reachable);
    assert!(elapsed < Duration::from_secs(4), "took {elapsed:?}");
}
