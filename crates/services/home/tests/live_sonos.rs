//! Acceptance tests that need the real speakers on the real network.
//!
//! These cannot be unit tests, and the distinction is the point of this file.
//! Everything in `src/` is tested against captured bytes, which proves the
//! parsers read what a Sonos said — it cannot prove that a Sonos says it, that
//! the socket handling survives a device which closes every connection, or
//! that a command actually moves a speaker in somebody's kitchen. Only a run
//! against the hardware proves that, and only on a network where the hardware
//! is present.
//!
//! So every test here is `#[ignore]`d and is run deliberately:
//!
//! ```text
//! cargo test -p selfhost-home --test live_sonos -- --ignored --nocapture
//! ```
//!
//! On a machine with no speakers they are skipped rather than failing, because
//! a red test suite that means "you are on the wrong network" trains people to
//! ignore red test suites.
//!
//! **These tests touch a real household.** They read freely, and the one that
//! writes — the volume round trip — restores what it found, including when it
//! fails, because a test suite that leaves somebody's kitchen at volume 100 at
//! two in the morning has done more harm than the coverage was worth.

use std::time::Duration;

use selfhost_home::device::Transport;
use selfhost_home::{discovery, sonos};

/// The window a sweep listens for. Generous, because a missed speaker here
/// reads as "no Sonos on this network" and skips every test below it.
const SWEEP: Duration = Duration::from_secs(4);

/// Finds one speaker, or returns `None` so the caller can skip.
async fn any_speaker() -> Option<String> {
    let found = discovery::sweep(SWEEP).await;
    found
        .into_iter()
        .find(|f| f.kind == discovery::FoundKind::Sonos)
        .map(|f| f.address)
}

macro_rules! speaker_or_skip {
    () => {
        match any_speaker().await {
            Some(address) => address,
            None => {
                eprintln!("skipped: no Sonos answered on this network");
                return;
            }
        }
    };
}

#[tokio::test]
#[ignore = "needs a real Sonos on the network"]
async fn a_speaker_answers_discovery() {
    let address = speaker_or_skip!();
    eprintln!("found a speaker at {address}");
    assert!(!address.is_empty());
}

/// The claim the whole driver rests on: one speaker describes the household.
#[tokio::test]
#[ignore = "needs a real Sonos on the network"]
async fn one_speaker_describes_the_whole_household() {
    let address = speaker_or_skip!();
    let devices = sonos::household(&address).await.expect("the household");
    assert!(!devices.is_empty(), "a speaker must at least describe itself");

    for device in &devices {
        eprintln!(
            "  {} — {} — {} — group of {}",
            device.id,
            device.name,
            device.address.as_deref().unwrap_or("?"),
            device.state.group.len()
        );
        assert!(device.address.is_some(), "every speaker must carry an address");
        assert!(!device.name.is_empty(), "every speaker must carry a name");
        assert!(
            device.state.coordinator.is_some(),
            "every speaker belongs to a group, even a group of one"
        );
    }
}

/// Reading state off a real speaker: the path the dashboard takes every two
/// seconds, end to end.
#[tokio::test]
#[ignore = "needs a real Sonos on the network"]
async fn a_speaker_reports_what_it_is_doing() {
    let address = speaker_or_skip!();
    let mut devices = sonos::household(&address).await.expect("the household");

    for device in &mut devices {
        sonos::refresh(device).await;
        eprintln!(
            "  {} — reachable={} transport={:?} volume={:?} muted={:?} title={:?}",
            device.name,
            device.reachable,
            device.state.transport,
            device.state.volume,
            device.state.muted,
            device.state.title,
        );
        assert!(device.reachable, "a speaker just discovered must answer: {:?}", device.note);
        assert!(device.state.transport.is_some(), "it must say what it is doing");
        let volume = device.state.volume.expect("it must report a volume");
        assert!(volume <= 100, "a volume is a percentage");
        assert!(device.state.muted.is_some(), "it must say whether it is muted");
    }
}

/// The one writing test. Sets a volume, reads it back, and puts it back —
/// including on failure, which is what the explicit restore below is for.
#[tokio::test]
#[ignore = "needs a real Sonos on the network; CHANGES A REAL SPEAKER'S VOLUME"]
async fn a_volume_set_is_a_volume_read_back() {
    let address = speaker_or_skip!();

    let original = sonos::control::volume(&address).await.expect("a volume to start from");
    eprintln!("  {address} is at volume {original}");

    // A quiet, unmistakable value that is not whatever it already was.
    let target = if original == 7 { 9 } else { 7 };

    let outcome = async {
        sonos::control::set_volume(&address, target).await?;
        // The speaker applies this immediately; no settle is needed for volume,
        // unlike a transport change.
        let read_back = sonos::control::volume(&address).await?;
        Ok::<u8, selfhost_home::soap::SoapError>(read_back)
    }
    .await;

    // Restore before asserting, so a failed assertion still leaves the kitchen
    // as it was found.
    let restored = sonos::control::set_volume(&address, original).await;

    let read_back = outcome.expect("setting and reading a volume must succeed");
    assert_eq!(read_back, target, "the speaker must report the volume it was set to");
    restored.expect("the original volume must be restored");
    eprintln!("  set to {target}, read back {read_back}, restored to {original}");
}

/// Mute is a separate fact from volume, and this proves the driver keeps them
/// separate — a muted speaker must remember its level.
#[tokio::test]
#[ignore = "needs a real Sonos on the network; MUTES A REAL SPEAKER BRIEFLY"]
async fn muting_does_not_disturb_the_volume() {
    let address = speaker_or_skip!();

    let original_volume = sonos::control::volume(&address).await.expect("a volume");
    let original_mute = sonos::control::muted(&address).await.expect("a mute state");

    let outcome = async {
        sonos::control::set_muted(&address, true).await?;
        let muted = sonos::control::muted(&address).await?;
        let volume_while_muted = sonos::control::volume(&address).await?;
        Ok::<(bool, u8), selfhost_home::soap::SoapError>((muted, volume_while_muted))
    }
    .await;

    let restored = sonos::control::set_muted(&address, original_mute).await;

    let (muted, volume_while_muted) = outcome.expect("muting must succeed");
    assert!(muted, "the speaker must report itself muted");
    assert_eq!(
        volume_while_muted, original_volume,
        "muting must not change the remembered volume"
    );
    restored.expect("the original mute state must be restored");
}

/// Transport state is legible even when nothing is playing — this is the read
/// that decides which buttons the page draws.
#[tokio::test]
#[ignore = "needs a real Sonos on the network"]
async fn the_transport_state_is_one_of_the_four() {
    let address = speaker_or_skip!();
    let state = sonos::control::transport_info(&address).await.expect("a transport state");
    eprintln!("  {address} is {state:?}");
    assert!(matches!(
        state,
        Transport::Stopped | Transport::Playing | Transport::Paused | Transport::Transitioning
    ));
}

/// A speaker's own description names the room, which is the default a person
/// sees before they rename anything.
#[tokio::test]
#[ignore = "needs a real Sonos on the network"]
async fn a_speaker_names_its_room_and_model() {
    let address = speaker_or_skip!();
    let (room, model, uuid) = sonos::control::description(&address).await.expect("a description");
    eprintln!("  {address}: room={room:?} model={model:?} uuid={uuid:?}");
    assert!(!room.is_empty(), "a speaker must name its room");
    assert!(uuid.starts_with("RINCON_"), "a Sonos UUID starts with RINCON_");
}

/// An address with nothing behind it must fail quickly and in words, not hang.
/// This is what keeps one unplugged speaker from stalling the whole refresh.
#[tokio::test]
#[ignore = "needs a real network"]
async fn an_absent_speaker_fails_quickly_rather_than_hanging() {
    let started = std::time::Instant::now();
    // A documentation-range address, which is routable-looking and answers
    // nothing — the shape of a speaker that has been unplugged.
    let outcome = sonos::control::transport_info("192.0.2.1").await;
    let elapsed = started.elapsed();
    eprintln!("  failed after {elapsed:?}: {outcome:?}");
    assert!(outcome.is_err(), "there is nothing at that address");
    assert!(
        elapsed < Duration::from_secs(10),
        "an absent speaker must not hold the refresh for {elapsed:?}"
    );
}
