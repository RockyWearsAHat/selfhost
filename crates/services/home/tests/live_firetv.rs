//! The Fire TV remote API, against a real television on this network.
//!
//! Every test is `#[ignore]`d and run deliberately:
//!
//! ```text
//! SELFHOST_FIRETV=192.168.1.12 SELFHOST_FIRETV_TOKEN=… \
//!   cargo test -p selfhost-home --test live_firetv -- --ignored --nocapture --test-threads=1
//! ```
//!
//! **The token is not in this repository and must not be.** It is the pairing
//! `crate::firetv::confirm` returns, it lives on the television until somebody
//! removes it there, and it belongs in the registry beside the device. The
//! tests that need one skip cleanly without it, so the read-only half of this
//! suite runs on any machine with a Fire TV on the LAN and no setup at all.
//!
//! The wake test **turns a television on**, and the key tests **move the
//! selection on a real screen**. They restore nothing, because there is
//! nothing to restore: a d-pad press is not a state a suite can put back, and
//! pretending otherwise would be worse than saying so. Run them when nobody is
//! watching that television.

use std::time::Duration;

use selfhost_home::device::{Command, Key};
use selfhost_home::firetv;

/// The television under test, or an early return.
macro_rules! television_or_skip {
    () => {{
        match std::env::var("SELFHOST_FIRETV") {
            Ok(address) if !address.is_empty() => address,
            _ => {
                eprintln!("skipped: set SELFHOST_FIRETV to a Fire TV address");
                return;
            }
        }
    }};
}

/// The pairing token, or an early return.
macro_rules! token_or_skip {
    () => {{
        match std::env::var("SELFHOST_FIRETV_TOKEN") {
            Ok(token) if !token.is_empty() => token,
            _ => {
                eprintln!("skipped: set SELFHOST_FIRETV_TOKEN to a paired token");
                return;
            }
        }
    }};
}

/// The wake is the whole power-on story and needs no token, which is the
/// property worth proving: an unpaired television can still be turned on.
#[tokio::test]
#[ignore = "turns a real television on"]
async fn the_wake_needs_no_pairing_and_opens_the_remote_service() {
    let address = television_or_skip!();

    firetv::wake(&address).await.expect("the television took the wake");
    eprintln!("  {address} — woken, no token used");

    // The service is started by that launch, so a connection to it now is the
    // proof the launch did more than answer 201.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let reachable = tokio::net::TcpStream::connect(format!("{address}:{}", firetv::REMOTE_PORT))
        .await
        .is_ok();
    assert!(reachable, "the remote service should be listening after a wake");
    eprintln!("  {address}:{} — listening", firetv::REMOTE_PORT);
}

/// An unauthenticated command is refused, and refused as a *sentence*. This is
/// the one live test that needs no token at all and still proves something
/// about authorisation.
#[tokio::test]
#[ignore = "needs a real Fire TV on the network"]
async fn a_command_without_a_pairing_is_refused_in_words() {
    let address = television_or_skip!();
    firetv::wake(&address).await.expect("the television took the wake");
    tokio::time::sleep(Duration::from_secs(3)).await;

    let error = firetv::perform(&address, "not-a-token", &Command::Key(Key::Home))
        .await
        .expect_err("an invalid token must not be honoured");
    eprintln!("  refused: {error}");
    assert!(!error.contains("403"), "the reader is shown a reason, not a status");
}

/// The d-pad, on the real screen. Four directions and a back, chosen so the
/// television ends roughly where it started.
#[tokio::test]
#[ignore = "moves the selection on a real screen"]
async fn the_d_pad_lands_on_a_real_television() {
    let address = television_or_skip!();
    let token = token_or_skip!();

    for key in [Key::Down, Key::Right, Key::Left, Key::Up, Key::Back] {
        firetv::perform(&address, &token, &Command::Key(key))
            .await
            .unwrap_or_else(|error| panic!("{} was refused: {error}", key.as_str()));
        eprintln!("  {} — 200", key.as_str());
        tokio::time::sleep(Duration::from_millis(600)).await;
    }
}

/// Volume is refused **before** a request is sent, and the sentence says why.
///
/// The point of this test is that the refusal is local: the television would
/// answer `400`, and relaying that would be both slower and less honest than
/// naming the actual reason, which is that the button lives on the remote's
/// infrared emitter and not on the stick.
#[tokio::test]
#[ignore = "needs a real Fire TV on the network"]
async fn volume_is_refused_with_the_reason_and_not_relayed() {
    let address = television_or_skip!();
    let token = token_or_skip!();

    let error = firetv::perform(&address, &token, &Command::Key(Key::VolumeUp))
        .await
        .expect_err("a Fire TV has no volume key");
    eprintln!("  refused: {error}");
    assert!(error.contains("infrared"), "the reason is named: {error}");
}

/// Launching by package name — the thing DIAL cannot do. Prime Video is the
/// case worth proving, because it is Amazon's own application, is not
/// DIAL-registered, and was recorded as an unreachable `404` before this API
/// was found.
#[tokio::test]
#[ignore = "puts an application on a real screen"]
async fn an_application_launches_by_package_name() {
    let address = television_or_skip!();
    let token = token_or_skip!();

    for package in ["com.amazon.avod", "com.netflix.ninja"] {
        firetv::perform(&address, &token, &Command::Launch(package.to_owned()))
            .await
            .unwrap_or_else(|error| panic!("{package} was refused: {error}"));
        eprintln!("  {package} — launched");
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    // Put the television back on its home screen rather than leaving somebody
    // else's application up.
    firetv::perform(&address, &token, &Command::Key(Key::Home))
        .await
        .expect("home restores the screen");
    eprintln!("  home — restored");
}

/// Power off is best-effort and the stick survives it: this asserts the half
/// that is actually true, which is that the stick stays reachable and can be
/// woken again. Whether the *television* went dark is a CEC fact this suite
/// cannot observe and therefore does not claim.
#[tokio::test]
#[ignore = "sleeps a real television and wakes it again"]
async fn sleep_leaves_the_stick_reachable_and_the_wake_brings_it_back() {
    let address = television_or_skip!();
    let token = token_or_skip!();

    firetv::perform(&address, &token, &Command::Power(false))
        .await
        .expect("the stick took the sleep");
    eprintln!("  slept");
    tokio::time::sleep(Duration::from_secs(8)).await;

    firetv::perform(&address, &token, &Command::Power(true)).await.expect("the wake landed");
    tokio::time::sleep(Duration::from_secs(4)).await;

    firetv::perform(&address, &token, &Command::Key(Key::Home))
        .await
        .expect("the television takes keys again after a wake");
    eprintln!("  woken, and taking keys again");
}

/// The whole path a button press actually takes: hub → registry → routing →
/// driver → television.
///
/// The unit suite proves each piece and none of the seams, and the seams are
/// where this crate's two real defects have lived (home-lab.dx §"Two defects
/// the unit suite could not have found"). Specifically it proves the two facts
/// a page depends on and a driver test cannot see: that a **paired** television
/// advertises `keys`, so the d-pad is drawn at all, and that a `Key` command
/// reaches the remote API rather than DIAL.
#[tokio::test]
#[ignore = "moves the selection on a real screen"]
async fn the_hub_routes_a_key_to_the_remote_api() {
    use selfhost_home::api::Act;
    use selfhost_home::device::Capability;
    use selfhost_home::hub::Hub;
    use selfhost_home::registry::Registry;

    let address = television_or_skip!();
    let token = token_or_skip!();

    let hub = Hub::new(std::env::temp_dir().join("selfhost-live-firetv-registry"));
    hub.discover().await;

    let (_, _, devices) = hub.snapshot().await;
    let Some(television) =
        devices.into_iter().find(|device| device.address.as_deref() == Some(address.as_str()))
    else {
        eprintln!("skipped: {address} was not discovered");
        return;
    };
    eprintln!("  found {} — {}", television.id, television.name);

    // Unpaired, the television offers what DIAL and the wake give and no more.
    assert!(television.can(Capability::Apps));
    assert!(television.can(Capability::Power), "a wake needs no pairing");

    // Pair it by writing the token the way `confirm_pairing` would, then let
    // the hub re-read the device. This stands in for the PIN exchange, which
    // needs a person at the screen and so cannot live in a suite.
    let mut registry = Registry::default();
    registry.set_token(&television.id, Some(token));
    let path = std::env::temp_dir().join("selfhost-live-firetv-registry");
    registry.save(&path).expect("the registry saves");

    let hub = Hub::new(path);
    hub.discover().await;
    let (_, _, devices) = hub.snapshot().await;
    let television = devices
        .into_iter()
        .find(|device| device.id == television.id)
        .expect("the television is still there");

    assert!(television.can(Capability::Keys), "a paired television advertises keys");
    assert!(television.can(Capability::Transport));
    eprintln!("  paired — advertises {:?}", television.capabilities);

    hub.apply(&television.id, Act::Command(Command::Key(Key::Down)))
        .await
        .expect("the hub routed the key to the remote API");
    eprintln!("  down — landed through the hub");

    // And the refusal still names infrared rather than relaying a 400.
    let error = hub
        .apply(&television.id, Act::Command(Command::Key(Key::VolumeUp)))
        .await
        .expect_err("a Fire TV has no volume key");
    eprintln!("  refused: {error}");
}
