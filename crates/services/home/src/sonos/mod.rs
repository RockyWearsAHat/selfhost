//! The Sonos driver: one household of speakers, turned into [`Device`] values
//! and driven by [`Command`] ones.
//!
//! The modules below are the protocol; this file is the translation, and it is
//! the only place in the crate that knows a `RINCON_…` UUID from a device id.
//!
//! | Module | Pure? | What it is the authority on |
//! |---|---|---|
//! | [`control`] | mixed | every action performed against a speaker |
//! | [`topology`] | yes | reading `ZoneGroupState` into a household |
//! | [`event`] | yes | reading a GENA `LastChange` into a state delta |
//!
//! # Two facts shape everything here
//!
//! **One speaker answers for the whole house.** `GetZoneGroupState` returns
//! every player, its address, its name and its group, whichever player is
//! asked. So discovery only has to find *one* Sonos and the rest arrive with
//! it — which is why [`household`] takes a single seed address and returns
//! every device.
//!
//! **A transport command belongs to the group's coordinator.** Telling a
//! grouped speaker to pause does nothing; the coordinator is playing on its
//! behalf. [`perform`] therefore resolves the coordinator before sending
//! anything transport-shaped, and sends volume to the speaker itself, because
//! volume is genuinely per-player. Getting this backwards produces a dashboard
//! whose buttons work only when nothing is grouped, which is the single most
//! common defect in a hand-written Sonos client.

pub mod control;
pub mod event;
pub mod topology;

use crate::device::{Capability, Command, Device, DeviceId, Kind, State, Transport};
use crate::soap::SoapError;

/// The driver's name, and the first half of every device id it produces.
pub const DRIVER: &str = "sonos";

/// The id a speaker's UUID maps to.
#[must_use]
pub fn id_of(uuid: &str) -> DeviceId {
    DeviceId::new(DRIVER, uuid)
}

/// Every speaker in the household the seed address belongs to.
///
/// The returned devices carry name, room, address, group membership and
/// battery — everything the topology document knows — but no transport or
/// volume state, because that costs a SOAP call per speaker and belongs to
/// [`refresh`], which the hub runs on its own schedule.
pub async fn household(seed_address: &str) -> Result<Vec<Device>, SoapError> {
    let document = control::zone_group_state(seed_address).await?;
    Ok(from_zones(&topology::parse(&document)))
}

/// Turns a parsed topology into devices.
///
/// Split out from [`household`] so the mapping can be tested against a
/// captured document without a speaker on the network.
#[must_use]
pub fn from_zones(zones: &[topology::Zone]) -> Vec<Device> {
    zones
        .iter()
        .map(|zone| {
            let mut device = Device::new(id_of(&zone.uuid), zone.name.clone(), Kind::Speaker)
                .advertise(&[
                    Capability::Transport,
                    Capability::Volume,
                    Capability::Mute,
                    Capability::Group,
                ]);
            // A Sonos names itself after the room it is in, and that is very
            // often the right room name too. It is a default the registry may
            // override, not a claim.
            device.room = Some(zone.name.clone());
            device.address = Some(zone.address.clone());
            // A speaker present in the topology is one the household can see.
            // Whether it answers a SOAP call is a separate question, settled
            // by `refresh`, which clears this when the call fails.
            device.reachable = !zone.address.is_empty();
            device.state = State {
                coordinator: Some(id_of(&zone.coordinator)),
                group: zones
                    .iter()
                    .filter(|other| other.coordinator == zone.coordinator)
                    .map(|other| id_of(&other.uuid))
                    .collect(),
                battery_pct: zone.battery_pct,
                battery_charging: zone.battery_charging,
                ..State::default()
            };
            device
        })
        .collect()
}

/// Fills in what is playing and how loud, for one speaker.
///
/// Reads are done against the speaker itself even when it is grouped: its own
/// volume is its own, and its transport state mirrors its coordinator's, which
/// is what the page should show on that speaker's plate.
///
/// A failure marks the device unreachable and says so in a sentence rather
/// than propagating — one speaker being unplugged must not fail the whole
/// refresh, and the reader is better served by "the Kitchen speaker did not
/// answer" on one plate than by an empty page.
pub async fn refresh(device: &mut Device) {
    let Some(address) = device.address.clone() else {
        device.reachable = false;
        device.note = Some("This speaker has no address yet.".to_owned());
        return;
    };

    match control::transport_info(&address).await {
        Ok(transport) => {
            device.reachable = true;
            device.note = None;
            device.state.transport = Some(transport);
        }
        Err(error) => {
            device.reachable = false;
            device.note = Some(format!("{} did not answer: {error}", device.name));
            return;
        }
    }

    if let Ok(level) = control::volume(&address).await {
        device.state.volume = Some(level);
    }
    if let Ok(muted) = control::muted(&address).await {
        device.state.muted = Some(muted);
    }

    // Position is the one read that is worth skipping when nothing is
    // playing: a stopped speaker returns an empty track, and asking costs a
    // whole TCP connection per speaker per poll.
    if device.state.transport == Some(Transport::Stopped) {
        device.state.title = None;
        device.state.artist = None;
        device.state.duration_secs = None;
        device.state.position_secs = None;
        device.state.source = None;
        return;
    }

    if let Ok(position) = control::position_info(&address).await {
        device.state.title = position.title;
        device.state.artist = position.artist;
        device.state.duration_secs = position.duration_secs;
        device.state.position_secs = position.position_secs;
        device.state.source = position.uri.as_deref().map(describe_source).map(str::to_owned);
    }
}

/// What to call the thing a URI names, in a word a person recognises.
///
/// The URI scheme is the only place the protocol says where audio came from,
/// and the page wants a word rather than a scheme.
#[must_use]
pub fn describe_source(uri: &str) -> &'static str {
    if uri.starts_with("x-rincon-mp3radio:") || uri.starts_with("x-sonosapi-stream:") {
        "radio"
    } else if uri.starts_with("x-rincon-stream:") {
        "line in"
    } else if uri.starts_with("x-sonos-htastream:") {
        "television"
    } else if uri.starts_with("x-rincon:") {
        "following the group"
    } else if uri.starts_with("x-rincon-queue:") || uri.starts_with("x-file-cifs:") {
        "queue"
    } else if uri.starts_with("x-sonosapi-radio:") || uri.starts_with("x-sonosapi-hls:") {
        "streaming"
    } else {
        "playing"
    }
}

/// Performs one command against one speaker.
///
/// `house` is every device the hub knows, needed because a transport command
/// must be addressed to the group's coordinator and only the hub knows where
/// that speaker lives.
pub async fn perform(device: &Device, house: &[Device], command: &Command) -> Result<(), String> {
    let own_address = device
        .address
        .clone()
        .ok_or_else(|| format!("{} has no address to send to.", device.name))?;

    // Transport belongs to whoever is actually playing. For a standalone
    // speaker that is itself, so this resolves to the same address and costs
    // nothing; for a grouped one it is the difference between working and
    // silently doing nothing.
    let transport_address = coordinator_address(device, house).unwrap_or_else(|| own_address.clone());

    let outcome = match command {
        Command::Play => control::play(&transport_address).await,
        Command::Pause => control::pause(&transport_address).await,
        Command::Stop => control::stop(&transport_address).await,
        Command::Next => control::next(&transport_address).await,
        Command::Previous => control::previous(&transport_address).await,
        // Volume and mute are per-player and are sent to the speaker named,
        // never to the coordinator — turning down a grouped speaker must not
        // turn down the whole group.
        Command::Volume(level) => control::set_volume(&own_address, *level).await,
        Command::VolumeStep(step) => control::adjust_volume(&own_address, *step).await.map(|_| ()),
        Command::Mute(muted) => control::set_muted(&own_address, *muted).await,
        Command::Join(target) => {
            let coordinator = house
                .iter()
                .find(|other| &other.id == target)
                .ok_or_else(|| "There is no such speaker to join.".to_owned())?;
            // Join the target's *coordinator*, not the target: joining a
            // speaker that is itself following another would otherwise make a
            // group of one behind a group of one.
            let uuid = coordinator
                .state
                .coordinator
                .as_ref()
                .unwrap_or(&coordinator.id)
                .key()
                .to_uppercase();
            control::join(&own_address, &uuid).await
        }
        Command::Leave => control::leave(&own_address).await,
        other => {
            return Err(format!(
                "A Sonos speaker cannot be asked to {}.",
                other.as_str().replace('_', " ")
            ))
        }
    };

    outcome.map_err(|error| format!("{} refused: {error}", device.name))
}

/// Where the speaker coordinating this device's group can be reached.
fn coordinator_address(device: &Device, house: &[Device]) -> Option<String> {
    let coordinator = device.state.coordinator.as_ref()?;
    house
        .iter()
        .find(|other| &other.id == coordinator)
        .and_then(|other| other.address.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ungrouped household, captured from the two real speakers.
    const UNGROUPED: &str = concat!(
        r#"<ZoneGroupState><ZoneGroups>"#,
        r#"<ZoneGroup Coordinator="RINCON_7828CA1491AE01400" ID="RINCON_7828CA1491AE01400:1058864410">"#,
        r#"<ZoneGroupMember UUID="RINCON_7828CA1491AE01400" Location="http://192.168.1.6:1400/xml/device_description.xml" ZoneName="Kitchen" AirPlayEnabled="1" MoreInfo="TargetRoomName:Kitchen"/>"#,
        r#"</ZoneGroup>"#,
        r#"<ZoneGroup Coordinator="RINCON_F0F6C150935601400" ID="RINCON_F0F6C150935601400:731391979">"#,
        r#"<ZoneGroupMember UUID="RINCON_F0F6C150935601400" Location="http://192.168.1.17:1400/xml/device_description.xml" ZoneName="Sonos Move" AirPlayEnabled="1" MoreInfo="RawBattPct:100,BattPct:100,BattChg:CHARGING,BattTmp:25"/>"#,
        r#"</ZoneGroup>"#,
        r#"</ZoneGroups><VanishedDevices></VanishedDevices></ZoneGroupState>"#,
    );

    /// The same two speakers after the Move joined the Kitchen's group.
    const GROUPED: &str = concat!(
        r#"<ZoneGroupState><ZoneGroups>"#,
        r#"<ZoneGroup Coordinator="RINCON_7828CA1491AE01400" ID="RINCON_7828CA1491AE01400:1058864410">"#,
        r#"<ZoneGroupMember UUID="RINCON_7828CA1491AE01400" Location="http://192.168.1.6:1400/xml/device_description.xml" ZoneName="Kitchen"/>"#,
        r#"<ZoneGroupMember UUID="RINCON_F0F6C150935601400" Location="http://192.168.1.17:1400/xml/device_description.xml" ZoneName="Sonos Move" MoreInfo="RawBattPct:100,BattPct:100,BattChg:CHARGING,BattTmp:25"/>"#,
        r#"</ZoneGroup>"#,
        r#"</ZoneGroups><VanishedDevices></VanishedDevices></ZoneGroupState>"#,
    );

    fn house(document: &str) -> Vec<Device> {
        from_zones(&topology::parse(document))
    }

    #[test]
    fn both_real_speakers_become_devices() {
        let devices = house(UNGROUPED);
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].name, "Kitchen");
        assert_eq!(devices[0].address.as_deref(), Some("192.168.1.6"));
        assert_eq!(devices[1].name, "Sonos Move");
        assert_eq!(devices[1].address.as_deref(), Some("192.168.1.17"));
    }

    #[test]
    fn a_speaker_advertises_what_a_sonos_can_do() {
        let devices = house(UNGROUPED);
        for capability in [
            Capability::Transport,
            Capability::Volume,
            Capability::Mute,
            Capability::Group,
        ] {
            assert!(devices[0].can(capability), "a speaker must advertise {capability:?}");
        }
        assert!(!devices[0].can(Capability::Color));
    }

    #[test]
    fn the_move_reports_its_battery() {
        let devices = house(UNGROUPED);
        let move_speaker = devices.iter().find(|d| d.name == "Sonos Move").expect("the Move");
        assert_eq!(move_speaker.state.battery_pct, Some(100));
        assert_eq!(move_speaker.state.battery_charging, Some(true));
    }

    /// A standalone speaker is a group of one whose coordinator is itself.
    #[test]
    fn an_ungrouped_speaker_coordinates_itself() {
        let devices = house(UNGROUPED);
        for device in &devices {
            assert_eq!(device.state.coordinator.as_ref(), Some(&device.id));
            assert_eq!(device.state.group, vec![device.id.clone()]);
        }
    }

    #[test]
    fn a_grouped_speaker_names_its_coordinator_and_its_whole_group() {
        let devices = house(GROUPED);
        let kitchen = id_of("RINCON_7828CA1491AE01400");
        for device in &devices {
            assert_eq!(device.state.coordinator.as_ref(), Some(&kitchen));
            assert_eq!(device.state.group.len(), 2);
        }
    }

    /// The defect this driver is shaped around: a transport command sent to a
    /// grouped member must be readdressed to the coordinator's address.
    #[test]
    fn a_transport_command_is_addressed_to_the_coordinator() {
        let devices = house(GROUPED);
        let follower = devices.iter().find(|d| d.name == "Sonos Move").expect("the Move");
        assert_eq!(follower.address.as_deref(), Some("192.168.1.17"));
        assert_eq!(
            coordinator_address(follower, &devices).as_deref(),
            Some("192.168.1.6"),
            "pause on the Move must be sent to the Kitchen, which is playing for it"
        );
    }

    /// …while volume is not. Turning down one speaker of a group must not turn
    /// down the group.
    #[test]
    fn an_ungrouped_speaker_addresses_itself() {
        let devices = house(UNGROUPED);
        let move_speaker = devices.iter().find(|d| d.name == "Sonos Move").expect("the Move");
        assert_eq!(
            coordinator_address(move_speaker, &devices).as_deref(),
            Some("192.168.1.17")
        );
    }

    #[test]
    fn every_uri_scheme_gets_a_word_a_person_recognises() {
        assert_eq!(describe_source("x-rincon-mp3radio://http://ice1.somafm.com/x"), "radio");
        assert_eq!(describe_source("x-rincon-stream:RINCON_A"), "line in");
        assert_eq!(describe_source("x-rincon:RINCON_A"), "following the group");
        assert_eq!(describe_source("x-rincon-queue:RINCON_A#0"), "queue");
        assert_eq!(describe_source("x-sonos-htastream:RINCON_A:spdif"), "television");
        assert_eq!(describe_source("https://example.invalid/track.mp3"), "playing");
    }

    #[test]
    fn a_speaker_refuses_a_command_no_speaker_can_perform() {
        let devices = house(UNGROUPED);
        let outcome = tokio_test_block(perform(
            &devices[0],
            &devices,
            &Command::Color("FF0000".into()),
        ));
        let sentence = outcome.expect_err("a speaker cannot change colour");
        assert!(sentence.contains("cannot be asked to"));
    }

    /// A tiny blocking runner so a test that never touches the network does
    /// not need the multi-threaded runtime attribute.
    fn tokio_test_block<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime")
            .block_on(future)
    }
}
