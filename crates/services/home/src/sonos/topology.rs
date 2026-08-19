//! Who the speakers in the house are, and which of them is in charge of which.
//!
//! Every Sonos player answers `GetZoneGroupState` with the *whole* household's
//! topology, so this module is the single authority on that answer: the list of
//! speakers, their addresses, and — the part everything else depends on — the
//! coordinator of each group. A grouped speaker does not play anything itself;
//! the coordinator plays for it. Sending `Play` to the member a person tapped
//! is the classic Sonos bug, and it fails silently, so the driver must resolve
//! a member to its coordinator before every transport call. That resolution
//! lives here, next to the parse that produces it, rather than being rebuilt
//! from raw XML at each call site.
//!
//! Two decisions are worth stating because the obvious alternatives are wrong.
//! The first is that a group is identified by its **coordinator UUID** and
//! never by the `ID` attribute: the numeric suffix of `RINCON_…:1058864410`
//! changes every time the household regroups, so a cache keyed on it would
//! treat an unchanged group as a new one on every event. The second is that
//! this parser accepts the document in *either* form — already unescaped, or
//! still singly escaped as it arrives inside a SOAP body — because the same
//! document reaches the driver down two paths, the `GetZoneGroupState` reply
//! and the `ZoneGroupState` GENA event, and having two entry points that
//! disagree about escaping is how one of them ends up parsing nothing.
//!
//! Unlike `LastChange`, `ZoneGroupState` is escaped exactly **once**. The
//! module unescapes at most one level and never guesses at a second.
//!
//! Nothing here does I/O, and nothing here fails: a document this module
//! cannot make sense of yields an empty list, because a driver that panicked
//! on a firmware upgrade's unfamiliar attribute would take the whole house
//! down with it.

use std::borrow::Cow;

use crate::device::clamp_percent;
use crate::xml;

/// One speaker, as the household describes it.
///
/// Flat rather than a tree of groups because every consumer — the registry,
/// the hub, the page — asks about *a speaker* and then asks who leads it. A
/// nested shape would force each of them to invert it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Zone {
    /// The `RINCON_…` UUID, which is what the speaker calls itself forever.
    /// This is the device key: the address changes with a DHCP lease and the
    /// name changes when a person renames the room.
    pub uuid: String,
    /// The room name a person gave the speaker, e.g. `Kitchen`. Shown as-is;
    /// the registry may override it, but this is what the household believes.
    pub name: String,
    /// The host from the member's `Location` URL, e.g. `192.168.1.6`. Carried
    /// without the port because every Sonos endpoint is on 1400 and a caller
    /// building a URL would only have to strip it again. Empty when the
    /// document omitted the location, which the driver reads as unreachable.
    pub address: String,
    /// The UUID of the speaker that actually plays for this one. Equal to
    /// [`Zone::uuid`] when the speaker is standalone or is itself the leader
    /// of a group; transport commands go here, never to [`Zone::uuid`].
    pub coordinator: String,
    /// Battery charge, when the speaker has a battery. `None` is the normal
    /// case — a mains-powered player never reports one — and is not an error.
    pub battery_pct: Option<u8>,
    /// Whether the battery is charging, when the speaker has one. Separate
    /// from the percentage because a Move on its base sits at 100 % and
    /// charging, and a page wants to say so rather than show a full bar.
    pub battery_charging: Option<bool>,
    /// Whether the speaker accepts AirPlay. Not a [`crate::device::Capability`]
    /// because nothing in this crate drives AirPlay; it is worth surfacing so
    /// a person knows why a phone can see one speaker and not another.
    pub airplay: bool,
}

impl Zone {
    /// Whether this speaker leads its own group.
    ///
    /// True for a standalone speaker as well as for the leader of a group of
    /// several, because Sonos does not distinguish them: a lone speaker is a
    /// group of one whose coordinator is itself.
    #[must_use]
    pub fn is_coordinator(&self) -> bool {
        self.uuid == self.coordinator
    }
}

/// Every speaker in the household, in the order the document names them.
///
/// Accepts the document escaped or not; see the module documentation. A
/// document that is missing, truncated, or shaped in a way this parser does
/// not recognise yields an empty list rather than a panic or an error, because
/// there is nothing a caller could do with the error that it would not also do
/// with "no speakers found": try again on the next event.
#[must_use]
pub fn parse(zone_group_state: &str) -> Vec<Zone> {
    let document = decode(zone_group_state);

    // Scope the scan to <ZoneGroups>. Its sibling <VanishedDevices> lists
    // speakers that have left the household — they are still described in
    // full, and reporting them would leave dead devices on the page forever.
    let Some(groups) = xml::elements(&document, "ZoneGroups").into_iter().next() else {
        return Vec::new();
    };

    let mut zones = Vec::new();
    for group in xml::elements(groups.inner, "ZoneGroup") {
        // A group without a coordinator is not a group this driver can drive,
        // so its members are dropped rather than guessed at.
        let Some(coordinator) = xml::attr(group.attrs, "Coordinator") else {
            continue;
        };
        for member in xml::elements(group.inner, "ZoneGroupMember") {
            let Some(uuid) = xml::attr(member.attrs, "UUID") else {
                continue;
            };
            let more_info = xml::attr(member.attrs, "MoreInfo").unwrap_or_default();
            zones.push(Zone {
                uuid,
                name: xml::attr(member.attrs, "ZoneName").unwrap_or_default(),
                address: xml::attr(member.attrs, "Location")
                    .as_deref()
                    .and_then(host_of)
                    .unwrap_or_default(),
                coordinator: coordinator.clone(),
                battery_pct: field(&more_info, "BattPct")
                    .and_then(|value| value.parse::<i32>().ok())
                    .map(clamp_percent),
                battery_charging: field(&more_info, "BattChg")
                    .map(|value| value.eq_ignore_ascii_case("CHARGING")),
                airplay: xml::attr(member.attrs, "AirPlayEnabled").as_deref() == Some("1"),
            });
        }
    }
    zones
}

/// The speaker that plays for the one named, given a parsed household.
///
/// The reason this module is worth importing rather than inlining: a transport
/// command aimed at a grouped member is accepted and then ignored by the
/// speaker, which looks exactly like a broken button. Returns `None` when the
/// household does not name the speaker at all — it vanished between the event
/// and the command — which a caller should treat as "unreachable", not as
/// "send it anyway". A speaker whose named coordinator is itself missing falls
/// back to the speaker: a command sent to it may fail, which is recoverable,
/// where refusing to send anything is a dead button.
#[must_use]
pub fn coordinator_of<'a>(zones: &'a [Zone], uuid: &str) -> Option<&'a Zone> {
    let member = zones.iter().find(|zone| zone.uuid == uuid)?;
    zones
        .iter()
        .find(|zone| zone.uuid == member.coordinator)
        .or(Some(member))
}

/// The host part of a `Location` URL, e.g. `192.168.1.6` from
/// `http://192.168.1.6:1400/xml/device_description.xml`.
///
/// Written by hand rather than with a URL type because the only URL this crate
/// ever reads is this one, always absolute, always HTTP. The port is dropped
/// only when it is numeric, so a bracketed IPv6 literal survives intact
/// instead of being cut at one of its own colons.
#[must_use]
pub fn host_of(location: &str) -> Option<String> {
    let after_scheme = location
        .split_once("//")
        .map_or(location, |(_, rest)| rest);
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Userinfo never appears in a Sonos location, but dropping it costs one
    // line and keeps a hostile document from producing an address like
    // "attacker@192.168.1.6".
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => host,
        _ => authority,
    };
    (!host.is_empty()).then(|| host.to_owned())
}

/// The document with at most one level of escaping removed.
///
/// Detection is by `&lt;ZoneGroup`, which cannot occur in an already-decoded
/// document — a decoded one contains the literal `<` — and which matches
/// whichever element the caller happened to hand over, whether that is the
/// whole SOAP envelope, `ZoneGroupState`, or a bare `ZoneGroups`. Borrowing in
/// the common case keeps the event path from copying the household on every
/// notification.
fn decode(document: &str) -> Cow<'_, str> {
    if document.contains("&lt;ZoneGroup") {
        Cow::Owned(xml::unescape(document))
    } else {
        Cow::Borrowed(document)
    }
}

/// One value out of `MoreInfo`, which is comma-separated `key:value` text and
/// not XML — `RawBattPct:100,BattPct:100,BattChg:CHARGING,BattTmp:25`.
///
/// Matched on the exact key so `BattPct` is never answered by `RawBattPct`,
/// which reports a different, unrounded number.
fn field<'a>(more_info: &'a str, key: &str) -> Option<&'a str> {
    more_info
        .split(',')
        .filter_map(|pair| pair.split_once(':'))
        .find(|(name, _)| name.trim() == key)
        .map(|(_, value)| value.trim())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The household as captured with the two speakers ungrouped: two groups
    /// of one, each its own coordinator.
    const UNGROUPED: &str = concat!(
        r#"<ZoneGroupState><ZoneGroups>"#,
        r#"<ZoneGroup Coordinator="RINCON_7828CA1491AE01400" ID="RINCON_7828CA1491AE01400:1058864410">"#,
        r#"<ZoneGroupMember UUID="RINCON_7828CA1491AE01400" Location="http://192.168.1.6:1400/xml/device_description.xml""#,
        r#" ZoneName="Kitchen" Icon="x-rincon-roomicon:kitchen" Configuration="1" SoftwareVersion="84.1-63110""#,
        r#" SWGen="2" MinCompatibleVersion="83.1-00000" LegacyCompatibleVersion="58.0-00000" BootSeq="42""#,
        r#" TVConfigurationError="0" HdmiCecAvailable="0" WirelessMode="0" WirelessLeafOnly="0""#,
        r#" ChannelFreq="2412" BehindWifiExtender="0" WifiEnabled="1" EthLink="0" Orientation="0""#,
        r#" RoomCalibrationState="4" SecureRegState="3" VoiceConfigState="0" MicEnabled="0""#,
        r#" AirPlayEnabled="1" IdleState="1" MoreInfo="TargetRoomName:Kitchen" SSLPort="1443" HHSSLPort="1843"/>"#,
        r#"</ZoneGroup>"#,
        r#"<ZoneGroup Coordinator="RINCON_F0F6C150935601400" ID="RINCON_F0F6C150935601400:2947118322">"#,
        r#"<ZoneGroupMember UUID="RINCON_F0F6C150935601400" Location="http://192.168.1.17:1400/xml/device_description.xml""#,
        r#" ZoneName="Sonos Move" Icon="x-rincon-roomicon:portable" Configuration="1" SoftwareVersion="84.1-63110""#,
        r#" SWGen="2" MinCompatibleVersion="83.1-00000" LegacyCompatibleVersion="58.0-00000" BootSeq="17""#,
        r#" TVConfigurationError="0" HdmiCecAvailable="0" WirelessMode="0" WirelessLeafOnly="0""#,
        r#" ChannelFreq="2412" BehindWifiExtender="0" WifiEnabled="1" EthLink="0" Orientation="0""#,
        r#" RoomCalibrationState="4" SecureRegState="3" VoiceConfigState="0" MicEnabled="1""#,
        r#" AirPlayEnabled="1" IdleState="1""#,
        r#" MoreInfo="TargetRoomName:Sonos Move,RawBattPct:100,BattPct:100,BattChg:CHARGING,BattTmp:25""#,
        r#" SSLPort="1443" HHSSLPort="1843"/>"#,
        r#"</ZoneGroup>"#,
        r#"</ZoneGroups><VanishedDevices></VanishedDevices></ZoneGroupState>"#,
    );

    /// The same household after the Move joined the Kitchen: one group of two,
    /// the Kitchen leading.
    const GROUPED: &str = concat!(
        r#"<ZoneGroupState><ZoneGroups>"#,
        r#"<ZoneGroup Coordinator="RINCON_7828CA1491AE01400" ID="RINCON_7828CA1491AE01400:1058864411">"#,
        r#"<ZoneGroupMember UUID="RINCON_7828CA1491AE01400" Location="http://192.168.1.6:1400/xml/device_description.xml""#,
        r#" ZoneName="Kitchen" Icon="x-rincon-roomicon:kitchen" Configuration="1" SoftwareVersion="84.1-63110""#,
        r#" BootSeq="42" AirPlayEnabled="1" IdleState="1" MoreInfo="TargetRoomName:Kitchen" SSLPort="1443" HHSSLPort="1843"/>"#,
        r#"<ZoneGroupMember UUID="RINCON_F0F6C150935601400" Location="http://192.168.1.17:1400/xml/device_description.xml""#,
        r#" ZoneName="Sonos Move" Icon="x-rincon-roomicon:portable" Configuration="1" SoftwareVersion="84.1-63110""#,
        r#" BootSeq="17" AirPlayEnabled="1" IdleState="1""#,
        r#" MoreInfo="TargetRoomName:Sonos Move,RawBattPct:97,BattPct:96,BattChg:NOT_CHARGING,BattTmp:26""#,
        r#" SSLPort="1443" HHSSLPort="1843"/>"#,
        r#"</ZoneGroup>"#,
        r#"</ZoneGroups><VanishedDevices></VanishedDevices></ZoneGroupState>"#,
    );

    /// The reply exactly as it comes off the wire: a SOAP body whose
    /// `ZoneGroupState` element holds the document escaped once.
    const SOAP_REPLY: &str = concat!(
        r#"<?xml version="1.0" encoding="utf-8"?>"#,
        r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">"#,
        r#"<s:Body><u:GetZoneGroupStateResponse xmlns:u="urn:schemas-upnp-org:service:ZoneGroupTopology:1">"#,
        r#"<ZoneGroupState>&lt;ZoneGroupState&gt;&lt;ZoneGroups&gt;"#,
        r#"&lt;ZoneGroup Coordinator=&quot;RINCON_7828CA1491AE01400&quot; ID=&quot;RINCON_7828CA1491AE01400:1058864410&quot;&gt;"#,
        r#"&lt;ZoneGroupMember UUID=&quot;RINCON_7828CA1491AE01400&quot;"#,
        r#" Location=&quot;http://192.168.1.6:1400/xml/device_description.xml&quot;"#,
        r#" ZoneName=&quot;Kitchen&quot; SoftwareVersion=&quot;84.1-63110&quot; AirPlayEnabled=&quot;1&quot;"#,
        r#" MoreInfo=&quot;TargetRoomName:Kitchen&quot;/&gt;"#,
        r#"&lt;/ZoneGroup&gt;"#,
        r#"&lt;ZoneGroup Coordinator=&quot;RINCON_F0F6C150935601400&quot; ID=&quot;RINCON_F0F6C150935601400:2947118322&quot;&gt;"#,
        r#"&lt;ZoneGroupMember UUID=&quot;RINCON_F0F6C150935601400&quot;"#,
        r#" Location=&quot;http://192.168.1.17:1400/xml/device_description.xml&quot;"#,
        r#" ZoneName=&quot;Sonos Move&quot; SoftwareVersion=&quot;84.1-63110&quot; AirPlayEnabled=&quot;1&quot;"#,
        r#" MoreInfo=&quot;RawBattPct:100,BattPct:100,BattChg:CHARGING,BattTmp:25&quot;/&gt;"#,
        r#"&lt;/ZoneGroup&gt;"#,
        r#"&lt;/ZoneGroups&gt;&lt;VanishedDevices&gt;&lt;/VanishedDevices&gt;&lt;/ZoneGroupState&gt;"#,
        r#"</ZoneGroupState></u:GetZoneGroupStateResponse></s:Body></s:Envelope>"#,
    );

    const KITCHEN: &str = "RINCON_7828CA1491AE01400";
    const MOVE: &str = "RINCON_F0F6C150935601400";

    #[test]
    fn an_ungrouped_household_is_two_groups_of_one() {
        let zones = parse(UNGROUPED);
        assert_eq!(zones.len(), 2);
        assert_eq!(zones[0].uuid, KITCHEN);
        assert_eq!(zones[0].name, "Kitchen");
        assert_eq!(zones[0].address, "192.168.1.6");
        assert_eq!(zones[1].uuid, MOVE);
        assert_eq!(zones[1].name, "Sonos Move");
        assert_eq!(zones[1].address, "192.168.1.17");
        assert!(zones.iter().all(Zone::is_coordinator));
    }

    /// The whole point of the module: a grouped member must name the speaker
    /// that plays for it, or every transport command goes to a speaker that
    /// accepts it and does nothing.
    #[test]
    fn a_grouped_member_reports_its_coordinator() {
        let zones = parse(GROUPED);
        assert_eq!(zones.len(), 2);
        let leader = &zones[0];
        let follower = &zones[1];
        assert_eq!(leader.uuid, KITCHEN);
        assert!(leader.is_coordinator());
        assert_eq!(follower.uuid, MOVE);
        assert_eq!(follower.coordinator, KITCHEN);
        assert!(!follower.is_coordinator());
    }

    #[test]
    fn a_transport_command_resolves_to_the_group_leader() {
        let zones = parse(GROUPED);
        assert_eq!(coordinator_of(&zones, MOVE).map(|zone| zone.uuid.as_str()), Some(KITCHEN));
        assert_eq!(coordinator_of(&zones, KITCHEN).map(|zone| zone.uuid.as_str()), Some(KITCHEN));
        assert_eq!(coordinator_of(&zones, "RINCON_NOBODY"), None);
    }

    #[test]
    fn the_move_reports_its_battery() {
        let zones = parse(UNGROUPED);
        let sonos_move = &zones[1];
        assert_eq!(sonos_move.battery_pct, Some(100));
        assert_eq!(sonos_move.battery_charging, Some(true));
    }

    /// `BattPct` and `RawBattPct` are different numbers and the raw one comes
    /// first in the string; reading a prefix match would report it instead.
    #[test]
    fn a_discharging_move_is_not_reported_as_charging() {
        let zones = parse(GROUPED);
        assert_eq!(zones[1].battery_pct, Some(96));
        assert_eq!(zones[1].battery_charging, Some(false));
    }

    #[test]
    fn a_mains_powered_speaker_reports_no_battery() {
        let zones = parse(UNGROUPED);
        assert_eq!(zones[0].battery_pct, None);
        assert_eq!(zones[0].battery_charging, None);
    }

    #[test]
    fn airplay_is_read_from_the_member() {
        assert!(parse(UNGROUPED).iter().all(|zone| zone.airplay));
        let without = r#"<ZoneGroupState><ZoneGroups><ZoneGroup Coordinator="A" ID="A:1">
            <ZoneGroupMember UUID="A" ZoneName="Old" AirPlayEnabled="0"/></ZoneGroup></ZoneGroups></ZoneGroupState>"#;
        assert!(!parse(without)[0].airplay);
    }

    /// The same document reaches the driver from the SOAP reply still escaped
    /// and from the event already decoded; one entry point must read both, or
    /// the half that is wrong silently reports an empty house.
    #[test]
    fn a_singly_escaped_document_is_unescaped_once() {
        let from_soap = parse(SOAP_REPLY);
        assert_eq!(from_soap.len(), 2);
        assert_eq!(from_soap[0].uuid, KITCHEN);
        assert_eq!(from_soap[0].address, "192.168.1.6");
        assert_eq!(from_soap[1].name, "Sonos Move");
        assert_eq!(from_soap[1].battery_pct, Some(100));
        assert!(from_soap.iter().all(Zone::is_coordinator));
    }

    #[test]
    fn a_decoded_document_is_not_unescaped_again() {
        // The name is escaped in the decoded document exactly as a literal
        // ampersand must be; a second pass would eat it.
        let document = r#"<ZoneGroupState><ZoneGroups><ZoneGroup Coordinator="A" ID="A:1">
            <ZoneGroupMember UUID="A" ZoneName="Ben &amp;amp; Jerry"/></ZoneGroup></ZoneGroups></ZoneGroupState>"#;
        assert_eq!(parse(document)[0].name, "Ben &amp; Jerry");
    }

    /// A speaker that has left the household is still described in full inside
    /// `<VanishedDevices>`; reporting it would leave a dead device on the page
    /// that no command can ever reach.
    #[test]
    fn a_vanished_device_is_not_a_speaker() {
        let document = concat!(
            r#"<ZoneGroupState><ZoneGroups>"#,
            r#"<ZoneGroup Coordinator="RINCON_7828CA1491AE01400" ID="RINCON_7828CA1491AE01400:1058864410">"#,
            r#"<ZoneGroupMember UUID="RINCON_7828CA1491AE01400" Location="http://192.168.1.6:1400/xml/device_description.xml" ZoneName="Kitchen"/>"#,
            r#"</ZoneGroup></ZoneGroups>"#,
            r#"<VanishedDevices>"#,
            r#"<Device UUID="RINCON_F0F6C150935601400" ZoneName="Sonos Move" Reason="powered off"/>"#,
            r#"<ZoneGroupMember UUID="RINCON_DEADBEEF01400" ZoneName="Guest Room"/>"#,
            r#"</VanishedDevices></ZoneGroupState>"#,
        );
        let zones = parse(document);
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].name, "Kitchen");
    }

    #[test]
    fn a_location_url_yields_its_host() {
        assert_eq!(
            host_of("http://192.168.1.6:1400/xml/device_description.xml").as_deref(),
            Some("192.168.1.6")
        );
        assert_eq!(host_of("http://192.168.1.17:1400").as_deref(), Some("192.168.1.17"));
        assert_eq!(host_of("http://kitchen.local/xml/x.xml").as_deref(), Some("kitchen.local"));
        assert_eq!(host_of("http://[fe80::1]:1400/x.xml").as_deref(), Some("[fe80::1]"));
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("http://"), None);
    }

    #[test]
    fn a_member_without_a_location_is_still_a_speaker() {
        let document = r#"<ZoneGroupState><ZoneGroups><ZoneGroup Coordinator="A" ID="A:1">
            <ZoneGroupMember UUID="A" ZoneName="Kitchen"/></ZoneGroup></ZoneGroups></ZoneGroupState>"#;
        let zones = parse(document);
        assert_eq!(zones.len(), 1);
        assert_eq!(zones[0].address, "");
    }

    #[test]
    fn a_malformed_document_is_empty_rather_than_a_panic() {
        assert!(parse("").is_empty());
        assert!(parse("not xml at all").is_empty());
        assert!(parse("<ZoneGroupState><ZoneGroups>").is_empty());
        assert!(parse("<ZoneGroupState><ZoneGroups><ZoneGroup Coordinator=").is_empty());
        assert!(parse("&lt;ZoneGroupState&gt;&lt;ZoneGroups&gt;").is_empty());
        // A group with no coordinator, and a member with no UUID: neither is
        // drivable, and neither may take the parse down with it.
        assert!(parse(r#"<ZoneGroups><ZoneGroup ID="A:1"><ZoneGroupMember UUID="A"/></ZoneGroup></ZoneGroups>"#).is_empty());
        assert!(parse(r#"<ZoneGroups><ZoneGroup Coordinator="A"><ZoneGroupMember ZoneName="x"/></ZoneGroup></ZoneGroups>"#).is_empty());
    }

    #[test]
    fn a_nonsense_battery_percentage_is_clamped() {
        let document = r#"<ZoneGroups><ZoneGroup Coordinator="A"><ZoneGroupMember UUID="A"
            MoreInfo="BattPct:900,BattChg:CHARGING"/></ZoneGroup></ZoneGroups>"#;
        assert_eq!(parse(document)[0].battery_pct, Some(100));
    }
}
