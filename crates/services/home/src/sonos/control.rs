//! Every action the Sonos driver performs, written down once.
//!
//! This module is the authority on which UPnP action, on which service, at
//! which path, means a given thing a person asked for — "play", "turn it down",
//! "put this speaker with that one". Nothing above it may build a [`Call`], and
//! nothing below it knows what a person wanted; that split is what keeps the
//! protocol's quirks in one file where they can be stated and tested rather
//! than rediscovered at each call site.
//!
//! The quirks are not incidental, and each of the following was measured
//! against the real players rather than taken from documentation:
//!
//! - **`InstanceID` is always `0`.** A Sonos player has exactly one transport
//!   and one rendering instance. Any other value is refused with UPnP error
//!   718, so the value is a constant here and is never a parameter.
//! - **`Play` carries a `Speed` of `"1"`**, as a string, and no other value is
//!   legal — there is no double-speed playback to expose.
//! - **Volume and mute are per-channel**, and the channel is always `Master`.
//! - **A relative volume step is one action, not three.** `SetRelativeVolume`
//!   is atomic and returns the resulting volume; read-modify-write across three
//!   round trips loses a step whenever two people press the button at once, or
//!   whenever the speaker's own app moves the volume in between.
//! - **Pause on live radio yields `STOPPED`, not `PAUSED_PLAYBACK`.** So the
//!   state a caller gets back is whatever the speaker says, never what the
//!   command implied it would be.
//!
//! One boundary is worth stating because getting it wrong is invisible until a
//! group exists: every function here talks to *the address it is given*, and
//! choosing that address is not its job. A transport command must be sent to
//! the group's coordinator, which the topology module works out; sending `Play`
//! to a grouped member is refused, or worse, silently does nothing. Volume, by
//! contrast, is genuinely per-speaker and goes to the member itself.

use crate::device::{Transport, clamp_percent};
use crate::soap::{self, Call, SoapError};

/// The transport service: play, pause, seek, queue, and group membership.
pub const AV_TRANSPORT: &str = "urn:schemas-upnp-org:service:AVTransport:1";

/// The rendering service: volume, mute, bass, treble — everything per-speaker.
pub const RENDERING_CONTROL: &str = "urn:schemas-upnp-org:service:RenderingControl:1";

/// The topology service: who is grouped with whom, for the whole household.
pub const ZONE_GROUP_TOPOLOGY: &str = "urn:schemas-upnp-org:service:ZoneGroupTopology:1";

/// Where [`AV_TRANSPORT`] is controlled. Under `MediaRenderer`, unlike topology.
pub const AV_TRANSPORT_PATH: &str = "/MediaRenderer/AVTransport/Control";

/// Where [`RENDERING_CONTROL`] is controlled.
pub const RENDERING_CONTROL_PATH: &str = "/MediaRenderer/RenderingControl/Control";

/// Where [`ZONE_GROUP_TOPOLOGY`] is controlled. Not under `MediaRenderer`: it
/// describes the household rather than this player's rendering.
pub const ZONE_GROUP_TOPOLOGY_PATH: &str = "/ZoneGroupTopology/Control";

/// The document a player serves describing itself, fetched by `GET` and chunked.
pub const DESCRIPTION_PATH: &str = "/xml/device_description.xml";

/// The only instance a Sonos player has.
///
/// A string because that is what goes on the wire, and a constant because it is
/// never a choice: any other value is answered with UPnP errorCode 718,
/// "invalid InstanceID", which is a fault a caller cannot recover from and so
/// must not be able to cause.
const INSTANCE: &str = "0";

/// The only channel a Sonos player renders on.
///
/// `GetVolume`, `SetVolume`, `GetMute` and `SetMute` all require a channel, and
/// `Master` is the one every model answers for.
const MASTER: &str = "Master";

/// The sentinel a player puts in a stream's title before the first audio.
///
/// It means "not playing yet", and showing it to a person would put the literal
/// text `ZPSTR_BUFFERING` where a song title belongs.
const BUFFERING: &str = "ZPSTR_BUFFERING";

/// The literal a player uses for a field it does not implement.
///
/// `GetPositionInfo` always answers `AbsTime` with it, and answers
/// `TrackDuration` with it on a live stream that has no end.
const NOT_IMPLEMENTED: &str = "NOT_IMPLEMENTED";

/// What is playing, and how far into it the player is.
///
/// Assembled from two documents at once: the out-arguments of
/// `GetPositionInfo`, and the DIDL-Lite metadata carried inside one of them.
/// They are merged here rather than returned separately because a caller wants
/// "what is on", and no caller wants to know that the title arrived nested one
/// level of escaping deeper than the duration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Position {
    /// Which track in the queue, one-based. `0` when nothing is loaded.
    pub track: u32,
    /// The track title, absent when the player is idle or still buffering.
    pub title: Option<String>,
    /// The artist — DIDL-Lite's `dc:creator`. Absent for most radio streams.
    pub artist: Option<String>,
    /// The album, when the source has one.
    pub album: Option<String>,
    /// A URL for the cover art, usually relative to the player's own address.
    pub art_uri: Option<String>,
    /// Track length in seconds. Absent on a live stream, which has no length.
    pub duration_secs: Option<u32>,
    /// How far in, in seconds. Absent when the player reports no relative time.
    pub position_secs: Option<u32>,
    /// The track's URI, which is also how the source is recognised — an
    /// `x-rincon:` URI means this player is following a coordinator.
    pub uri: Option<String>,
}

/// What the player has loaded, as distinct from which track of it is playing.
///
/// The useful field is [`uri`](Media::uri): a queue, a radio stream, and a
/// grouped player's `x-rincon:` follow-URI are told apart by it and by nothing
/// else in the protocol.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Media {
    /// How many tracks are loaded. `1` for a stream, `0` for nothing.
    pub tracks: u32,
    /// The length of the whole medium, when it has one.
    pub duration_secs: Option<u32>,
    /// The URI of what is loaded.
    pub uri: Option<String>,
    /// The name carried in the medium's own metadata — a station's name, say.
    pub title: Option<String>,
}

/// Starts or resumes playback.
///
/// `Speed` is `"1"` because that is the only value the player accepts; it is
/// not a rate this crate could ever expose.
pub async fn play(address: &str) -> Result<(), SoapError> {
    send(address, AV_TRANSPORT_PATH, &play_call()).await
}

/// Pauses playback.
///
/// The resulting state is *not* assumed: pausing a live radio stream leaves the
/// player `STOPPED`, so a caller that needs to know must ask
/// [`transport_info`].
pub async fn pause(address: &str) -> Result<(), SoapError> {
    send(address, AV_TRANSPORT_PATH, &instance_only(AV_TRANSPORT, "Pause")).await
}

/// Stops playback.
pub async fn stop(address: &str) -> Result<(), SoapError> {
    send(address, AV_TRANSPORT_PATH, &instance_only(AV_TRANSPORT, "Stop")).await
}

/// Skips to the next track.
///
/// Answers [`SoapError::Upnp`] with 701 when there is nothing to skip to — on a
/// radio stream, or at the end of a queue. That is a refusal, not a breakage.
pub async fn next(address: &str) -> Result<(), SoapError> {
    send(address, AV_TRANSPORT_PATH, &instance_only(AV_TRANSPORT, "Next")).await
}

/// Skips to the previous track. Refused with 701 in the same cases as [`next`].
pub async fn previous(address: &str) -> Result<(), SoapError> {
    send(address, AV_TRANSPORT_PATH, &instance_only(AV_TRANSPORT, "Previous")).await
}

/// Asks what the transport is doing.
pub async fn transport_info(address: &str) -> Result<Transport, SoapError> {
    let body = soap::call(address, AV_TRANSPORT_PATH, &instance_only(AV_TRANSPORT, "GetTransportInfo")).await?;
    parse_transport(&body)
}

/// Asks what is playing and how far into it the player is.
pub async fn position_info(address: &str) -> Result<Position, SoapError> {
    let body = soap::call(address, AV_TRANSPORT_PATH, &instance_only(AV_TRANSPORT, "GetPositionInfo")).await?;
    parse_position(&body)
}

/// Asks what medium is loaded — a queue, a stream, or another player to follow.
pub async fn media_info(address: &str) -> Result<Media, SoapError> {
    let body = soap::call(address, AV_TRANSPORT_PATH, &instance_only(AV_TRANSPORT, "GetMediaInfo")).await?;
    parse_media(&body)
}

/// Asks which transport actions are available right now.
///
/// The answer is what makes a page able to grey out a button instead of
/// offering it and being refused: an idle player answers just `Set`, and a
/// radio stream omits `Next`. Returned as owned words because the vocabulary is
/// the device's, not this crate's, and a value nobody here has seen must still
/// reach the caller intact.
pub async fn current_transport_actions(address: &str) -> Result<Vec<String>, SoapError> {
    let call = instance_only(AV_TRANSPORT, "GetCurrentTransportActions");
    let body = soap::call(address, AV_TRANSPORT_PATH, &call).await?;
    Ok(parse_actions(&field(&body, "Actions")?))
}

/// Reads this speaker's own volume, 0–100.
///
/// Per-speaker even when grouped: a group has no single volume, and reading one
/// member's is the only honest answer.
pub async fn volume(address: &str) -> Result<u8, SoapError> {
    let body = soap::call(address, RENDERING_CONTROL_PATH, &channel_call("GetVolume")).await?;
    percent(&body, "CurrentVolume")
}

/// Sets this speaker's volume.
///
/// Clamped through [`clamp_percent`] rather than trusted: the argument is a
/// `ui2` the player range-checks, and sending 255 earns a fault instead of a
/// loud speaker.
pub async fn set_volume(address: &str, level: u8) -> Result<(), SoapError> {
    send(address, RENDERING_CONTROL_PATH, &set_volume_call(level)).await
}

/// Moves the volume by `step` and answers where it ended up.
///
/// One action, deliberately. The obvious alternative — read, add, write — is
/// three round trips with a gap in the middle, and two people pressing "louder"
/// at the same moment lose a press. `SetRelativeVolume` is atomic in the
/// player and returns the resulting volume, so the answer is the truth rather
/// than what this end predicted.
pub async fn adjust_volume(address: &str, step: i16) -> Result<u8, SoapError> {
    let body = soap::call(address, RENDERING_CONTROL_PATH, &relative_volume_call(step)).await?;
    percent(&body, "NewVolume")
}

/// Reads whether this speaker is muted.
pub async fn muted(address: &str) -> Result<bool, SoapError> {
    let body = soap::call(address, RENDERING_CONTROL_PATH, &channel_call("GetMute")).await?;
    Ok(field(&body, "CurrentMute")?.trim() == "1")
}

/// Mutes or unmutes this speaker.
pub async fn set_muted(address: &str, muted: bool) -> Result<(), SoapError> {
    send(address, RENDERING_CONTROL_PATH, &set_mute_call(muted)).await
}

/// Puts the speaker at `address` into the group led by `coordinator_uuid`.
///
/// Joining is not its own action in the protocol: it is the joining player
/// being told to play the coordinator, by way of the `x-rincon:` scheme. The
/// command therefore goes to the *joining* player, never to the coordinator —
/// sending it the other way round would drag the coordinator into the joiner's
/// group instead.
pub async fn join(address: &str, coordinator_uuid: &str) -> Result<(), SoapError> {
    send(address, AV_TRANSPORT_PATH, &join_call(coordinator_uuid)).await
}

/// Takes the speaker at `address` out of its group, leaving it standalone.
///
/// The symmetric operation to [`join`], and it also goes to the player that is
/// moving. A coordinator that leaves its own group hands coordination to a
/// remaining member; the topology is re-read afterwards rather than predicted.
pub async fn leave(address: &str) -> Result<(), SoapError> {
    let call = instance_only(AV_TRANSPORT, "BecomeCoordinatorOfStandaloneGroup");
    send(address, AV_TRANSPORT_PATH, &call).await
}

/// Fetches the household's grouping as the raw `ZoneGroupState` document.
///
/// Raw on purpose: reading it belongs to the topology module, and returning a
/// parsed structure here would put the same knowledge in two places. Any player
/// answers for the *whole* household, so one call describes every group — which
/// is why a refresh asks one speaker and not all of them.
pub async fn zone_group_state(address: &str) -> Result<String, SoapError> {
    let call = Call { service: ZONE_GROUP_TOPOLOGY, action: "GetZoneGroupState", args: Vec::new() };
    let body = soap::call(address, ZONE_GROUP_TOPOLOGY_PATH, &call).await?;
    field(&body, "ZoneGroupState")
}

/// Asks a player to describe itself: `(room name, model, UUID)`.
///
/// The one call that needs no prior knowledge, which is what makes it the first
/// thing discovery does with a newly seen address. It is a plain `GET`, and its
/// answer is chunked rather than length-framed — the reason the transport
/// handles both framings.
pub async fn description(address: &str) -> Result<(String, String, String), SoapError> {
    let document = soap::get(address, DESCRIPTION_PATH).await?;
    parse_description(&document)
}

/// Builds a call carrying nothing but the instance.
///
/// Most of AVTransport is this shape, and writing it once means `InstanceID`
/// has one spelling and one value in the whole driver.
fn instance_only<'a>(service: &'a str, action: &'a str) -> Call<'a> {
    Call { service, action, args: vec![("InstanceID", INSTANCE.to_owned())] }
}

/// `Play`, whose `Speed` is the string `"1"` and can be nothing else.
fn play_call() -> Call<'static> {
    Call {
        service: AV_TRANSPORT,
        action: "Play",
        args: vec![("InstanceID", INSTANCE.to_owned()), ("Speed", "1".to_owned())],
    }
}

/// A RenderingControl read: the instance and the `Master` channel.
fn channel_call(action: &'static str) -> Call<'static> {
    Call {
        service: RENDERING_CONTROL,
        action,
        args: vec![("InstanceID", INSTANCE.to_owned()), ("Channel", MASTER.to_owned())],
    }
}

/// `SetVolume`, with the level clamped to the range the player accepts.
fn set_volume_call(level: u8) -> Call<'static> {
    let level = clamp_percent(i32::from(level));
    Call {
        service: RENDERING_CONTROL,
        action: "SetVolume",
        args: vec![
            ("InstanceID", INSTANCE.to_owned()),
            ("Channel", MASTER.to_owned()),
            ("DesiredVolume", level.to_string()),
        ],
    }
}

/// `SetMute`, whose boolean travels as `"0"` or `"1"` and not as `"false"`.
fn set_mute_call(muted: bool) -> Call<'static> {
    Call {
        service: RENDERING_CONTROL,
        action: "SetMute",
        args: vec![
            ("InstanceID", INSTANCE.to_owned()),
            ("Channel", MASTER.to_owned()),
            ("DesiredMute", if muted { "1" } else { "0" }.to_owned()),
        ],
    }
}

/// `SetRelativeVolume`, whose adjustment is signed and applied by the player.
fn relative_volume_call(step: i16) -> Call<'static> {
    Call {
        service: RENDERING_CONTROL,
        action: "SetRelativeVolume",
        args: vec![
            ("InstanceID", INSTANCE.to_owned()),
            ("Channel", MASTER.to_owned()),
            ("Adjustment", step.to_string()),
        ],
    }
}

/// `SetAVTransportURI` pointing at a coordinator, which is what joining is.
///
/// The metadata argument is present and empty: the action requires it, and
/// there is no metadata to give for a player that is about to mirror another.
fn join_call(coordinator_uuid: &str) -> Call<'static> {
    Call {
        service: AV_TRANSPORT,
        action: "SetAVTransportURI",
        args: vec![
            ("InstanceID", INSTANCE.to_owned()),
            ("CurrentURI", group_uri(coordinator_uuid)),
            ("CurrentURIMetaData", String::new()),
        ],
    }
}

/// The `x-rincon:` URI a player follows to be part of `coordinator_uuid`'s group.
///
/// Tolerates a UUID that arrives with the `uuid:` prefix the description
/// document uses, or one that is already a full follow-URI, because those are
/// the two shapes the same identifier reaches this crate in.
fn group_uri(coordinator_uuid: &str) -> String {
    let uuid = coordinator_uuid.trim();
    if uuid.starts_with("x-rincon:") {
        return uuid.to_owned();
    }
    format!("x-rincon:{}", uuid.strip_prefix("uuid:").unwrap_or(uuid))
}

/// Sends a call whose success is HTTP 200 and whose body says nothing.
///
/// Every setter answers with an empty response element, so discarding the body
/// is the whole of reading the answer — stated here once rather than looking
/// like an oversight at five call sites.
async fn send(address: &str, path: &str, call: &Call<'_>) -> Result<(), SoapError> {
    soap::call(address, path, call).await.map(|_| ())
}

/// One out-argument of a response, or a [`SoapError::Malformed`] naming it.
///
/// A missing out-argument is a malformed answer rather than a `None`: every
/// field this module asks for is one the action is specified to return, so its
/// absence means the reply was not the reply to this request.
fn field(body: &str, name: &str) -> Result<String, SoapError> {
    crate::xml::element(body, name)
        .ok_or_else(|| SoapError::Malformed(format!("the answer carried no <{name}>")))
}

/// An out-argument read as a percentage, clamped rather than range-checked.
fn percent(body: &str, name: &str) -> Result<u8, SoapError> {
    let text = field(body, name)?;
    let value: i32 = text
        .trim()
        .parse()
        .map_err(|_| SoapError::Malformed(format!("<{name}> was not a number: {text:?}")))?;
    Ok(clamp_percent(value))
}

/// Reads `CurrentTransportState` out of a `GetTransportInfo` answer.
fn parse_transport(body: &str) -> Result<Transport, SoapError> {
    Ok(Transport::from_upnp(field(body, "CurrentTransportState")?.trim()))
}

/// Reads a `GetPositionInfo` answer, metadata and all.
///
/// The metadata is a DIDL-Lite document that arrived escaped inside an element,
/// so it has been unescaped exactly once by the time it is read here — one
/// level, not the two a GENA event needs. Getting that count wrong is the
/// classic way this parse turns into nonsense, which is why it is stated.
fn parse_position(body: &str) -> Result<Position, SoapError> {
    let metadata = crate::xml::element(body, "TrackMetaData").unwrap_or_default();
    Ok(Position {
        track: field(body, "Track")?.trim().parse().unwrap_or(0),
        title: didl_field(&metadata, "title"),
        artist: didl_field(&metadata, "creator"),
        album: didl_field(&metadata, "album"),
        art_uri: didl_field(&metadata, "albumArtURI"),
        duration_secs: duration_secs(&field(body, "TrackDuration")?),
        position_secs: duration_secs(&field(body, "RelTime")?),
        uri: present(crate::xml::element(body, "TrackURI").unwrap_or_default()),
    })
}

/// Reads a `GetMediaInfo` answer.
fn parse_media(body: &str) -> Result<Media, SoapError> {
    let metadata = crate::xml::element(body, "CurrentURIMetaData").unwrap_or_default();
    Ok(Media {
        tracks: field(body, "NrTracks")?.trim().parse().unwrap_or(0),
        duration_secs: duration_secs(&field(body, "MediaDuration")?),
        uri: present(crate::xml::element(body, "CurrentURI").unwrap_or_default()),
        title: didl_field(&metadata, "title"),
    })
}

/// Splits the comma-separated capability word list a player answers with.
///
/// Whitespace is trimmed and empties dropped, so an idle player's bare `Set`
/// and a playing player's `Set, Play, Pause` both read as clean words.
fn parse_actions(list: &str) -> Vec<String> {
    list.split(',')
        .map(str::trim)
        .filter(|word| !word.is_empty())
        .map(str::to_owned)
        .collect()
}

/// Reads `(room name, model, UUID)` out of a device description document.
///
/// Public because discovery reaches the same document from an SSDP `LOCATION`
/// header without going through [`description`], and both must read it the same
/// way. The model is taken from `modelNumber` — the terse code (`S13`, `S17`)
/// that identifies the hardware — falling back to `modelName` for a player that
/// omits it. The `uuid:` prefix is stripped, because everywhere else in this
/// crate a player is its bare `RINCON_…`.
pub fn parse_description(document: &str) -> Result<(String, String, String), SoapError> {
    let room = crate::xml::element(document, "roomName")
        .ok_or_else(|| SoapError::Malformed("the description carried no <roomName>".to_owned()))?;
    let model = crate::xml::element(document, "modelNumber")
        .or_else(|| crate::xml::element(document, "modelName"))
        .unwrap_or_default();
    let udn = crate::xml::element(document, "UDN")
        .ok_or_else(|| SoapError::Malformed("the description carried no <UDN>".to_owned()))?;
    let uuid = udn.trim().strip_prefix("uuid:").unwrap_or(udn.trim()).to_owned();
    Ok((room.trim().to_owned(), model.trim().to_owned(), uuid))
}

/// The coordinator a follow-URI names, if it is one.
///
/// `x-rincon:RINCON_…` is how a grouped player says who it is following, and it
/// is the only place in the protocol where that fact appears in a transport
/// answer rather than in the topology document. Borrowed rather than owned
/// because the caller usually only compares it.
#[must_use]
pub fn rincon_coordinator(uri: &str) -> Option<&str> {
    uri.strip_prefix("x-rincon:").filter(|uuid| !uuid.is_empty())
}

/// A Sonos clock value (`H:MM:SS`, unpadded hours) as whole seconds.
///
/// Not ISO 8601 and not padded, so neither a duration crate nor a fixed-width
/// slice would read it. `NOT_IMPLEMENTED` and an empty value are `None` rather
/// than zero: a live stream has no length, and rendering that as `0:00` would
/// draw a progress bar that is permanently full.
#[must_use]
pub fn duration_secs(clock: &str) -> Option<u32> {
    let clock = clock.trim();
    if clock.is_empty() || clock == NOT_IMPLEMENTED {
        return None;
    }
    let mut seconds: u32 = 0;
    let mut parts = 0;
    for part in clock.split(':') {
        let value: u32 = part.trim().parse().ok()?;
        seconds = seconds.checked_mul(60)?.checked_add(value)?;
        parts += 1;
    }
    // Two parts (`MM:SS`) or three (`H:MM:SS`); anything else is not a clock.
    (parts == 2 || parts == 3).then_some(seconds)
}

/// A DIDL-Lite field, with the player's two "nothing here" spellings removed.
///
/// An empty string and the buffering sentinel both mean "no title yet", and
/// both would otherwise be shown to a person as though they were one.
fn didl_field(metadata: &str, name: &str) -> Option<String> {
    present(crate::xml::element(metadata, name)?)
}

/// `Some(text)` unless the text is empty or the buffering sentinel.
fn present(text: String) -> Option<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == BUFFERING {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::soap::envelope;

    /// A `GetPositionInfo` answer captured from the Kitchen speaker, verbatim,
    /// including the sentinels the player really sends: `NOT_IMPLEMENTED` for
    /// `AbsTime` and `2147483647` for the counters.
    const POSITION_INFO: &str = concat!(
        r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>"#,
        r#"<u:GetPositionInfoResponse xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">"#,
        r#"<Track>3</Track><TrackDuration>0:03:12</TrackDuration>"#,
        r#"<TrackMetaData>&lt;DIDL-Lite xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/"&gt;"#,
        r#"&lt;item id="-1" parentID="-1" restricted="true"&gt;&lt;dc:title&gt;Hopp&#237;polla&lt;/dc:title&gt;"#,
        r#"&lt;dc:creator&gt;Sigur R&#243;s&lt;/dc:creator&gt;&lt;upnp:album&gt;Takk...&lt;/upnp:album&gt;"#,
        r#"&lt;upnp:albumArtURI&gt;/getaa?u=x-sonos-http&amp;amp;flags=8&lt;/upnp:albumArtURI&gt;"#,
        r#"&lt;/item&gt;&lt;/DIDL-Lite&gt;</TrackMetaData>"#,
        r#"<TrackURI>x-sonos-http:librarytrack%3ai.3zPvpZQ.mp4</TrackURI>"#,
        r#"<RelTime>0:00:42</RelTime><AbsTime>NOT_IMPLEMENTED</AbsTime>"#,
        r#"<RelCount>2147483647</RelCount><AbsCount>2147483647</AbsCount>"#,
        r#"</u:GetPositionInfoResponse></s:Body></s:Envelope>"#,
    );

    /// The same call answered by a player that is idle: every field present,
    /// every field empty. An idle player is not an error and must not read as
    /// one.
    const POSITION_INFO_IDLE: &str = concat!(
        r#"<s:Envelope><s:Body><u:GetPositionInfoResponse xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">"#,
        r#"<Track>0</Track><TrackDuration>0:00:00</TrackDuration><TrackMetaData></TrackMetaData>"#,
        r#"<TrackURI></TrackURI><RelTime>NOT_IMPLEMENTED</RelTime><AbsTime>NOT_IMPLEMENTED</AbsTime>"#,
        r#"<RelCount>2147483647</RelCount><AbsCount>2147483647</AbsCount>"#,
        r#"</u:GetPositionInfoResponse></s:Body></s:Envelope>"#,
    );

    /// A live radio stream: no duration, and the buffering sentinel where a
    /// title will later be.
    const POSITION_INFO_RADIO: &str = concat!(
        r#"<s:Envelope><s:Body><u:GetPositionInfoResponse xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">"#,
        r#"<Track>1</Track><TrackDuration>NOT_IMPLEMENTED</TrackDuration>"#,
        r#"<TrackMetaData>&lt;DIDL-Lite&gt;&lt;item&gt;&lt;dc:title&gt;ZPSTR_BUFFERING&lt;/dc:title&gt;&lt;/item&gt;&lt;/DIDL-Lite&gt;</TrackMetaData>"#,
        r#"<TrackURI>x-sonosapi-stream:s24939?sid=254</TrackURI>"#,
        r#"<RelTime>0:01:07</RelTime><AbsTime>NOT_IMPLEMENTED</AbsTime>"#,
        r#"</u:GetPositionInfoResponse></s:Body></s:Envelope>"#,
    );

    /// The description document the Kitchen Sonos One serves, trimmed to the
    /// three fields this module reads plus the neighbours that could be
    /// mistaken for them.
    const DESCRIPTION: &str = concat!(
        r#"<?xml version="1.0" encoding="utf-8" ?><root xmlns="urn:schemas-upnp-org:device-1-0">"#,
        r#"<specVersion><major>1</major><minor>0</minor></specVersion><device>"#,
        r#"<deviceType>urn:schemas-upnp-org:device:ZonePlayer:1</deviceType>"#,
        r#"<friendlyName>192.168.1.6 - Sonos One</friendlyName>"#,
        r#"<manufacturer>Sonos, Inc.</manufacturer><modelNumber>S13</modelNumber>"#,
        r#"<modelDescription>Sonos One</modelDescription><modelName>Sonos One</modelName>"#,
        r#"<softwareVersion>84.1-63110</softwareVersion>"#,
        r#"<UDN>uuid:RINCON_7828CA1491AE01400</UDN><roomName>Kitchen</roomName>"#,
        r#"</device></root>"#,
    );

    #[test]
    fn play_sends_the_only_speed_the_player_accepts() {
        assert_eq!(
            envelope(&play_call()),
            concat!(
                r#"<?xml version="1.0" encoding="utf-8"?>"#,
                r#"<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" "#,
                r#"s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">"#,
                r#"<s:Body><u:Play xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">"#,
                r#"<InstanceID>0</InstanceID><Speed>1</Speed></u:Play></s:Body></s:Envelope>"#,
            )
        );
    }

    /// Every AVTransport action but `Play` and `SetAVTransportURI` carries the
    /// instance alone, and the instance is always zero — anything else is
    /// answered with errorCode 718.
    #[test]
    fn a_transport_command_carries_only_instance_zero() {
        for action in ["Pause", "Stop", "Next", "Previous", "BecomeCoordinatorOfStandaloneGroup"] {
            let body = envelope(&instance_only(AV_TRANSPORT, action));
            assert!(body.contains(&format!(r#"<u:{action} xmlns:u="{AV_TRANSPORT}"><InstanceID>0</InstanceID></u:{action}>"#)));
        }
    }

    #[test]
    fn a_volume_read_names_the_master_channel() {
        let body = envelope(&channel_call("GetVolume"));
        assert!(body.contains("<InstanceID>0</InstanceID><Channel>Master</Channel>"));
        assert_eq!(
            soap::soap_action(&channel_call("GetMute")),
            "\"urn:schemas-upnp-org:service:RenderingControl:1#GetMute\""
        );
    }

    #[test]
    fn a_volume_set_carries_instance_channel_and_level_in_that_order() {
        let body = envelope(&set_volume_call(9));
        assert!(body.contains("<InstanceID>0</InstanceID><Channel>Master</Channel><DesiredVolume>9</DesiredVolume>"));
    }

    /// A volume above the range is clamped here rather than sent and refused:
    /// the player range-checks `DesiredVolume` and answers a fault, which would
    /// reach a person as a failed button press.
    #[test]
    fn a_volume_out_of_range_is_clamped_before_it_is_sent() {
        assert!(envelope(&set_volume_call(255)).contains("<DesiredVolume>100</DesiredVolume>"));
    }

    #[test]
    fn mute_travels_as_one_and_zero() {
        assert!(envelope(&set_mute_call(true)).contains("<DesiredMute>1</DesiredMute>"));
        assert!(envelope(&set_mute_call(false)).contains("<DesiredMute>0</DesiredMute>"));
    }

    /// A relative step must be one signed adjustment, not a read followed by a
    /// write: the whole point of `SetRelativeVolume` is that no other change can
    /// land in the gap.
    #[test]
    fn a_relative_step_is_a_single_signed_adjustment() {
        assert!(envelope(&relative_volume_call(-5)).contains("<Adjustment>-5</Adjustment>"));
        assert!(envelope(&relative_volume_call(5)).contains("<Adjustment>5</Adjustment>"));
    }

    #[test]
    fn joining_points_the_player_at_a_coordinator_with_empty_metadata() {
        let body = envelope(&join_call("RINCON_F0F6C150935601400"));
        assert!(body.contains(concat!(
            "<InstanceID>0</InstanceID>",
            "<CurrentURI>x-rincon:RINCON_F0F6C150935601400</CurrentURI>",
            "<CurrentURIMetaData></CurrentURIMetaData>",
        )));
    }

    /// The same speaker's identifier arrives with a `uuid:` prefix from its
    /// description document and without one from the topology document; both
    /// must produce the same follow-URI.
    #[test]
    fn a_coordinator_uuid_is_accepted_in_either_spelling() {
        assert_eq!(group_uri("RINCON_A"), "x-rincon:RINCON_A");
        assert_eq!(group_uri("uuid:RINCON_A"), "x-rincon:RINCON_A");
        assert_eq!(group_uri(" x-rincon:RINCON_A "), "x-rincon:RINCON_A");
    }

    /// The topology action takes no arguments at all, which the transport
    /// renders as a self-closing body element.
    #[test]
    fn the_topology_request_has_no_arguments() {
        let call = Call { service: ZONE_GROUP_TOPOLOGY, action: "GetZoneGroupState", args: Vec::new() };
        assert!(envelope(&call).contains(&format!(r#"<u:GetZoneGroupState xmlns:u="{ZONE_GROUP_TOPOLOGY}"/>"#)));
    }

    #[test]
    fn a_transport_state_is_read_from_a_captured_answer() {
        let body = concat!(
            r#"<s:Envelope><s:Body><u:GetTransportInfoResponse xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">"#,
            r#"<CurrentTransportState>PAUSED_PLAYBACK</CurrentTransportState>"#,
            r#"<CurrentTransportStatus>OK</CurrentTransportStatus><CurrentSpeed>1</CurrentSpeed>"#,
            r#"</u:GetTransportInfoResponse></s:Body></s:Envelope>"#,
        );
        assert_eq!(parse_transport(body).unwrap(), Transport::Paused);
    }

    /// The captured answer, read whole: the title and artist come from the
    /// DIDL-Lite nested inside `TrackMetaData`, and the clock values are
    /// unpadded `H:MM:SS` rather than ISO 8601.
    #[test]
    fn a_captured_position_answer_yields_title_artist_and_clock() {
        let position = parse_position(POSITION_INFO).unwrap();
        assert_eq!(position.track, 3);
        assert_eq!(position.title.as_deref(), Some("Hoppípolla"));
        assert_eq!(position.artist.as_deref(), Some("Sigur Rós"));
        assert_eq!(position.album.as_deref(), Some("Takk..."));
        assert_eq!(position.art_uri.as_deref(), Some("/getaa?u=x-sonos-http&flags=8"));
        assert_eq!(position.duration_secs, Some(192));
        assert_eq!(position.position_secs, Some(42));
        assert_eq!(position.uri.as_deref(), Some("x-sonos-http:librarytrack%3ai.3zPvpZQ.mp4"));
    }

    /// An idle player answers every field, all of them empty. None of that is a
    /// failure, and none of it may reach the page as a track called "".
    #[test]
    fn an_idle_player_reads_as_nothing_playing_rather_than_an_error() {
        let position = parse_position(POSITION_INFO_IDLE).unwrap();
        assert_eq!(position.track, 0);
        assert_eq!(position.title, None);
        assert_eq!(position.uri, None);
        assert_eq!(position.position_secs, None);
    }

    /// Radio: no duration at all, and the buffering sentinel standing where the
    /// title will be. Showing `ZPSTR_BUFFERING` as a song title is the bug this
    /// guards.
    #[test]
    fn a_buffering_radio_stream_has_no_title_and_no_duration() {
        let position = parse_position(POSITION_INFO_RADIO).unwrap();
        assert_eq!(position.title, None);
        assert_eq!(position.duration_secs, None);
        assert_eq!(position.position_secs, Some(67));
        assert_eq!(position.uri.as_deref(), Some("x-sonosapi-stream:s24939?sid=254"));
    }

    /// A grouped member's medium is the coordinator it follows, and that URI is
    /// the only place a transport answer says so.
    #[test]
    fn a_grouped_member_reports_the_coordinator_it_follows() {
        let body = concat!(
            r#"<s:Envelope><s:Body><u:GetMediaInfoResponse xmlns:u="urn:schemas-upnp-org:service:AVTransport:1">"#,
            r#"<NrTracks>1</NrTracks><MediaDuration>NOT_IMPLEMENTED</MediaDuration>"#,
            r#"<CurrentURI>x-rincon:RINCON_7828CA1491AE01400</CurrentURI>"#,
            r#"<CurrentURIMetaData></CurrentURIMetaData><NextURI></NextURI>"#,
            r#"<PlayMedium>NETWORK</PlayMedium><RecordMedium>NOT_IMPLEMENTED</RecordMedium>"#,
            r#"</u:GetMediaInfoResponse></s:Body></s:Envelope>"#,
        );
        let media = parse_media(body).unwrap();
        assert_eq!(media.tracks, 1);
        assert_eq!(media.duration_secs, None);
        assert_eq!(
            media.uri.as_deref().and_then(rincon_coordinator),
            Some("RINCON_7828CA1491AE01400")
        );
        assert_eq!(rincon_coordinator("x-sonosapi-stream:s24939?sid=254"), None);
    }

    /// An idle player's available actions are the single word `Set` — the case
    /// that would break a naive split into a vector holding one empty string.
    #[test]
    fn an_idle_player_offers_only_set() {
        assert_eq!(parse_actions("Set"), ["Set"]);
        assert_eq!(parse_actions("Set, Play, Pause, Stop, Next, Previous"), [
            "Set", "Play", "Pause", "Stop", "Next", "Previous"
        ]);
        assert!(parse_actions("").is_empty());
    }

    #[test]
    fn a_clock_value_is_read_as_seconds() {
        assert_eq!(duration_secs("0:03:12"), Some(192));
        assert_eq!(duration_secs("1:00:00"), Some(3600));
        assert_eq!(duration_secs("10:30"), Some(630));
    }

    /// A stream has no length, and `NOT_IMPLEMENTED` must not become zero: a
    /// zero duration draws a progress bar that is permanently complete.
    #[test]
    fn an_absent_duration_is_none_and_not_zero() {
        assert_eq!(duration_secs("NOT_IMPLEMENTED"), None);
        assert_eq!(duration_secs(""), None);
        assert_eq!(duration_secs("0:00:00"), Some(0));
        assert_eq!(duration_secs("not a clock"), None);
    }

    #[test]
    fn a_description_yields_room_model_and_bare_uuid() {
        let (room, model, uuid) = parse_description(DESCRIPTION).unwrap();
        assert_eq!(room, "Kitchen");
        assert_eq!(model, "S13");
        assert_eq!(uuid, "RINCON_7828CA1491AE01400");
    }

    #[test]
    fn a_description_without_a_room_is_malformed_rather_than_blank() {
        assert!(matches!(parse_description("<root><device/></root>"), Err(SoapError::Malformed(_))));
    }

    /// A missing out-argument means the answer was not the answer to this
    /// request, so it is reported rather than defaulted.
    #[test]
    fn a_missing_out_argument_is_malformed() {
        let body = r#"<s:Envelope><s:Body><u:GetVolumeResponse/></s:Body></s:Envelope>"#;
        assert!(matches!(percent(body, "CurrentVolume"), Err(SoapError::Malformed(_))));
    }

    #[test]
    fn a_volume_answer_is_read_as_a_percentage() {
        let body = concat!(
            r#"<s:Envelope><s:Body><u:GetVolumeResponse xmlns:u="urn:schemas-upnp-org:service:RenderingControl:1">"#,
            r#"<CurrentVolume>9</CurrentVolume></u:GetVolumeResponse></s:Body></s:Envelope>"#,
        );
        assert_eq!(percent(body, "CurrentVolume").unwrap(), 9);
    }

    #[test]
    fn a_mute_answer_is_one_or_zero() {
        let muted = r#"<s:Body><u:GetMuteResponse><CurrentMute>1</CurrentMute></u:GetMuteResponse></s:Body>"#;
        let unmuted = r#"<s:Body><u:GetMuteResponse><CurrentMute>0</CurrentMute></u:GetMuteResponse></s:Body>"#;
        assert!(field(muted, "CurrentMute").unwrap().trim() == "1");
        assert!(field(unmuted, "CurrentMute").unwrap().trim() != "1");
    }

    /// The topology answer is singly escaped, so one unescape by
    /// [`crate::xml::element`] is the whole of the decoding — the document that
    /// comes back must be usable text, not an escaped blob.
    #[test]
    fn the_topology_answer_unescapes_once_into_a_document() {
        let body = concat!(
            r#"<s:Envelope><s:Body><u:GetZoneGroupStateResponse xmlns:u="urn:schemas-upnp-org:service:ZoneGroupTopology:1">"#,
            r#"<ZoneGroupState>&lt;ZoneGroupState&gt;&lt;ZoneGroups&gt;&lt;ZoneGroup Coordinator="RINCON_A" ID="RINCON_A:1058864410"&gt;"#,
            r#"&lt;ZoneGroupMember UUID="RINCON_A" ZoneName="Kitchen"/&gt;&lt;/ZoneGroup&gt;&lt;/ZoneGroups&gt;&lt;/ZoneGroupState&gt;</ZoneGroupState>"#,
            r#"</u:GetZoneGroupStateResponse></s:Body></s:Envelope>"#,
        );
        let state = field(body, "ZoneGroupState").unwrap();
        assert!(state.starts_with("<ZoneGroupState><ZoneGroups><ZoneGroup Coordinator=\"RINCON_A\""));
        assert_eq!(crate::xml::elements(&state, "ZoneGroupMember").len(), 1);
    }
}
