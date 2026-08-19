//! What a speaker just told us changed, and nothing more than that.
//!
//! A Sonos player pushes state at us through GENA: on subscribing it sends one
//! notification carrying everything it knows, and from then on it sends only
//! what actually changed. This module is the authority on turning either of
//! those bodies into a [`Delta`] — a set of `Option` fields where `None` means
//! *the speaker did not mention it*, not *it is empty*. That distinction is the
//! whole design. The obvious alternative, parsing an event into a full state
//! and storing that, is wrong in a way that looks fine in testing: the first
//! volume change after a track starts would arrive as a body naming only
//! `Volume`, and storing it whole would wipe the title off the page.
//!
//! The second thing this module exists to get right is the escaping, which is
//! the likeliest bug in the entire driver. `LastChange` is escaped **twice**.
//! Its text unescapes once into an `<Event>` document whose values live in
//! `val` attributes; the `val` of `CurrentTrackMetaData` is itself an escaped
//! DIDL-Lite document and must be unescaped **again** before a title can be
//! read out of it. Doing one pass where two are needed does not fail loudly —
//! it yields a document full of `&lt;dc:title&gt;` that no element lookup
//! matches, so the track silently never appears. The [`crate::xml`] primitives
//! each unescape exactly one level for this reason, and the code below spends
//! them deliberately: [`crate::xml::element`] on `LastChange` is the first,
//! [`crate::xml::attr`] on `val` is the second, and
//! [`crate::xml::element`] on `dc:title` is the third, which is the title's own
//! escaping.
//!
//! Two smaller traps, both measured on real hardware, are handled here rather
//! than left to callers. A `RenderingControl` event reports `Volume` and `Mute`
//! once per channel, and the `LF`/`RF` channels are hard-wired to 100 and 0 on
//! a stereo player — reading the last one seen would peg every speaker in the
//! house at full volume. And `r:streamContent` holds the sentinel
//! `ZPSTR_BUFFERING` while a radio stream is still connecting, which is not a
//! song title and must never be shown as one.
//!
//! Nothing here does I/O and nothing here fails: an unparseable body is a
//! [`Delta`] that changes nothing, because a firmware that starts sending
//! something unfamiliar should cost the house a stale field, not a crash in
//! the event listener.

use crate::device::{clamp_percent, Transport};
use crate::xml;

/// Everything one notification said changed, and nothing it did not say.
///
/// Every field is an `Option` because a `SEQ > 0` notification names only what
/// moved. A caller merges this onto the state it already holds — `Some`
/// overwrites, `None` leaves alone — which is the only merge that survives the
/// stream of partial events a speaker actually sends.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Delta {
    /// The new transport state, from `TransportState`. Note that pausing a
    /// live radio stream reports `STOPPED` rather than `PAUSED_PLAYBACK`;
    /// that is the speaker's truth and is carried through unchanged.
    pub transport: Option<Transport>,
    /// The new volume of the `Master` channel only, 0–100.
    pub volume: Option<u8>,
    /// The new mute state of the `Master` channel only.
    pub muted: Option<bool>,
    /// `dc:title` from the track's DIDL-Lite metadata.
    pub title: Option<String>,
    /// `dc:creator` from the track's DIDL-Lite metadata — the artist, under
    /// the name UPnP gives it.
    pub artist: Option<String>,
    /// `upnp:album` from the track's DIDL-Lite metadata.
    pub album: Option<String>,
    /// `CurrentTrackURI`, which is the only field that tells a queued track
    /// apart from a radio stream (`x-rincon-mp3radio:`, `x-sonosapi-stream:`)
    /// or a group member following its coordinator (`x-rincon:`).
    pub track_uri: Option<String>,
    /// `CurrentTrackDuration` in whole seconds. `None` for a live stream,
    /// whose duration the speaker reports as a sentinel rather than a number —
    /// see [`parse_duration`].
    pub duration_secs: Option<u32>,
    /// `r:streamContent`, raw, with the `ZPSTR_BUFFERING` sentinel removed.
    ///
    /// For a radio stream this is conventionally `Artist - Title` in one
    /// string, but only conventionally — plenty of stations put the station
    /// name here, or nothing. It is exposed unsplit so the caller can decide
    /// whether to trust it; splitting on the first dash here would silently
    /// mangle a track called `Sunday 8 - 12`.
    pub stream_content: Option<String>,
}

impl Delta {
    /// Whether this notification changed nothing this crate models.
    ///
    /// True for the many events that carry only fields the driver ignores —
    /// `Bass`, `Treble`, `Loudness`, `SubGain` — and for a body that could not
    /// be parsed. A caller can use it to skip waking the rest of the house.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Delta::default()
    }
}

/// The state change described by a GENA `NOTIFY` body.
///
/// Reads both evented namespaces — `AVT` (transport, track, metadata) and
/// `RCS` (volume, mute) — with one function, because the two arrive on the
/// same listener through the same `LastChange` wrapper and nothing about the
/// extraction differs. Telling them apart would mean trusting the `xmlns`,
/// which buys a way to be wrong and no accuracy: a body simply does not
/// contain the other namespace's fields.
#[must_use]
pub fn parse_last_change(body: &str) -> Delta {
    let mut delta = Delta::default();

    // Unescape #1: the text of <LastChange> *is* an escaped <Event> document.
    let Some(event) = xml::element(body, "LastChange") else {
        return delta;
    };

    if let Some(state) = value(&event, "TransportState") {
        delta.transport = Some(Transport::from_upnp(&state));
    }
    delta.volume = master(&event, "Volume")
        .and_then(|volume| volume.parse::<i32>().ok())
        .map(clamp_percent);
    delta.muted = master(&event, "Mute").and_then(|mute| flag(&mute));
    delta.track_uri = value(&event, "CurrentTrackURI").filter(|uri| !uri.is_empty());
    delta.duration_secs = value(&event, "CurrentTrackDuration")
        .as_deref()
        .and_then(parse_duration);
    delta.stream_content = value(&event, "streamContent")
        .filter(|content| !content.is_empty() && content != BUFFERING);

    // Unescape #2: the val of CurrentTrackMetaData is an escaped DIDL-Lite
    // document. Its own element text is unescaped a third time by `element`,
    // which is the title's escaping and not the event's.
    if let Some(didl) = value(&event, "CurrentTrackMetaData") {
        delta.title = text(&didl, "title");
        delta.artist = text(&didl, "creator");
        delta.album = text(&didl, "album");
    }

    delta
}

/// A UPnP duration, `H:MM:SS` with unpadded hours, as whole seconds.
///
/// Sonos does not send ISO 8601 here and does not zero-pad the hour, so
/// `0:03:12` is three minutes twelve. It also answers `NOT_IMPLEMENTED` for a
/// position it cannot report and for the duration of a live stream, which is
/// why this returns an `Option` rather than defaulting to zero: a stream of
/// unknown length and a track of length zero look identical downstream, and a
/// progress bar drawn from the wrong one sits at 100 %. `0:00:00` is a real
/// zero and stays `Some(0)`.
#[must_use]
pub fn parse_duration(text: &str) -> Option<u32> {
    let text = text.trim();
    let fields: Vec<&str> = text.split(':').collect();
    if fields.len() < 2 || fields.len() > 3 {
        return None;
    }
    let mut seconds: u32 = 0;
    for (index, field) in fields.iter().enumerate() {
        // The seconds field occasionally carries a fraction; the house shows
        // whole seconds, and a decimal point must not make the whole duration
        // unreadable.
        let field = if index + 1 == fields.len() {
            field.split_once('.').map_or(*field, |(whole, _)| whole)
        } else {
            *field
        };
        let part: u32 = field.trim().parse().ok()?;
        seconds = seconds.checked_mul(60)?.checked_add(part)?;
    }
    Some(seconds)
}

/// The sentinel a speaker puts in `r:streamContent` between being told to play
/// a stream and the stream arriving. It is a state, not a title.
const BUFFERING: &str = "ZPSTR_BUFFERING";

/// The `val` attribute of the first `<name>` element in a decoded event.
///
/// Inside an `<Event>` every value is an attribute and never element text, so
/// there is one way to read all of them.
fn value(event: &str, name: &str) -> Option<String> {
    xml::elements(event, name)
        .into_iter()
        .next()
        .and_then(|found| xml::attr(found.attrs, "val"))
}

/// The `val` of the `Master` channel's `<name>` element.
///
/// Strictly `Master`: an element with no channel at all is ignored too. On a
/// stereo pair `LF` and `RF` report a fixed 100 and 0, and accepting either of
/// them — by reading the first element, or the last — replaces the speaker's
/// real volume with a constant.
fn master(event: &str, name: &str) -> Option<String> {
    xml::elements(event, name)
        .into_iter()
        .find(|found| xml::attr(found.attrs, "channel").as_deref() == Some("Master"))
        .and_then(|found| xml::attr(found.attrs, "val"))
}

/// A UPnP boolean, which is `1` or `0` on the wire.
///
/// `true`/`false` are accepted because some Sonos services emit them, and
/// anything else is `None` rather than `false`, so an unfamiliar value leaves
/// the last known mute state alone instead of silently unmuting the house.
fn flag(value: &str) -> Option<bool> {
    match value.trim() {
        "1" | "true" | "True" => Some(true),
        "0" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// One DIDL-Lite field, empty treated as absent.
///
/// A speaker with nothing playing sends `<dc:title></dc:title>` rather than
/// omitting it, and an empty string here would overwrite a good title with a
/// blank the instant a stream rebuffers.
fn text(didl: &str, name: &str) -> Option<String> {
    xml::element(didl, name).filter(|found| !found.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `SEQ 0` `RenderingControl` notification, which arrives immediately
    /// on subscribing and carries the full rendering state. `Master` is the
    /// real volume; `LF` and `RF` are the fixed values that must be ignored.
    const RENDERING_SEQ_0: &str = concat!(
        r#"<e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0"><e:property><LastChange>"#,
        r#"&lt;Event xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/RCS/&quot;&gt;"#,
        r#"&lt;InstanceID val=&quot;0&quot;&gt;"#,
        r#"&lt;Volume channel=&quot;Master&quot; val=&quot;10&quot;/&gt;"#,
        r#"&lt;Volume channel=&quot;LF&quot; val=&quot;100&quot;/&gt;"#,
        r#"&lt;Volume channel=&quot;RF&quot; val=&quot;100&quot;/&gt;"#,
        r#"&lt;Mute channel=&quot;Master&quot; val=&quot;0&quot;/&gt;"#,
        r#"&lt;Mute channel=&quot;LF&quot; val=&quot;0&quot;/&gt;"#,
        r#"&lt;Mute channel=&quot;RF&quot; val=&quot;0&quot;/&gt;"#,
        r#"&lt;Bass val=&quot;0&quot;/&gt;&lt;Treble val=&quot;0&quot;/&gt;"#,
        r#"&lt;Loudness channel=&quot;Master&quot; val=&quot;1&quot;/&gt;"#,
        r#"&lt;OutputFixed val=&quot;0&quot;/&gt;&lt;HeadphoneConnected val=&quot;0&quot;/&gt;"#,
        r#"&lt;/InstanceID&gt;&lt;/Event&gt;"#,
        r#"</LastChange></e:property></e:propertyset>"#,
    );

    /// An `AVTransport` notification for a playing track, with the doubly
    /// escaped DIDL-Lite in `CurrentTrackMetaData` exactly as it arrives.
    const AVTRANSPORT_PLAYING: &str = concat!(
        r#"<e:propertyset xmlns:e="urn:schemas-upnp-org:event-1-0"><e:property><LastChange>"#,
        r#"&lt;Event xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/AVT/&quot;"#,
        r#" xmlns:r=&quot;urn:schemas-rinconnetworks-com:metadata-1-0/&quot;&gt;"#,
        r#"&lt;InstanceID val=&quot;0&quot;&gt;"#,
        r#"&lt;TransportState val=&quot;PLAYING&quot;/&gt;"#,
        r#"&lt;CurrentPlayMode val=&quot;NORMAL&quot;/&gt;"#,
        r#"&lt;NumberOfTracks val=&quot;12&quot;/&gt;&lt;CurrentTrack val=&quot;3&quot;/&gt;"#,
        r#"&lt;CurrentTrackDuration val=&quot;0:03:12&quot;/&gt;"#,
        r#"&lt;CurrentTrackURI val=&quot;x-sonos-http:track%3a42.mp4?sid=204&quot;/&gt;"#,
        r#"&lt;CurrentTrackMetaData val=&quot;"#,
        r#"&amp;lt;DIDL-Lite xmlns:dc=&amp;quot;http://purl.org/dc/elements/1.1/&amp;quot;"#,
        r#" xmlns:upnp=&amp;quot;urn:schemas-upnp-org:metadata-1-0/upnp/&amp;quot;"#,
        r#" xmlns:r=&amp;quot;urn:schemas-rinconnetworks-com:metadata-1-0/&amp;quot;"#,
        r#" xmlns=&amp;quot;urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/&amp;quot;&amp;gt;"#,
        r#"&amp;lt;item id=&amp;quot;-1&amp;quot; parentID=&amp;quot;-1&amp;quot; restricted=&amp;quot;true&amp;quot;&amp;gt;"#,
        r#"&amp;lt;res protocolInfo=&amp;quot;sonos.com-http:*:audio/mp4:*&amp;quot; duration=&amp;quot;0:03:12&amp;quot;&amp;gt;"#,
        r#"x-sonos-http:track%3a42.mp4&amp;lt;/res&amp;gt;"#,
        r#"&amp;lt;upnp:albumArtURI&amp;gt;/getaa?u=track42&amp;lt;/upnp:albumArtURI&amp;gt;"#,
        r#"&amp;lt;dc:title&amp;gt;Hoppípolla&amp;lt;/dc:title&amp;gt;"#,
        r#"&amp;lt;upnp:class&amp;gt;object.item.audioItem.musicTrack&amp;lt;/upnp:class&amp;gt;"#,
        r#"&amp;lt;dc:creator&amp;gt;Sigur Rós&amp;lt;/dc:creator&amp;gt;"#,
        r#"&amp;lt;upnp:album&amp;gt;Takk...&amp;lt;/upnp:album&amp;gt;"#,
        r#"&amp;lt;/item&amp;gt;&amp;lt;/DIDL-Lite&amp;gt;"#,
        r#"&quot;/&gt;"#,
        r#"&lt;r:streamContent val=&quot;&quot;/&gt;"#,
        r#"&lt;TransportStatus val=&quot;OK&quot;/&gt;"#,
        r#"&lt;/InstanceID&gt;&lt;/Event&gt;"#,
        r#"</LastChange></e:property></e:propertyset>"#,
    );

    #[test]
    fn the_seq_zero_rendering_body_yields_the_master_volume() {
        let delta = parse_last_change(RENDERING_SEQ_0);
        assert_eq!(delta.volume, Some(10));
        assert_eq!(delta.muted, Some(false));
        assert_eq!(delta.transport, None);
        assert_eq!(delta.title, None);
    }

    /// `LF` and `RF` are pinned at 100 on a stereo player. Reading the first
    /// element, or the last, would report a speaker at full volume that is
    /// actually at ten — and then a volume-up button would jump it there.
    #[test]
    fn the_left_and_right_channels_never_overwrite_the_master_volume() {
        // The channels are deliberately out of the order the speaker sends
        // them, so neither "first wins" nor "last wins" can pass by accident.
        let body = concat!(
            r#"<e:propertyset><e:property><LastChange>"#,
            r#"&lt;Event xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/RCS/&quot;&gt;&lt;InstanceID val=&quot;0&quot;&gt;"#,
            r#"&lt;Volume channel=&quot;LF&quot; val=&quot;100&quot;/&gt;"#,
            r#"&lt;Volume channel=&quot;Master&quot; val=&quot;7&quot;/&gt;"#,
            r#"&lt;Volume channel=&quot;RF&quot; val=&quot;100&quot;/&gt;"#,
            r#"&lt;Mute channel=&quot;LF&quot; val=&quot;0&quot;/&gt;"#,
            r#"&lt;Mute channel=&quot;Master&quot; val=&quot;1&quot;/&gt;"#,
            r#"&lt;Mute channel=&quot;RF&quot; val=&quot;0&quot;/&gt;"#,
            r#"&lt;/InstanceID&gt;&lt;/Event&gt;"#,
            r#"</LastChange></e:property></e:propertyset>"#,
        );
        let delta = parse_last_change(body);
        assert_eq!(delta.volume, Some(7));
        assert_eq!(delta.muted, Some(true));
    }

    #[test]
    fn the_avtransport_body_yields_the_track() {
        let delta = parse_last_change(AVTRANSPORT_PLAYING);
        assert_eq!(delta.transport, Some(Transport::Playing));
        assert_eq!(delta.title.as_deref(), Some("Hoppípolla"));
        assert_eq!(delta.artist.as_deref(), Some("Sigur Rós"));
        assert_eq!(delta.album.as_deref(), Some("Takk..."));
        assert_eq!(delta.duration_secs, Some(192));
        assert_eq!(delta.track_uri.as_deref(), Some("x-sonos-http:track%3a42.mp4?sid=204"));
        assert_eq!(delta.stream_content, None);
        assert_eq!(delta.volume, None);
    }

    /// The single likeliest bug in the driver. `LastChange` is escaped twice:
    /// after one pass the DIDL-Lite is still text, so every element lookup
    /// into it misses and the track silently never reaches the page. This test
    /// fails the moment someone "simplifies" the second unescape away.
    #[test]
    fn one_unescape_does_not_do_the_work_of_two() {
        let once = xml::unescape(AVTRANSPORT_PLAYING);
        // One pass reaches the Event and stops there.
        assert!(once.contains("<TransportState val=\"PLAYING\"/>"));
        assert!(once.contains("&lt;DIDL-Lite"));
        assert!(!once.contains("<DIDL-Lite"));
        // So no DIDL element exists yet to be found...
        assert_eq!(xml::element(&once, "title"), None);
        // ...and only the second pass, which the parser does, finds it.
        assert_eq!(parse_last_change(AVTRANSPORT_PLAYING).title.as_deref(), Some("Hoppípolla"));
    }

    /// A `SEQ > 0` notification names only what moved. Everything it does not
    /// name must stay `None`, or merging it would blank the page.
    #[test]
    fn a_later_notification_names_only_what_changed() {
        let body = concat!(
            r#"<e:propertyset><e:property><LastChange>"#,
            r#"&lt;Event xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/AVT/&quot;&gt;&lt;InstanceID val=&quot;0&quot;&gt;"#,
            r#"&lt;TransportState val=&quot;PAUSED_PLAYBACK&quot;/&gt;"#,
            r#"&lt;/InstanceID&gt;&lt;/Event&gt;"#,
            r#"</LastChange></e:property></e:propertyset>"#,
        );
        let delta = parse_last_change(body);
        assert_eq!(delta.transport, Some(Transport::Paused));
        assert_eq!(delta.volume, None);
        assert_eq!(delta.muted, None);
        assert_eq!(delta.title, None);
        assert_eq!(delta.artist, None);
        assert_eq!(delta.album, None);
        assert_eq!(delta.track_uri, None);
        assert_eq!(delta.duration_secs, None);
        assert_eq!(delta.stream_content, None);
        assert!(!delta.is_empty());
    }

    /// `ZPSTR_BUFFERING` is a speaker saying "the stream has not arrived yet".
    /// Shown as a title it reads as a corrupt track name.
    #[test]
    fn a_buffering_stream_reports_no_stream_content() {
        let body = radio(BUFFERING);
        assert_eq!(parse_last_change(&body).stream_content, None);
    }

    #[test]
    fn a_radio_stream_exposes_its_stream_content_unsplit() {
        let body = radio("Nacho Sotomayor - Reject");
        assert_eq!(
            parse_last_change(&body).stream_content.as_deref(),
            Some("Nacho Sotomayor - Reject")
        );
    }

    /// A live stream has no length, and the speaker says so with a sentinel
    /// rather than a number. Reading it as zero draws a finished progress bar
    /// over something that is still playing.
    #[test]
    fn a_duration_is_read_but_a_sentinel_is_not() {
        assert_eq!(parse_duration("0:03:12"), Some(192));
        assert_eq!(parse_duration("0:00:00"), Some(0));
        assert_eq!(parse_duration("1:00:00"), Some(3600));
        assert_eq!(parse_duration("10:20:30"), Some(37230));
        assert_eq!(parse_duration("03:12"), Some(192));
        assert_eq!(parse_duration(" 0:03:12 "), Some(192));
        assert_eq!(parse_duration("0:03:12.500"), Some(192));
        assert_eq!(parse_duration("NOT_IMPLEMENTED"), None);
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("192"), None);
        assert_eq!(parse_duration("0:0a:12"), None);
        assert_eq!(parse_duration("-1:00:00"), None);
        assert_eq!(parse_duration("1:2:3:4"), None);
    }

    #[test]
    fn an_unfamiliar_transport_state_reads_as_stopped_rather_than_failing() {
        let body = concat!(
            r#"<LastChange>&lt;Event&gt;&lt;InstanceID val=&quot;0&quot;&gt;"#,
            r#"&lt;TransportState val=&quot;VENDOR_SURPRISE&quot;/&gt;"#,
            r#"&lt;/InstanceID&gt;&lt;/Event&gt;</LastChange>"#,
        );
        assert_eq!(parse_last_change(body).transport, Some(Transport::Stopped));
    }

    /// An idle player sends the fields with empty values rather than omitting
    /// them; taken literally that would clear a title the page is still
    /// rightly showing.
    #[test]
    fn an_empty_value_is_not_news() {
        let body = concat!(
            r#"<LastChange>&lt;Event&gt;&lt;InstanceID val=&quot;0&quot;&gt;"#,
            r#"&lt;CurrentTrackURI val=&quot;&quot;/&gt;"#,
            r#"&lt;CurrentTrackDuration val=&quot;&quot;/&gt;"#,
            r#"&lt;CurrentTrackMetaData val=&quot;&amp;lt;DIDL-Lite&amp;gt;&amp;lt;item&amp;gt;"#,
            r#"&amp;lt;dc:title&amp;gt;&amp;lt;/dc:title&amp;gt;&amp;lt;/item&amp;gt;&amp;lt;/DIDL-Lite&amp;gt;&quot;/&gt;"#,
            r#"&lt;/InstanceID&gt;&lt;/Event&gt;</LastChange>"#,
        );
        let delta = parse_last_change(body);
        assert_eq!(delta.track_uri, None);
        assert_eq!(delta.duration_secs, None);
        assert_eq!(delta.title, None);
    }

    /// A track title carrying an ampersand is escaped once for the DIDL, again
    /// for the metadata attribute, and again for `LastChange` — three levels,
    /// and a parser that spends the wrong number of them shows the difference.
    #[test]
    fn a_title_with_an_ampersand_survives_three_levels_of_escaping() {
        let body = concat!(
            r#"<LastChange>&lt;Event&gt;&lt;InstanceID val=&quot;0&quot;&gt;"#,
            r#"&lt;CurrentTrackMetaData val=&quot;&amp;lt;DIDL-Lite&amp;gt;&amp;lt;item&amp;gt;"#,
            r#"&amp;lt;dc:title&amp;gt;Simon &amp;amp;amp; Garfunkel&amp;lt;/dc:title&amp;gt;"#,
            r#"&amp;lt;/item&amp;gt;&amp;lt;/DIDL-Lite&amp;gt;&quot;/&gt;"#,
            r#"&lt;/InstanceID&gt;&lt;/Event&gt;</LastChange>"#,
        );
        assert_eq!(parse_last_change(body).title.as_deref(), Some("Simon & Garfunkel"));
    }

    #[test]
    fn a_malformed_body_changes_nothing_rather_than_panicking() {
        assert!(parse_last_change("").is_empty());
        assert!(parse_last_change("not xml at all").is_empty());
        assert!(parse_last_change("<e:propertyset><e:property></e:property></e:propertyset>").is_empty());
        assert!(parse_last_change("<LastChange>&lt;Event&gt;&lt;InstanceID").is_empty());
        assert!(parse_last_change("<LastChange></LastChange>").is_empty());
        assert!(parse_last_change("<LastChange>&lt;&lt;&gt;&gt;</LastChange>").is_empty());
    }

    /// An event carrying only fields this crate does not model is not a
    /// change, and the listener may drop it without waking anything.
    #[test]
    fn an_event_about_bass_alone_is_empty() {
        let body = concat!(
            r#"<LastChange>&lt;Event&gt;&lt;InstanceID val=&quot;0&quot;&gt;"#,
            r#"&lt;Bass val=&quot;3&quot;/&gt;&lt;Treble val=&quot;-2&quot;/&gt;"#,
            r#"&lt;/InstanceID&gt;&lt;/Event&gt;</LastChange>"#,
        );
        assert!(parse_last_change(body).is_empty());
    }

    /// Builds an AVTransport body for a radio stream with the given
    /// `r:streamContent`, which is the only place a station names a track.
    fn radio(stream_content: &str) -> String {
        format!(
            concat!(
                r#"<e:propertyset><e:property><LastChange>"#,
                r#"&lt;Event xmlns=&quot;urn:schemas-upnp-org:metadata-1-0/AVT/&quot;"#,
                r#" xmlns:r=&quot;urn:schemas-rinconnetworks-com:metadata-1-0/&quot;&gt;"#,
                r#"&lt;InstanceID val=&quot;0&quot;&gt;"#,
                r#"&lt;TransportState val=&quot;PLAYING&quot;/&gt;"#,
                r#"&lt;CurrentTrackDuration val=&quot;0:00:00&quot;/&gt;"#,
                r#"&lt;CurrentTrackURI val=&quot;x-sonosapi-stream:s24885?sid=254&quot;/&gt;"#,
                r#"&lt;r:streamContent val=&quot;{content}&quot;/&gt;"#,
                r#"&lt;/InstanceID&gt;&lt;/Event&gt;"#,
                r#"</LastChange></e:property></e:propertyset>"#,
            ),
            content = xml::escape(&xml::escape(stream_content)),
        )
    }
}
