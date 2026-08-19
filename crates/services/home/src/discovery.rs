//! What is on the network, and nothing about what to do with it.
//!
//! This module is the authority on the question "which machines in this house
//! answered us, and what did they say they were". It is the only place that
//! speaks SSDP, and it deliberately stops short of everything a driver does: it
//! opens no HTTP connection to a device description, learns no room name, and
//! reads no state. What it returns is a list of addresses with an identity
//! attached — enough for a driver to take over, and nothing that would make
//! this module have to be edited when a driver changes.
//!
//! # Why it cannot fail
//!
//! Discovery runs on every startup and on a timer, on machines whose network is
//! not the one it was written against: a box whose only interface is a VPN
//! tunnel, a container on a bridge that drops multicast, a laptop on a guest
//! network where the access point blocks it outright. On all of those an
//! `M-SEARCH` goes nowhere, and that is not an error — it is a house with
//! nothing discoverable in it. So every path here returns an empty [`Vec`]
//! rather than a `Result`, and the daemon that calls it has no error to handle
//! and no reason to stop. Nothing is written to stdout either: the caller
//! decides what is worth saying, because this runs on a timer and a line per
//! sweep would be a log nobody reads.
//!
//! # Why it asks more than once
//!
//! `M-SEARCH` is a UDP datagram to a multicast group, and both the question and
//! the answer are unacknowledged. On a busy wireless network one speaker in ten
//! is missed by a single datagram, and a missing speaker is worse than a slow
//! sweep — the page shows a house with a hole in it, and a person concludes the
//! system is unreliable. So the search is sent [`BURSTS`] times, spread across
//! the caller's window, and the answers are collected until the window closes.
//! A device answering three times is expected, not a fault, which is why
//! everything is deduplicated by the UUID in its `USN` rather than by address.
//!
//! # Why a Fire TV is decided by a TCP connection
//!
//! Sonos is the device that matters here and it is discovered properly: it
//! answers a `ZonePlayer` search with a stable `RINCON_` identity. An Amazon
//! box answers a general search too, but answering says nothing about whether
//! it can be driven — its debug bridge is off until somebody enables it by hand
//! on the device. Reporting one as a Fire TV on the strength of its SSDP text
//! would put a tile on the page that refuses every command. So a host is called
//! [`FoundKind::FireTv`] only when a TCP connection to port 5555 is accepted.
//! That is a reachability probe and stops there: no ADB handshake is spoken in
//! this module, because the protocol belongs with the driver that uses it.
//!
//! The rejected alternative was sweeping the whole subnet for open ports. It
//! finds boxes that answer no discovery at all, and it costs a few hundred
//! connections per sweep, sets off every intrusion detector on the network, and
//! guesses at the subnet it should scan. Probing only hosts that already spoke
//! to us keeps the sweep to as many connections as there are devices.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use tokio::net::{TcpStream, UdpSocket};

/// The SSDP multicast group and port, fixed by the specification.
const SSDP_GROUP: &str = "239.255.255.250:1900";

/// The search target that only a Sonos answers.
const SONOS_TARGET: &str = "urn:schemas-upnp-org:device:ZonePlayer:1";

/// The search target everything with a UPnP stack answers, which is how a
/// candidate for the port 5555 probe gets onto the list at all.
const EVERYTHING_TARGET: &str = "ssdp:all";

/// How many times the search is sent across the caller's window.
///
/// Three rather than one because a single datagram loses roughly one speaker in
/// ten, and three rather than ten because the return diminishes sharply and
/// every extra burst is another round of answers from every device on the
/// network.
pub const BURSTS: u32 = 3;

/// The port Android's debug bridge listens on, and the only thing this module
/// asks about a television.
pub const ADB_PORT: u16 = 5555;

/// How long a single port probe may wait before the host counts as closed.
///
/// A LAN handshake completes in single-digit milliseconds; this budget is only
/// ever spent in full by a host that silently drops the SYN, which is what a
/// firewalled port does. It is a ceiling on how far past the caller's window a
/// sweep can run, and the probes run concurrently, so it is paid once and not
/// once per device.
pub const PROBE_BUDGET: Duration = Duration::from_millis(800);

/// The largest SSDP response worth reading.
///
/// Answers are a few hundred bytes of headers; anything claiming to be larger
/// is not a device this crate can use, and a fixed buffer means a sweep on a
/// hostile network cannot be made to allocate.
const DATAGRAM_LIMIT: usize = 4096;

/// What a discovered host appears to be.
///
/// Not the same question as [`crate::device::Kind`], which says what a device
/// is for. This says which driver should be handed the address, and `Unknown`
/// is a normal, common answer — a printer, a television, a router — carried
/// rather than dropped so a person diagnosing an absent speaker can see what
/// the network *did* answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FoundKind {
    /// A Sonos zone player: it answered the `ZonePlayer` search, or named
    /// itself Sonos, or quoted a household.
    Sonos,
    /// A host with the Android debug bridge accepting connections. Decided by
    /// the probe, never by what the host said about itself.
    FireTv,
    /// Something that answered discovery and is neither of the above.
    Unknown,
}

impl FoundKind {
    /// The lowercase word this kind travels as in JSON and in a diagnostic.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            FoundKind::Sonos => "sonos",
            FoundKind::FireTv => "firetv",
            FoundKind::Unknown => "unknown",
        }
    }
}

/// One host that answered, as discovery saw it.
///
/// Everything except the address is optional because everything except the
/// address is the device's choice. A driver decides for itself whether what it
/// was given is enough to work with; discovery does not withhold a half-filled
/// answer, because a speaker that replied without a household is still a
/// speaker at that address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The host, without a port: `192.168.1.6`.
    ///
    /// Bare on purpose. The port belongs to the protocol rather than to the
    /// discovery — Sonos control is 1400, the debug bridge is 5555, and the
    /// same host can be both — so composing one is the caller's job and the
    /// probe here does not have to take a port back off a string.
    pub address: String,
    /// Which driver should be handed this address.
    pub kind: FoundKind,
    /// The only name a datagram carries: the hardware model out of the `SERVER`
    /// header, such as `ZPS13`. Never the room, which lives in the device
    /// description a driver fetches, and never a name a person chose.
    pub name: Option<String>,
    /// The device's permanent identity, as its own protocol states it — a
    /// Sonos `RINCON_…` UUID. This is what [`crate::device::DeviceId::new`]
    /// wants as its key, and it is the reason an address change does not
    /// rename a device.
    pub key: Option<String>,
    /// The Sonos household this speaker belongs to.
    ///
    /// Carried because a network can hear more than one Sonos system — a
    /// neighbour's, across a shared flat's wifi — and adopting a speaker from
    /// the wrong household means a person's music starting in somebody else's
    /// living room. The hub decides on it; discovery only reports it.
    pub household: Option<String>,
    /// The device description URL verbatim, from `LOCATION`.
    ///
    /// Kept whole rather than rebuilt from [`Found::address`], because
    /// rebuilding assumes a port and a path that the device stated and the
    /// specification does not promise.
    pub location: Option<String>,
}

impl Found {
    /// What two answers must share to be the same device.
    ///
    /// The UUID, when there is one — a device answers each of the three bursts
    /// and answers every search target it matches, so by design the same
    /// speaker arrives four or six times, from the same address, and only its
    /// `USN` says so. The address is the fallback identity for something that
    /// answered without a `USN`, which is the worst case rather than the normal
    /// one.
    #[must_use]
    pub fn identity(&self) -> String {
        match &self.key {
            Some(key) => format!("uuid:{key}"),
            None => format!("addr:{}", self.address),
        }
    }
}

/// Finds every device on the local network that answers within `timeout`.
///
/// The window is the SSDP budget: the searches are spread across it and answers
/// are taken until it closes. The port 5555 probes then run concurrently and
/// may add up to [`PROBE_BUDGET`] on top, so a caller sizing a startup
/// sequence should allow for the window plus a second.
///
/// Never fails. A machine with no route to the multicast group, no permission
/// to bind, or no devices to find all produce an empty `Vec`.
pub async fn sweep(timeout: Duration) -> Vec<Found> {
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else {
        return Vec::new();
    };
    // A few hops so a bridged or meshed access point still forwards the search.
    // Best effort: a stack that refuses is one where the default is already
    // whatever it is going to be, and refusing to sweep over it helps nobody.
    let _ = socket.set_multicast_ttl_v4(4);

    let mut found = listen(&socket, timeout).await;
    upgrade_reachable_televisions(&mut found).await;
    found
}

/// Sends the bursts and collects answers until the window closes.
///
/// Split out from [`sweep`] so the loop that has to reason about two deadlines
/// at once — the next burst and the end of the window — is not also holding the
/// probe logic.
async fn listen(socket: &UdpSocket, timeout: Duration) -> Vec<Found> {
    let started = Instant::now();
    let deadline = started + timeout;
    // The last burst goes out with a third of the window left to answer in;
    // spacing on `BURSTS` rather than `BURSTS - 1` is what reserves it.
    let spacing = timeout / BURSTS;

    let mut found: Vec<Found> = Vec::new();
    let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
    let mut sent = 0_u32;
    let mut next_burst = started;

    loop {
        let now = Instant::now();
        if now >= deadline {
            return found;
        }
        if sent < BURSTS && now >= next_burst {
            for target in [SONOS_TARGET, EVERYTHING_TARGET] {
                let _ = socket.send_to(search(target).as_bytes(), SSDP_GROUP).await;
            }
            sent += 1;
            next_burst = now + spacing;
            continue;
        }

        // Wake for whichever comes first, so a burst is never late because a
        // quiet network left us blocked on a read until the window ended.
        let wake = if sent < BURSTS { next_burst.min(deadline) } else { deadline };
        let slice = wake.saturating_duration_since(now);
        match tokio::time::timeout(slice, socket.recv_from(&mut buffer)).await {
            Ok(Ok((length, from))) => {
                let datagram = String::from_utf8_lossy(&buffer[..length.min(DATAGRAM_LIMIT)]);
                if let Some(answer) = parse(&datagram, &from.ip().to_string()) {
                    absorb(&mut found, answer);
                }
            }
            // A read error is per-datagram, not per-socket: a host that went
            // away can produce one on some platforms, and the window is what
            // bounds the loop, so there is nothing to abandon.
            Ok(Err(_)) => {}
            Err(_) => {}
        }
    }
}

/// Turns hosts with an open debug bridge into [`FoundKind::FireTv`].
///
/// Every host that answered anything is a candidate except the speakers, which
/// are already identified and do not run a debug bridge; probing them would be
/// two connections per sweep spent proving something known. A host that does
/// not accept the connection keeps the kind it had, so a closed port removes
/// nothing from the list — it only declines to promise the thing is drivable.
async fn upgrade_reachable_televisions(found: &mut [Found]) {
    let mut candidates: Vec<String> = Vec::new();
    for entry in found.iter() {
        if entry.kind != FoundKind::Sonos && !candidates.contains(&entry.address) {
            candidates.push(entry.address.clone());
        }
    }
    if candidates.is_empty() {
        return;
    }

    let mut probes = Vec::with_capacity(candidates.len());
    for host in candidates {
        probes.push(tokio::spawn(async move {
            let open = accepts_adb(&host).await;
            (host, open)
        }));
    }

    let mut open: HashSet<String> = HashSet::new();
    for probe in probes {
        // A probe that panicked or was cancelled is a host we learned nothing
        // about, which is the same outcome as a closed port.
        if let Ok((host, true)) = probe.await {
            open.insert(host);
        }
    }

    for entry in found.iter_mut() {
        if entry.kind != FoundKind::Sonos && open.contains(&entry.address) {
            entry.kind = FoundKind::FireTv;
        }
    }
}

/// Whether a TCP connection to the debug bridge is accepted.
///
/// Connect and drop. Anything more — a handshake, a version banner — is the
/// ADB driver's protocol, and speaking half of it here would put the same
/// parsing in two places.
async fn accepts_adb(host: &str) -> bool {
    let connect = TcpStream::connect((host, ADB_PORT));
    matches!(tokio::time::timeout(PROBE_BUDGET, connect).await, Ok(Ok(_)))
}

/// Builds an `M-SEARCH` for one target.
///
/// `MAN` is quoted and `MX` is present because devices reject a search missing
/// either, quietly and without an answer — which looks exactly like a network
/// that drops multicast. `MX: 2` asks devices to spread their replies over two
/// seconds so a house full of speakers does not answer in one burst the socket
/// then drops; it is the reason a window shorter than about three seconds finds
/// less than the house contains.
#[must_use]
fn search(target: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\n\
         HOST: {SSDP_GROUP}\r\n\
         MAN: \"ssdp:discover\"\r\n\
         MX: 2\r\n\
         ST: {target}\r\n\
         \r\n"
    )
}

/// Reads one SSDP response into a [`Found`], or decides it is not one.
///
/// Pure and total, and separate from the socket for exactly that reason: this
/// is where every real bug in discovery lives — a header matched
/// case-sensitively, a `LOCATION` whose port was mistaken for the host, a
/// `byebye` notification counted as a device — and each of those is a captured
/// datagram and an assertion here rather than a speaker somebody has to unplug
/// to reproduce.
///
/// `source` is the address the datagram arrived from, used only when the
/// response carries no usable `LOCATION`. The socket knows it and the text does
/// not, which is why it is a parameter rather than something this function
/// could find out.
#[must_use]
pub fn parse(datagram: &str, source: &str) -> Option<Found> {
    // Only an answer to our own search may create a device. A `NOTIFY` —
    // including `ssdp:byebye`, which announces a *departure* — must never add
    // one, and a datagram that is not SSDP at all must not either.
    let status = datagram.lines().next()?.trim();
    if !status.starts_with("HTTP/1.") || !status.contains(" 200") {
        return None;
    }

    let location = header(datagram, "location").map(str::to_owned);
    let address = location
        .as_deref()
        .and_then(host_of)
        .unwrap_or_else(|| source.to_owned());
    if address.is_empty() {
        return None;
    }

    let usn = header(datagram, "usn").unwrap_or_default();
    let search_target = header(datagram, "st").unwrap_or_default();
    let server = header(datagram, "server").unwrap_or_default();
    let household = header(datagram, "x-rincon-household")
        .filter(|value| !value.is_empty())
        .map(str::to_owned);

    let sonos = search_target.contains("ZonePlayer")
        || usn.contains("ZonePlayer")
        || usn.contains("RINCON_")
        || server.to_ascii_lowercase().contains("sonos")
        || household.is_some();

    Some(Found {
        address,
        kind: if sonos { FoundKind::Sonos } else { FoundKind::Unknown },
        name: model_of(server),
        key: uuid_of(usn),
        household,
        location,
    })
}

/// Adds an answer to the list, or folds it into the one already there.
///
/// Folding rather than discarding, because the burst that arrives second is not
/// the same text as the first: a speaker answering the `ZonePlayer` search
/// quotes its household, and the same speaker answering `ssdp:all` may not.
/// Taking only the first answer would lose whichever fact the other one
/// carried, and the kind can only ever be sharpened from `Unknown`.
fn absorb(found: &mut Vec<Found>, answer: Found) {
    let identity = answer.identity();
    if let Some(existing) = found.iter_mut().find(|entry| entry.identity() == identity) {
        if existing.kind == FoundKind::Unknown {
            existing.kind = answer.kind;
        }
        if existing.name.is_none() {
            existing.name = answer.name;
        }
        if existing.household.is_none() {
            existing.household = answer.household;
        }
        if existing.location.is_none() {
            existing.location = answer.location;
        }
        return;
    }
    found.push(answer);
}

/// The value of one header, matched without regard to case.
///
/// Sonos sends `LOCATION`, a Fire TV sends `Location`, and the specification
/// permits both — matching either exactly is the single most common way an
/// SSDP reader silently finds nothing. The split is on the *first* colon only,
/// because the value of `LOCATION` contains two more.
#[must_use]
fn header<'a>(datagram: &'a str, name: &str) -> Option<&'a str> {
    datagram.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

/// The host out of a URL, without scheme, port, or path.
#[must_use]
fn host_of(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = after_scheme.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    // A bracketed IPv6 literal holds colons of its own, so the closing bracket
    // is the end of the host, not the first colon.
    if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        return (!host.is_empty()).then(|| host.to_owned());
    }
    let host = authority.split_once(':').map_or(authority, |(host, _)| host);
    (!host.is_empty()).then(|| host.to_owned())
}

/// The device UUID out of a `USN`.
///
/// A `USN` is the identity and the answered target joined by `::`, as in
/// `uuid:RINCON_7828CA1491AE01400::urn:schemas-upnp-org:device:ZonePlayer:1`.
/// Only the first half is the device; keeping the whole string would give the
/// same speaker one identity per search target it answered — nineteen of them,
/// on the hardware this was written against — and defeat the deduplication
/// entirely.
///
/// Two things this has to survive were found on real hardware rather than
/// reasoned about, and both are why this is a function with tests instead of a
/// `strip_prefix` at the call site:
///
/// * A Sonos advertises **three** UUIDs — the zone player, and a `_MR` media
///   renderer and `_MS` media server embedded in it. They are one speaker in
///   one box, and taking them at their word puts three tiles on the page for
///   it. The suffix is dropped so all three fold onto the zone player, which
///   is also the identity the Sonos protocol itself uses everywhere else.
/// * MiniUPnPd, which is what the router in the test house runs, emits
///   `uuid:uuid:4d696e69-…` — it stores the prefix as part of the UUID and
///   prepends it again. Stripping once leaves a `uuid:` inside the key, so the
///   prefix is consumed until there is none left.
#[must_use]
fn uuid_of(usn: &str) -> Option<String> {
    let mut body = usn.trim();
    while let Some(prefix) = body.get(..5) {
        if !prefix.eq_ignore_ascii_case("uuid:") {
            break;
        }
        body = body[5..].trim_start();
    }
    let uuid = body.split("::").next()?.trim();
    let uuid = zone_player_of(uuid);
    (!uuid.is_empty()).then(|| uuid.to_owned())
}

/// The speaker a Sonos sub-device UUID belongs to.
///
/// Scoped to `RINCON_` on purpose: `_MS` and `_MR` are only known to mean
/// "media server" and "media renderer" in Sonos's own scheme, and trimming
/// them from anybody else's UUID would merge two devices that are genuinely
/// two.
#[must_use]
fn zone_player_of(uuid: &str) -> &str {
    if !uuid.starts_with("RINCON_") {
        return uuid;
    }
    uuid.strip_suffix("_MR").or_else(|| uuid.strip_suffix("_MS")).unwrap_or(uuid)
}

/// The model out of a `SERVER` header.
///
/// Sonos states it in parentheses at the end — `Linux UPnP/1.0 Sonos/84.1-63110
/// (ZPS13)` — and that fragment is the only part worth showing a person. The
/// whole header is a user agent string: it names an operating system and a
/// firmware build, neither of which identifies the box in the corner.
#[must_use]
fn model_of(server: &str) -> Option<String> {
    let open = server.find('(')?;
    let close = server[open + 1..].find(')')?;
    let model = server[open + 1..open + 1 + close].trim();
    (!model.is_empty()).then(|| model.to_owned())
}

/// How many distinct devices a set of answers describes.
///
/// Exposed because the caller that logs a sweep wants the honest number, and
/// counting the `Vec` after deduplication is only the same number for as long
/// as nobody adds a second entry per host — which is exactly what the port
/// probe does.
#[must_use]
pub fn distinct_hosts(found: &[Found]) -> usize {
    let mut hosts: HashMap<&str, ()> = HashMap::new();
    for entry in found {
        hosts.insert(entry.address.as_str(), ());
    }
    hosts.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real answer from a Sonos One, captured off the wire byte for byte,
    /// including the space either side of the `=` in `max-age = 1800` that a
    /// stricter reader would trip on.
    const CAPTURED: &str = "HTTP/1.1 200 OK\r\n\
CACHE-CONTROL: max-age = 1800\r\n\
EXT:\r\n\
LOCATION: http://192.168.1.6:1400/xml/device_description.xml\r\n\
SERVER: Linux UPnP/1.0 Sonos/84.1-63110 (ZPS13)\r\n\
ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
USN: uuid:RINCON_7828CA1491AE01400::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
X-RINCON-HOUSEHOLD: Sonos_EIFyXFHMzYBeAfsBofjVb1VGIB\r\n\
\r\n";

    #[test]
    fn a_captured_sonos_answer_reads_into_a_found() {
        let found = parse(CAPTURED, "192.168.1.6").expect("a 200 answer is a device");
        assert_eq!(found.kind, FoundKind::Sonos);
        assert_eq!(found.address, "192.168.1.6");
        assert_eq!(found.key.as_deref(), Some("RINCON_7828CA1491AE01400"));
        assert_eq!(
            found.household.as_deref(),
            Some("Sonos_EIFyXFHMzYBeAfsBofjVb1VGIB")
        );
        assert_eq!(
            found.location.as_deref(),
            Some("http://192.168.1.6:1400/xml/device_description.xml")
        );
        assert_eq!(found.name.as_deref(), Some("ZPS13"));
    }

    /// The key is what [`crate::device::DeviceId`] is built from, so it must be
    /// the UUID alone and not the whole `USN` — a speaker answering two search
    /// targets would otherwise become two devices.
    #[test]
    fn the_key_is_the_uuid_without_the_answered_target() {
        let found = parse(CAPTURED, "192.168.1.6").expect("a device");
        let key = found.key.expect("a USN carries one");
        assert!(!key.contains("::"));
        assert!(!key.starts_with("uuid:"));
        assert_eq!(
            crate::device::DeviceId::new("sonos", &key).as_str(),
            "sonos:rincon_7828ca1491ae01400"
        );
    }

    /// Header names are case-insensitive by specification and firmware differs;
    /// matching `LOCATION` exactly is how a reader finds nothing on a network
    /// full of devices.
    #[test]
    fn header_names_are_matched_without_regard_to_case() {
        let lowercase = "HTTP/1.1 200 OK\r\n\
location: http://192.168.1.9:1400/xml/device_description.xml\r\n\
usn: uuid:RINCON_000E58000001400::urn:schemas-upnp-org:device:ZonePlayer:1\r\n\
x-rincon-household: Sonos_abc\r\n\r\n";
        let found = parse(lowercase, "10.0.0.1").expect("a device");
        assert_eq!(found.address, "192.168.1.9");
        assert_eq!(found.key.as_deref(), Some("RINCON_000E58000001400"));
        assert_eq!(found.household.as_deref(), Some("Sonos_abc"));
    }

    /// The port in `LOCATION` is not the host. Reading it as one produces an
    /// address nothing can be reached at, and the failure appears later as a
    /// speaker that discovers fine and never answers.
    #[test]
    fn the_location_port_is_not_mistaken_for_the_host() {
        assert_eq!(
            host_of("http://192.168.1.6:1400/xml/device_description.xml").as_deref(),
            Some("192.168.1.6")
        );
        assert_eq!(host_of("http://192.168.1.6/desc.xml").as_deref(), Some("192.168.1.6"));
        assert_eq!(host_of("http://[fe80::1]:1400/desc.xml").as_deref(), Some("fe80::1"));
        assert_eq!(host_of("http://").as_deref(), None);
    }

    /// `LOCATION` is the device's own statement of where it is; the datagram's
    /// source address is only a fallback. A device answering through a relay
    /// must still be recorded where it said it was.
    #[test]
    fn the_stated_location_wins_over_the_datagram_source() {
        let found = parse(CAPTURED, "10.9.9.9").expect("a device");
        assert_eq!(found.address, "192.168.1.6");
    }

    #[test]
    fn an_answer_without_a_location_falls_back_to_the_sender() {
        let terse = "HTTP/1.1 200 OK\r\nST: ssdp:all\r\nUSN: uuid:0d1a-77\r\n\r\n";
        let found = parse(terse, "192.168.1.44").expect("a device");
        assert_eq!(found.address, "192.168.1.44");
        assert_eq!(found.key.as_deref(), Some("0d1a-77"));
        assert_eq!(found.kind, FoundKind::Unknown);
    }

    /// A `byebye` announces a device *leaving*. Counting it as an answer would
    /// add a device to the house at the moment it was unplugged.
    #[test]
    fn a_byebye_notification_is_not_a_device() {
        let byebye = "NOTIFY * HTTP/1.1\r\n\
HOST: 239.255.255.250:1900\r\n\
NTS: ssdp:byebye\r\n\
USN: uuid:RINCON_7828CA1491AE01400::upnp:rootdevice\r\n\r\n";
        assert_eq!(parse(byebye, "192.168.1.6"), None);
    }

    #[test]
    fn a_datagram_that_is_not_ssdp_is_ignored() {
        assert_eq!(parse("", "192.168.1.6"), None);
        assert_eq!(parse("\u{0}\u{1}garbage", "192.168.1.6"), None);
        assert_eq!(parse("HTTP/1.1 404 Not Found\r\n\r\n", "192.168.1.6"), None);
    }

    /// A device that says only that it is a Sonos, without a `ZonePlayer`
    /// target, is still a Sonos — the general search is answered with
    /// `upnp:rootdevice`, and refusing it would hide every speaker that
    /// happened to be heard that way first.
    #[test]
    fn a_sonos_is_recognised_by_its_server_line_alone() {
        let root = "HTTP/1.1 200 OK\r\n\
LOCATION: http://192.168.1.6:1400/xml/device_description.xml\r\n\
SERVER: Linux UPnP/1.0 Sonos/84.1-63110 (ZPS13)\r\n\
ST: upnp:rootdevice\r\n\
USN: uuid:RINCON_7828CA1491AE01400::upnp:rootdevice\r\n\r\n";
        assert_eq!(parse(root, "192.168.1.6").map(|f| f.kind), Some(FoundKind::Sonos));
    }

    /// The whole reason the search is sent three times: every device answers
    /// every burst, and each answer must land on the device already recorded.
    #[test]
    fn a_device_answering_every_burst_appears_once() {
        let mut found = Vec::new();
        for _ in 0..BURSTS {
            absorb(&mut found, parse(CAPTURED, "192.168.1.6").expect("a device"));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(distinct_hosts(&found), 1);
    }

    /// Answers to the two search targets carry different facts about the same
    /// speaker; the second must fill in what the first did not have rather than
    /// be thrown away.
    #[test]
    fn a_second_answer_fills_in_what_the_first_lacked() {
        let terse = "HTTP/1.1 200 OK\r\n\
ST: upnp:rootdevice\r\n\
USN: uuid:RINCON_7828CA1491AE01400::upnp:rootdevice\r\n\r\n";
        let mut found = Vec::new();
        absorb(&mut found, parse(terse, "192.168.1.6").expect("a device"));
        assert_eq!(found[0].kind, FoundKind::Sonos);
        assert_eq!(found[0].household, None);
        assert_eq!(found[0].name, None);

        absorb(&mut found, parse(CAPTURED, "192.168.1.6").expect("a device"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].name.as_deref(), Some("ZPS13"));
        assert_eq!(
            found[0].household.as_deref(),
            Some("Sonos_EIFyXFHMzYBeAfsBofjVb1VGIB")
        );
        assert_eq!(
            found[0].location.as_deref(),
            Some("http://192.168.1.6:1400/xml/device_description.xml")
        );
    }

    /// Two speakers behind one address — which is what a device answering from
    /// a shared host looks like — must stay two devices, because the UUID and
    /// not the address is the identity.
    #[test]
    fn two_uuids_at_one_address_are_two_devices() {
        let first = parse(CAPTURED, "192.168.1.6").expect("a device");
        let mut second = first.clone();
        second.key = Some("RINCON_000E58FFFF01400".to_owned());
        let mut found = Vec::new();
        absorb(&mut found, first);
        absorb(&mut found, second);
        assert_eq!(found.len(), 2);
        assert_eq!(distinct_hosts(&found), 1);
    }

    /// A device that gave no `USN` is identified by address, so two answers
    /// from one such host are still one device.
    #[test]
    fn an_answer_without_a_usn_is_identified_by_address() {
        let anonymous = "HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n";
        let mut found = Vec::new();
        absorb(&mut found, parse(anonymous, "192.168.1.70").expect("a device"));
        absorb(&mut found, parse(anonymous, "192.168.1.70").expect("a device"));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].identity(), "addr:192.168.1.70");
    }

    /// One Sonos answers with three UUIDs — itself, its `_MR` media renderer
    /// and its `_MS` media server — all from one box at one address. Captured
    /// off the wire; taking them at their word puts three tiles on the page for
    /// one speaker.
    #[test]
    fn a_speaker_advertising_its_sub_devices_is_still_one_speaker() {
        let renderer = "HTTP/1.1 200 OK\r\n\
CACHE-CONTROL: max-age = 1800\r\n\
EXT:\r\n\
LOCATION: http://192.168.1.6:1400/xml/device_description.xml\r\n\
SERVER: Linux UPnP/1.0 Sonos/84.1-63110 (ZPS13)\r\n\
ST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\
USN: uuid:RINCON_7828CA1491AE01400_MR::urn:schemas-upnp-org:device:MediaRenderer:1\r\n\
X-RINCON-HOUSEHOLD: Sonos_EIFyXFHMzYBeAfsBofjVb1VGIB\r\n\r\n";
        let server = "HTTP/1.1 200 OK\r\n\
CACHE-CONTROL: max-age = 1800\r\n\
EXT:\r\n\
LOCATION: http://192.168.1.6:1400/xml/device_description.xml\r\n\
SERVER: Linux UPnP/1.0 Sonos/84.1-63110 (ZPS13)\r\n\
ST: urn:schemas-upnp-org:device:MediaServer:1\r\n\
USN: uuid:RINCON_7828CA1491AE01400_MS::urn:schemas-upnp-org:device:MediaServer:1\r\n\
X-RINCON-HOUSEHOLD: Sonos_EIFyXFHMzYBeAfsBofjVb1VGIB\r\n\r\n";

        let mut found = Vec::new();
        for datagram in [CAPTURED, renderer, server] {
            absorb(&mut found, parse(datagram, "192.168.1.6").expect("a device"));
        }
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].key.as_deref(), Some("RINCON_7828CA1491AE01400"));
    }

    /// `_MS` and `_MR` mean something only in Sonos's scheme; trimming them off
    /// anybody else's UUID would merge two devices that really are two.
    #[test]
    fn a_sub_device_suffix_is_only_trimmed_from_a_sonos_uuid() {
        assert_eq!(zone_player_of("RINCON_7828CA1491AE01400_MR"), "RINCON_7828CA1491AE01400");
        assert_eq!(zone_player_of("RINCON_7828CA1491AE01400_MS"), "RINCON_7828CA1491AE01400");
        assert_eq!(zone_player_of("RINCON_7828CA1491AE01400"), "RINCON_7828CA1491AE01400");
        assert_eq!(zone_player_of("kitchen-display_MS"), "kitchen-display_MS");
    }

    /// MiniUPnPd — the router in the test house — states its UUID with the
    /// prefix already in it and then prefixes it again. Captured off the wire;
    /// stripping once leaves a `uuid:` buried in the middle of the key.
    #[test]
    fn a_doubled_uuid_prefix_is_not_part_of_the_key() {
        let router = "HTTP/1.1 200 OK\r\n\
CACHE-CONTROL: max-age=120\r\n\
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
USN: uuid:uuid:4d696e69-444c-164e-9d42-54077d244ff5::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
EXT:\r\n\
SERVER: Netgear_Router UPnP/1.1 MiniUPnPd/2.2.0-RC0\r\n\
LOCATION: http://192.168.1.1:56688/rootDesc.xml\r\n\r\n";
        let found = parse(router, "192.168.1.1").expect("a device");
        assert_eq!(found.key.as_deref(), Some("4d696e69-444c-164e-9d42-54077d244ff5"));
        assert_eq!(found.kind, FoundKind::Unknown);
        assert_eq!(found.address, "192.168.1.1");
    }

    /// Devices answer nothing at all to a search missing a quoted `MAN` or an
    /// `MX`, and the silence is indistinguishable from a network that drops
    /// multicast — so the exact bytes are asserted.
    #[test]
    fn the_search_carries_the_headers_ssdp_requires() {
        let probe = search(SONOS_TARGET);
        assert!(probe.starts_with("M-SEARCH * HTTP/1.1\r\n"));
        assert!(probe.contains("HOST: 239.255.255.250:1900\r\n"));
        assert!(probe.contains("MAN: \"ssdp:discover\"\r\n"));
        assert!(probe.contains("MX: 2\r\n"));
        assert!(probe.contains("ST: urn:schemas-upnp-org:device:ZonePlayer:1\r\n"));
        assert!(probe.ends_with("\r\n\r\n"));
    }

    #[test]
    fn the_model_is_read_out_of_the_server_line() {
        assert_eq!(model_of("Linux UPnP/1.0 Sonos/84.1-63110 (ZPS13)").as_deref(), Some("ZPS13"));
        assert_eq!(model_of("Linux UPnP/1.0 Sonos/84.1-63110").as_deref(), None);
        assert_eq!(model_of("Some Server ()").as_deref(), None);
    }

    #[test]
    fn a_kind_travels_as_one_lowercase_word() {
        assert_eq!(FoundKind::Sonos.as_str(), "sonos");
        assert_eq!(FoundKind::FireTv.as_str(), "firetv");
        assert_eq!(FoundKind::Unknown.as_str(), "unknown");
    }

    /// A network with nothing on it is a house with no devices, not a fault.
    /// The daemon calls this on a timer and must never have an error to handle.
    #[tokio::test]
    async fn a_sweep_that_finds_nothing_returns_an_empty_list() {
        let found = sweep(Duration::from_millis(120)).await;
        assert!(found.iter().all(|entry| !entry.address.is_empty()));
    }

    /// A closed port leaves a host on the list as whatever it already was; only
    /// an accepted connection may call something a Fire TV.
    #[tokio::test]
    async fn a_host_with_no_debug_bridge_is_not_called_a_fire_tv() {
        let mut found = vec![Found {
            // Reserved for documentation by RFC 5737, so nothing answers and
            // the probe spends its whole budget, which is the case worth
            // holding to a bound.
            address: "192.0.2.1".to_owned(),
            kind: FoundKind::Unknown,
            name: None,
            key: Some("0d1a-77".to_owned()),
            household: None,
            location: None,
        }];
        upgrade_reachable_televisions(&mut found).await;
        assert_eq!(found[0].kind, FoundKind::Unknown);
    }

    /// A speaker is never probed and never reclassified, however the network
    /// answers — a Sonos does not run a debug bridge, and a sweep that renamed
    /// one would take the speakers off the page.
    #[tokio::test]
    async fn a_sonos_is_never_reclassified_by_the_probe() {
        let mut found = vec![parse(CAPTURED, "192.168.1.6").expect("a device")];
        upgrade_reachable_televisions(&mut found).await;
        assert_eq!(found[0].kind, FoundKind::Sonos);
    }
}
