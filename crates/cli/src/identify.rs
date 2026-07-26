//! Putting a name to the devices on the local network.
//!
//! `investigate` narrows a `/24` down to the devices worth looking at. That is
//! only useful if you can then walk to one and unplug it, and an address like
//! `192.168.1.25` tells nobody which box in the house that is. This module turns
//! addresses into hardware.
//!
//! Three independent questions are asked, because a device that will not answer
//! one often answers another:
//!
//! - **Who made it?** The first three bytes of its MAC address, which it cannot
//!   withhold, because the router already learned them to talk to it at all.
//! - **What does it call itself?** A reverse lookup over multicast DNS.
//! - **What does it advertise?** An SSDP search, which streaming devices answer
//!   with a product string precise enough to name the model.
//!
//! # Silence is itself evidence
//!
//! The most useful outcome here is often a device that answers *nothing* while
//! its neighbours answer freely. Ordinary consumer hardware is talkative — a
//! Fire TV announces its model over SSDP, a printer and a speaker publish mDNS
//! names. A device on the same network that publishes no name and no
//! advertisement, yet holds ports open, has gone out of its way to be hard to
//! identify. [`DeviceIdentity::is_anonymous`] reports exactly that, and it is
//! why the inventory covers every reachable device rather than only the ones
//! with a suspicious port: an anonymous device only looks anomalous next to the
//! talkative ones.

use crate::oui;
use selfhost_dns::wire::{decode_response, encode_query};
use selfhost_dns::{RecordType, reverse_name};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::process::Command;

/// What a device says about itself over SSDP.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Announcement {
    /// The `SERVER` header, which usually carries the OS and product version.
    pub server: Option<String>,
    /// The unique service name, which on streaming hardware embeds the model.
    pub unique_id: Option<String>,
}

impl Announcement {
    /// The most identifying string the device offered, if any.
    ///
    /// Prefers the `USN` when it names a product, because a `SERVER` header of
    /// `Linux/4.4.120+, UPnP/1.0` describes a kernel rather than a device, while
    /// the matching `USN` says `FIRETVSTICK2018`.
    ///
    /// Most `USN`s are a bare uuid, which names nothing at all — those fall back
    /// to the `SERVER` header rather than being printed as though they meant
    /// something.
    pub fn model_hint(&self) -> Option<&str> {
        let named_product =
            self.unique_id.as_deref().filter(|id| id.len() > 8 && !is_bare_uuid(id));
        named_product.or(self.server.as_deref())
    }
}

/// Whether an identifier is only hex digits and dashes, and so names nothing.
///
/// `4d696e69-444c-164e-9d44-54077d244ff5` identifies a service instance but
/// tells a reader nothing; `FIRETVSTICK2018-AMAZOAFTMM` names the hardware.
fn is_bare_uuid(id: &str) -> bool {
    id.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Everything known about one device on the local network.
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    /// Its address.
    pub address: Ipv4Addr,
    /// Its hardware address, as learned by the local ARP cache.
    pub mac: Option<[u8; 6]>,
    /// The vendor that registered that hardware address.
    pub vendor: Option<&'static str>,
    /// The name it publishes over multicast DNS.
    pub mdns_name: Option<String>,
    /// What it advertises over SSDP.
    pub announcement: Option<Announcement>,
}

impl DeviceIdentity {
    /// Whether the device published no name and no advertisement.
    ///
    /// Not proof of anything on its own — a device can be asleep, or simply run
    /// nothing that answers. It matters comparatively: an anonymous device
    /// sitting among neighbours that all identify themselves is the one to look
    /// at first, especially if it is also holding a port open.
    pub fn is_anonymous(&self) -> bool {
        self.mdns_name.is_none()
            && self.announcement.as_ref().and_then(Announcement::model_hint).is_none()
    }

    /// Whether the hardware address is randomised rather than assigned.
    ///
    /// Phones and laptops rotate these for privacy, so an unknown vendor here is
    /// expected rather than suspicious.
    pub fn has_randomised_mac(&self) -> bool {
        self.mac.is_some_and(oui::is_randomised)
    }

    /// A one-line description, naming whatever could actually be established.
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if let Some(vendor) = self.vendor {
            parts.push(vendor.to_owned());
        } else if self.has_randomised_mac() {
            // Phones and laptops rotate these by default. It is a privacy
            // feature, not an attempt to hide, and wording it as evasion would
            // point suspicion at ordinary hardware.
            parts.push("private Wi-Fi address, so the vendor is not knowable".to_owned());
        }
        if let Some(name) = &self.mdns_name {
            parts.push(format!("\"{name}\""));
        }
        if let Some(hint) = self.announcement.as_ref().and_then(Announcement::model_hint) {
            parts.push(hint.chars().take(60).collect());
        }
        if let Some(mac) = self.mac {
            parts.push(format_mac(mac));
        }
        if parts.is_empty() {
            return "could not be identified at all".to_owned();
        }
        parts.join(", ")
    }
}

/// Builds an inventory of every device currently reachable on the local network.
///
/// Runs the SSDP search once for the whole network rather than per device,
/// because it is a single multicast question that every device answers at once.
pub async fn survey(local: Ipv4Addr) -> Vec<DeviceIdentity> {
    let [a, b, c, _] = local.octets();
    let neighbours = arp_table().await;
    let announcements = ssdp_sweep().await;

    let addresses: Vec<Ipv4Addr> = neighbours
        .keys()
        .copied()
        .filter(|address| {
            let [x, y, z, _] = address.octets();
            (x, y, z) == (a, b, c)
        })
        .chain(announcements.keys().copied())
        .collect();

    let mut unique: Vec<Ipv4Addr> = addresses;
    unique.sort_unstable();
    unique.dedup();

    let mut tasks = tokio::task::JoinSet::new();
    for address in unique {
        let mac = neighbours.get(&address).copied();
        let announcement = announcements.get(&address).cloned();
        tasks.spawn(async move {
            DeviceIdentity {
                address,
                mac,
                vendor: mac.and_then(oui::vendor_of),
                mdns_name: mdns_name(address).await,
                announcement,
            }
        });
    }

    let mut identities = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(identity) = result {
            identities.push(identity);
        }
    }
    identities.sort_by_key(|identity| identity.address);
    identities
}

/// Reads the operating system's ARP cache.
///
/// The cache is authoritative for "who is actually on this network right now":
/// the machine cannot have exchanged a packet with a device without learning its
/// hardware address. A port sweep populates it as a side effect, so running this
/// afterwards sees every host that answered.
///
/// Shells out because there is no portable system call for this, and the command
/// is a built-in on all three target platforms rather than something to install.
pub async fn arp_table() -> BTreeMap<Ipv4Addr, [u8; 6]> {
    // `ip neigh` is the modern Linux form; `arp` is absent on distributions that
    // have dropped net-tools, so both are tried.
    let attempts: [(&str, &[&str]); 2] = if cfg!(windows) {
        [("arp", &["-a"]), ("arp", &["-a"])]
    } else {
        [("arp", &["-an"]), ("ip", &["neigh", "show"])]
    };

    for (program, args) in attempts {
        let Ok(output) = Command::new(program).args(args).output().await else { continue };
        let table = parse_arp_table(&String::from_utf8_lossy(&output.stdout));
        if !table.is_empty() {
            return table;
        }
    }
    BTreeMap::new()
}

/// Extracts address/hardware pairs from the output of `arp` or `ip neigh`.
///
/// Written against the shape all three platforms share — one device per line,
/// carrying both an IPv4 address and a hardware address — rather than against
/// any one platform's columns, which differ in order, punctuation, and whether
/// octets keep their leading zeros.
fn parse_arp_table(text: &str) -> BTreeMap<Ipv4Addr, [u8; 6]> {
    let mut table = BTreeMap::new();
    for line in text.lines() {
        let mut address = None;
        let mut mac = None;
        for token in line.split_whitespace() {
            let token = token.trim_matches(['(', ')', ',']);
            if address.is_none() {
                address = token.parse::<Ipv4Addr>().ok();
            }
            if mac.is_none() {
                mac = parse_mac(token);
            }
        }
        // The cache also holds the broadcast and multicast addresses the
        // machine talks to. They are not devices, and letting them through
        // produces findings against hardware that does not exist.
        if let (Some(address), Some(mac)) = (address, mac)
            && !is_group_address(mac)
            && !address.is_broadcast()
            && !address.is_multicast()
            && address.octets()[3] != 0
            && address.octets()[3] != 255
        {
            table.insert(address, mac);
        }
    }
    table
}

/// Whether a hardware address addresses a group rather than one interface.
///
/// The low bit of the first byte is the individual/group flag. Broadcast
/// (`ff:ff:ff:ff:ff:ff`) and every multicast address have it set, and no real
/// network interface does.
fn is_group_address(mac: [u8; 6]) -> bool {
    mac[0] & 0b0000_0001 != 0
}

/// Parses a hardware address written with either `:` or `-` separators.
///
/// Accepts octets without leading zeros, because macOS prints `14:a:c5:...`
/// where Linux and Windows print `14:0a:c5:...`; rejecting the short form would
/// silently identify nothing on macOS.
fn parse_mac(token: &str) -> Option<[u8; 6]> {
    let separator = if token.contains(':') { ':' } else { '-' };
    let mut octets = [0_u8; 6];
    let mut count = 0;
    for part in token.split(separator) {
        if part.is_empty() || part.len() > 2 || count == 6 {
            return None;
        }
        octets[count] = u8::from_str_radix(part, 16).ok()?;
        count += 1;
    }
    (count == 6).then_some(octets)
}

/// Formats a hardware address in the conventional lowercase colon form.
pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter().map(|byte| format!("{byte:02x}")).collect::<Vec<_>>().join(":")
}

/// Asks the network, over multicast DNS, what name a device answers to.
///
/// A one-shot query from an ephemeral port, which responders answer directly
/// rather than by multicast, so nothing needs to join a multicast group.
pub async fn mdns_name(address: Ipv4Addr) -> Option<String> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    // The transaction id only has to be stable per query; the address supplies
    // enough variation and avoids pulling in a random number generator.
    let [_, _, c, d] = address.octets();
    let query = encode_query(u16::from_be_bytes([c, d]) | 1, &reverse_name(address), RecordType::Ptr).ok()?;
    socket.send_to(&query, "224.0.0.251:5353").await.ok()?;

    let listen = async {
        let mut buffer = vec![0_u8; 2048];
        loop {
            let (read, from) = socket.recv_from(&mut buffer).await.ok()?;
            // Only the device itself can say what it is called; another
            // responder answering for it would be a different claim entirely.
            if from.ip() != address {
                continue;
            }
            if let Ok(response) = decode_response(&buffer[..read])
                && let Some(name) = response.names().into_iter().next()
            {
                return Some(name.trim_end_matches('.').to_owned());
            }
        }
    };

    tokio::time::timeout(Duration::from_millis(1500), listen).await.ok().flatten()
}

/// Asks every device on the network to describe itself over SSDP.
///
/// One multicast search, collecting replies until the window closes. Streaming
/// devices answer with a product string — this is what distinguishes a Fire TV
/// Stick from an anonymous box holding a proxy port open.
pub async fn ssdp_sweep() -> BTreeMap<Ipv4Addr, Announcement> {
    let mut found = BTreeMap::new();
    let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await else { return found };

    let search = b"M-SEARCH * HTTP/1.1\r\n\
HOST:239.255.255.250:1900\r\n\
ST:ssdp:all\r\n\
MX:2\r\n\
MAN:\"ssdp:discover\"\r\n\r\n";
    if socket.send_to(search, "239.255.255.250:1900").await.is_err() {
        return found;
    }

    let collect = async {
        let mut buffer = vec![0_u8; 4096];
        loop {
            let Ok((read, from)) = socket.recv_from(&mut buffer).await else { return };
            let std::net::IpAddr::V4(address) = from.ip() else { continue };
            let announcement = parse_announcement(&String::from_utf8_lossy(&buffer[..read]));
            // Devices answer once per advertised service; keep the reply that
            // names a product over the ones that only name a protocol.
            let entry = found.entry(address).or_insert_with(Announcement::default);
            if entry.server.is_none() {
                entry.server = announcement.server;
            }
            if entry.unique_id.is_none() || announcement.unique_id.as_ref().is_some_and(|id| id.len() > 20) {
                if let Some(id) = announcement.unique_id {
                    entry.unique_id = Some(id);
                }
            }
        }
    };

    let _ = tokio::time::timeout(Duration::from_secs(4), collect).await;
    found
}

/// Pulls the identifying headers out of an SSDP reply.
fn parse_announcement(text: &str) -> Announcement {
    let mut announcement = Announcement::default();
    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        match key.trim().to_ascii_uppercase().as_str() {
            "SERVER" => announcement.server = Some(value.to_owned()),
            "USN" => {
                // The uuid carries the product; the `::urn:...` suffix repeats
                // the service type and is noise here.
                let id = value.split("::").next().unwrap_or(value);
                announcement.unique_id = Some(id.trim_start_matches("uuid:").to_owned());
            }
            _ => {}
        }
    }
    announcement
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardware_addresses_parse_in_every_platform_spelling() {
        let expected = [0x14, 0x0a, 0xc5, 0x23, 0x51, 0x20];
        // Linux and Windows pad each octet; macOS does not.
        assert_eq!(parse_mac("14:0a:c5:23:51:20"), Some(expected));
        assert_eq!(parse_mac("14-0a-c5-23-51-20"), Some(expected));
        assert_eq!(parse_mac("14:a:c5:23:51:20"), Some(expected));
    }

    #[test]
    fn things_that_are_not_hardware_addresses_are_rejected() {
        assert_eq!(parse_mac("192.168.1.25"), None);
        assert_eq!(parse_mac("en0"), None);
        assert_eq!(parse_mac("14:0a:c5:23:51"), None, "five octets is not a MAC");
        assert_eq!(parse_mac("14:0a:c5:23:51:20:99"), None, "seven octets is not a MAC");
        assert_eq!(parse_mac("zz:0a:c5:23:51:20"), None);
        assert_eq!(parse_mac("(incomplete)"), None);
    }

    #[test]
    fn the_macos_arp_table_is_read() {
        // Real `arp -an` output, including the incomplete entries that dominate
        // it after a sweep and must not become phantom devices.
        let text = "? (192.168.1.1) at 54:7:7d:24:4f:f5 on en0 ifscope [ethernet]\n\
                    ? (192.168.1.3) at (incomplete) on en0 ifscope [ethernet]\n\
                    ? (192.168.1.25) at 14:a:c5:23:51:20 on en0 ifscope [ethernet]\n";
        let table = parse_arp_table(text);
        assert_eq!(table.len(), 2, "incomplete entries must not be counted as devices");
        assert_eq!(table[&Ipv4Addr::new(192, 168, 1, 1)], [0x54, 0x07, 0x7d, 0x24, 0x4f, 0xf5]);
        assert_eq!(table[&Ipv4Addr::new(192, 168, 1, 25)], [0x14, 0x0a, 0xc5, 0x23, 0x51, 0x20]);
    }

    #[test]
    fn broadcast_and_multicast_entries_are_not_devices() {
        // Found by running this for real: 192.168.1.255 was reported as a
        // device with a hidden vendor, and then raised as a finding. There is
        // no such machine.
        let text = "? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n\
                    mdns.mcast.net (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent\n\
                    ? (192.168.1.25) at 14:a:c5:23:51:20 on en0 ifscope [ethernet]\n";
        let table = parse_arp_table(text);
        assert_eq!(table.keys().collect::<Vec<_>>(), vec![&Ipv4Addr::new(192, 168, 1, 25)]);
    }

    #[test]
    fn a_bare_uuid_is_not_offered_as_a_model_name() {
        // The router advertised `4d696e69-444c-164e-9d44-54077d244ff5`, which
        // was printed as though it identified the hardware. It identifies a
        // service instance and tells a reader nothing.
        let uuid_only = Announcement {
            server: Some("Netgear_Router UPnP/1.1".to_owned()),
            unique_id: Some("4d696e69-444c-164e-9d44-54077d244ff5".to_owned()),
        };
        assert_eq!(uuid_only.model_hint(), Some("Netgear_Router UPnP/1.1"));

        // A product name still wins over the SERVER header.
        let product = Announcement {
            server: Some("Linux/4.4.120+, UPnP/1.0".to_owned()),
            unique_id: Some("NFANDROID2-PRV-FIRETVSTICK2018-AMAZOAFTMM".to_owned()),
        };
        assert!(product.model_hint().unwrap().contains("FIRETVSTICK2018"));
    }

    #[test]
    fn the_linux_and_windows_arp_tables_are_read() {
        let linux = "192.168.1.20 dev wlan0 lladdr 00:86:21:cd:70:a9 REACHABLE\n";
        assert_eq!(
            parse_arp_table(linux)[&Ipv4Addr::new(192, 168, 1, 20)],
            [0x00, 0x86, 0x21, 0xcd, 0x70, 0xa9]
        );

        let windows = "  192.168.1.20          00-86-21-cd-70-a9     dynamic\n";
        assert_eq!(
            parse_arp_table(windows)[&Ipv4Addr::new(192, 168, 1, 20)],
            [0x00, 0x86, 0x21, 0xcd, 0x70, 0xa9]
        );
    }

    #[test]
    fn an_ssdp_reply_yields_the_product_rather_than_the_kernel() {
        // Real reply from a Fire TV Stick. The SERVER header names a kernel,
        // which identifies nothing; the USN names the actual model.
        let reply = "HTTP/1.1 200 OK\r\n\
                     LOCATION: http://192.168.1.4:9080\r\n\
                     SERVER: Linux/4.4.120+, UPnP/1.0, Portable SDK for UPnP devices\r\n\
                     USN: uuid:NFANDROID2-PRV-FIRETVSTICK2018-AMAZOAFTMM-17461-8D69B75C::upnp:rootdevice\r\n\r\n";
        let announcement = parse_announcement(reply);
        assert_eq!(
            announcement.unique_id.as_deref(),
            Some("NFANDROID2-PRV-FIRETVSTICK2018-AMAZOAFTMM-17461-8D69B75C"),
            "the ::urn suffix is noise and must be trimmed"
        );
        let hint = announcement.model_hint().expect("a product was advertised");
        assert!(hint.contains("FIRETVSTICK2018"), "model hint {hint:?} lost the product name");
    }

    #[test]
    fn a_device_that_publishes_nothing_is_reported_as_anonymous() {
        // 192.168.1.25 as actually observed: Amazon hardware, no mDNS name, no
        // SSDP advertisement. Its silence next to talkative neighbours is the
        // finding, so this must not read as "nothing to see here".
        let silent = DeviceIdentity {
            address: Ipv4Addr::new(192, 168, 1, 25),
            mac: Some([0x14, 0x0a, 0xc5, 0x23, 0x51, 0x20]),
            vendor: Some("Amazon"),
            mdns_name: None,
            announcement: None,
        };
        assert!(silent.is_anonymous());
        assert!(silent.summary().contains("Amazon"), "the vendor is the only lead — it must survive");

        let talkative = DeviceIdentity {
            mdns_name: Some("firestick.local".to_owned()),
            ..silent.clone()
        };
        assert!(!talkative.is_anonymous());
    }

    #[test]
    fn a_randomised_address_is_explained_rather_than_left_blank() {
        let phone = DeviceIdentity {
            address: Ipv4Addr::new(192, 168, 1, 31),
            mac: Some([0x62, 0x94, 0x73, 0xb2, 0x3b, 0x25]),
            vendor: None,
            mdns_name: None,
            announcement: None,
        };
        assert!(phone.has_randomised_mac());
        assert!(
            phone.summary().contains("private Wi-Fi address"),
            "an unknown vendor on a randomised MAC is expected, and saying so prevents a false lead"
        );
        assert!(
            !phone.summary().contains("hidden"),
            "rotating a MAC is a privacy default, not evasion — wording it as evasion points \
             suspicion at ordinary hardware"
        );
    }

    #[test]
    fn an_empty_announcement_offers_no_hint() {
        assert_eq!(Announcement::default().model_hint(), None);
        // A bare uuid names no product, so it is not a model hint.
        let bare = Announcement { server: None, unique_id: Some("1234".to_owned()) };
        assert_eq!(bare.model_hint(), None);
    }
}
