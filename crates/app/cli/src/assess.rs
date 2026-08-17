//! Deciding which device is responsible, rather than listing candidates.
//!
//! A diagnostic that ends with eleven devices and a shrug has not diagnosed
//! anything — it has re-run the manual investigation and handed back the same
//! work. This module exists to finish the job: weigh what was observed about
//! each device against what that device is *supposed* to be, and come out the
//! other side with a ranking and a next action.
//!
//! # The judgement that does the work
//!
//! Almost no observation means anything on its own. A SOCKS proxy is
//! unremarkable on a laptop and damning on a speaker. A device publishing no
//! name is meaningless on a network where nothing publishes names, and pointed
//! on one where everything else does. So nothing here maps an observation
//! straight to a verdict; every rule combines an observation with the context
//! that gives it meaning, and says so in words the reader can check.
//!
//! # What clears a device, and what does not
//!
//! Only positive evidence clears anything. A refusal does not: residential
//! proxy malware is outbound-connected — it dials a controller and relays down
//! that tunnel, so it refuses probes from the LAN exactly as innocent hardware
//! does. A device is [`Standing::Consistent`] when it behaves as its hardware
//! should, never merely because a probe was turned away.

use crate::identify::DeviceIdentity;
use crate::investigate::{LanDevice, LanSurvey, PortMapping};
use std::net::Ipv4Addr;

/// How strongly a device is implicated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Standing {
    /// Behaves exactly as this kind of hardware should.
    Consistent,
    /// Nothing points at it, but nothing rules it out either.
    Unresolved,
    /// The strongest candidate. Act on this one first.
    PrimeSuspect,
    /// Proven to be relaying. Not a lead — a cause.
    Responsible,
}

impl Standing {
    /// A short label for the standing.
    pub fn label(self) -> &'static str {
        match self {
            Standing::Consistent => "behaving normally",
            Standing::Unresolved => "not ruled out",
            Standing::PrimeSuspect => "PRIME SUSPECT",
            Standing::Responsible => "RESPONSIBLE",
        }
    }
}

/// What kind of thing a piece of hardware is.
///
/// This is the context that turns an observation into evidence. It is a
/// judgement about a vendor's product line, not a fact about a device, so it
/// only ever shifts how much weight an observation carries — it never decides
/// anything by itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareClass {
    /// Fixed-function consumer hardware: streaming sticks, speakers, cameras,
    /// printers. The owner installs no software, so a proxy running on one had
    /// to arrive some other way.
    Appliance,
    /// A computer, where a proxy may be something the owner deliberately runs.
    GeneralPurpose,
    /// Routers and access points, which relay traffic as their actual job.
    Network,
    /// Not recognised, so it lends no context either way.
    Unrecognised,
}

/// Classifies a vendor's hardware.
///
/// Deliberately conservative: vendors with mixed product lines are left
/// [`HardwareClass::Unrecognised`] rather than guessed at, because a wrong class
/// here would quietly weight the whole assessment.
pub fn hardware_class(vendor: Option<&str>) -> HardwareClass {
    match vendor {
        Some(
            "Amazon" | "Roku" | "Sonos" | "Nintendo" | "Brother" | "Ring" | "Wyze" | "Arlo"
            | "ecobee" | "Nest" | "Philips Hue" | "Belkin/Wemo" | "Tuya" | "Vizio" | "Hisense"
            | "TCL" | "Sonoff/ITEAD" | "Anker/eufy",
        ) => HardwareClass::Appliance,
        Some("Apple" | "Dell" | "HP" | "Lenovo" | "Microsoft" | "Intel" | "Raspberry Pi") => {
            HardwareClass::GeneralPurpose
        }
        Some(
            "Netgear" | "eero" | "Ubiquiti" | "TP-Link" | "Linksys" | "D-Link" | "Cisco" | "Arris"
            | "Technicolor",
        ) => HardwareClass::Network,
        _ => HardwareClass::Unrecognised,
    }
}

/// A service pattern a vendor's own firmware is known to produce.
///
/// # Why this table has to exist
///
/// Weighing "runs a proxy" against "is an appliance" is right in general and
/// wrong for any appliance whose maker ships a proxy. An Amazon Echo listens on
/// 1080 and 8888 out of the box, so the rule that correctly flags a proxy on a
/// speaker will accuse every Echo on every network — and the reader, trusting
/// it, factory-resets a device that was fine.
///
/// That is the same defect this tool started with, pointing the other way. A
/// refusal reported as innocence and stock behaviour reported as guilt are both
/// a verdict outrunning the evidence.
///
/// # What a match does and does not mean
///
/// Matching says *this observation is explained*, not *this device is clean*.
/// The check runs after the open-relay test, so a device caught actually
/// relaying is never excused by it — hardware behaving like its documentation
/// stops being evidence; hardware caught relaying is still caught.
#[derive(Debug, Clone, Copy)]
pub struct StockBehaviour {
    /// The vendor whose firmware does this.
    pub vendor: &'static str,
    /// The product it identifies.
    pub product: &'static str,
    /// Ports the stock firmware is documented to hold open.
    pub ports: &'static [u16],
    /// Whether it also serves HTTP on an unpredictable high-numbered port.
    pub dynamic_http: bool,
    /// Where this was established, so a reader can check it rather than trust it.
    pub source: &'static str,
}

/// Stock service patterns this tool recognises.
///
/// Deliberately short. Every entry suppresses evidence, so each one needs a
/// source somebody can go and read, and a fingerprint specific enough that only
/// the product it names can match it.
const STOCK_BEHAVIOURS: [StockBehaviour; 1] = [StockBehaviour {
    vendor: "Amazon",
    product: "Amazon Echo / Alexa device",
    // 1080 carries audio-group traffic between Alexa devices; 8888 is reported
    // alongside it on every Echo scan that mentions either.
    ports: &[1080, 8888],
    dynamic_http: true,
    source: "reported on r/AmazonEchoDev and the Amazon device forum, and in an \
             IACIS scan of an Echo Dot (2021); a 2025 Echo Dot pentest saw the same \
             high-numbered HTTP port",
}];

/// The stock pattern a device matches, if the services it exposes are entirely
/// accounted for by one.
///
/// Requires *every* exposed service to be explained. A device that matches the
/// pattern and then does something extra is not a match, because the extra
/// thing is exactly what would matter.
pub fn stock_behaviour(
    identity: &DeviceIdentity,
    device: Option<&LanDevice>,
) -> Option<StockBehaviour> {
    let vendor = identity.vendor?;
    let known = STOCK_BEHAVIOURS.iter().find(|stock| stock.vendor == vendor)?;

    // A device exposing nothing has nothing to explain, and claiming it matches
    // a product would put a name on hardware on no evidence at all.
    let device = device.filter(|device| !device.open.is_empty())?;

    let all_explained = device.open.iter().all(|open| {
        known.ports.contains(&open.port)
            || (known.dynamic_http
                && open.port >= 49152
                && matches!(open.nature, crate::investigate::ServiceNature::HttpServer { .. }))
    });

    all_explained.then_some(*known)
}

/// One device, judged.
#[derive(Debug, Clone)]
pub struct Assessment {
    /// Its address.
    pub address: Ipv4Addr,
    /// What the hardware turned out to be, in plain words.
    pub what_it_is: String,
    /// How strongly it is implicated.
    pub standing: Standing,
    /// The reasoning, each line checkable against what was observed.
    pub because: Vec<String>,
    /// The one thing that would settle this device, when anything would.
    pub decisive_test: Option<String>,
}

/// The whole network, judged.
#[derive(Debug, Clone)]
pub struct Conclusion {
    /// What the evidence adds up to.
    pub summary: String,
    /// The single next action worth taking.
    pub next_step: String,
    /// Devices that need attention, strongest first.
    pub notable: Vec<Assessment>,
    /// Devices that behave as their hardware should, counted rather than listed.
    pub consistent: Vec<Assessment>,
}

/// Weights. Chosen so that no single circumstantial signal reaches suspicion on
/// its own — it takes a combination, which is what actually distinguishes a
/// compromised appliance from an unusual but innocent one.
const RUNS_PROXY_ON_APPLIANCE: u32 = 4;
const RUNS_PROXY_ON_UNKNOWN_HARDWARE: u32 = 3;
const RUNS_PROXY_ON_COMPUTER: u32 = 1;
const NON_STANDARD_PROTOCOL: u32 = 2;
const ANONYMOUS_AMONG_TALKATIVE: u32 = 1;
const FORWARDED_FROM_THE_INTERNET: u32 = 3;
const LISTENS_FOR_MAIL: u32 = 4;
const EXPOSED_SERVICE_ON_APPLIANCE: u32 = 2;
/// The score at which a device stops being one of several and becomes the one
/// to act on.
const SUSPECT_THRESHOLD: u32 = 4;

/// Judges the local network and returns what to do about it.
///
/// Pure: everything it needs was already measured, so the reasoning can be
/// tested without a network.
pub fn assess(survey: &LanSurvey, mappings: &[PortMapping], local: Ipv4Addr) -> Conclusion {
    // Anonymity only means something relative to the neighbours. On a network
    // where nothing publishes a name, publishing no name is just normal.
    let talkative = survey.inventory.iter().filter(|identity| !identity.is_anonymous()).count();
    let network_is_talkative = talkative * 2 >= survey.inventory.len() && talkative > 1;

    let mut assessments: Vec<Assessment> = survey
        .inventory
        .iter()
        .map(|identity| {
            let device = survey.devices.iter().find(|device| device.address == identity.address);
            judge(identity, device, mappings, local, network_is_talkative)
        })
        .collect();
    assessments.extend(forwarded_but_unseen(survey, mappings, local));

    assessments.sort_by(|a, b| b.standing.cmp(&a.standing).then(a.address.cmp(&b.address)));
    let (notable, consistent): (Vec<_>, Vec<_>) =
        assessments.into_iter().partition(|a| a.standing > Standing::Consistent);

    let summary = summarise(&notable, &consistent);
    let next_step = next_step(&notable);
    Conclusion { summary, next_step, notable, consistent }
}

/// Addresses the router forwards to that answered nothing at all.
///
/// # Why an address with no device behind it is worth a line
///
/// The sweep and the router's forwarding table are two separate observations,
/// and the interesting case is the one where they disagree. A mapping exists
/// because something asked for it — almost always over UPnP, which any program
/// can use without telling anyone — so an address holding a hole open while
/// answering no probe, publishing no name, and not even appearing in the ARP
/// cache is the one address on the network that went out of its way to be
/// reachable and then said nothing.
///
/// It is [`Standing::Unresolved`] rather than a suspicion, because a mapping
/// with no expiry outlives whatever created it: a laptop that opened one and
/// left the house leaves exactly this trace. The mapping's lease is what tells
/// the two apart, so the reasoning reports which case this is rather than
/// assuming the pessimistic one.
fn forwarded_but_unseen(
    survey: &LanSurvey,
    mappings: &[PortMapping],
    local: Ipv4Addr,
) -> Vec<Assessment> {
    let seen: Vec<Ipv4Addr> = survey
        .inventory
        .iter()
        .map(|identity| identity.address)
        .chain(survey.devices.iter().map(|device| device.address))
        .chain(std::iter::once(local))
        .collect();

    let mut unseen: Vec<Ipv4Addr> = mappings
        .iter()
        .filter_map(|mapping| mapping.internal_client.parse::<Ipv4Addr>().ok())
        .filter(|address| !seen.contains(address))
        .collect();
    unseen.sort();
    unseen.dedup();

    unseen
        .into_iter()
        .map(|address| {
            let theirs: Vec<&PortMapping> = mappings
                .iter()
                .filter(|mapping| mapping.internal_client == address.to_string())
                .collect();
            let ports = theirs
                .iter()
                .map(|mapping| format!("{}/{}", mapping.external_port, mapping.protocol))
                .collect::<Vec<_>>()
                .join(", ");

            let mut because = vec![format!(
                "The router forwards {ports} to this address, so something there asked for a hole \
                 through the firewall — but it answered nothing when the network was swept: no \
                 open port, no name, and no entry in this machine's ARP cache.",
            )];
            if theirs.iter().any(|mapping| mapping.description.to_ascii_lowercase().contains("teredo"))
            {
                because.push(
                    "The mapping calls itself Teredo, which is an IPv6 tunnel. While it is open \
                     that device has a public IPv6 address of its own, so \"the router forwards \
                     nothing\" does not cover it — it is reachable from the internet by a route \
                     the IPv4 forwarding table does not describe."
                        .to_owned(),
                );
            }
            // The lease is the only evidence in the table about *when*. A hole
            // with no expiry survives the device that punched it, so it dates
            // nothing; one still counting down had to be renewed to be here.
            // One expiring mapping is enough: it had to be renewed to still be
            // here, whatever the permanent ones alongside it prove nothing about.
            let expiring = theirs
                .iter()
                .filter(|mapping| !mapping.never_expires())
                .map(|mapping| mapping.lease_seconds)
                .min();
            because.push(match expiring {
                None => "This is not an accusation, and the mapping does not date itself: it has \
                         no expiry, so the router will hold it until something deletes it. A \
                         device that punched this hole and then left the network leaves exactly \
                         this trace, indefinitely."
                    .to_owned(),
                Some(lease) => format!(
                    "The mapping still has {lease}s to run, and a lease has to be renewed before it \
                     lapses — so something at this address was awake within the last {lease} \
                     seconds. This is not a leftover from a device that has gone."
                ),
            });

            Assessment {
                address,
                what_it_is: "did not answer the sweep at all".to_owned(),
                standing: Standing::Unresolved,
                because,
                decisive_test: Some(format!(
                    "The router's DHCP client list names whatever holds the {address} lease. If \
                     nothing holds it, the mapping is stale and can be deleted; if something does, \
                     it is the one device here that asked to be reachable and then stayed quiet."
                )),
            }
        })
        .collect()
}

/// Judges one device against what its hardware is supposed to do.
fn judge(
    identity: &DeviceIdentity,
    device: Option<&LanDevice>,
    mappings: &[PortMapping],
    local: Ipv4Addr,
    network_is_talkative: bool,
) -> Assessment {
    let class = hardware_class(identity.vendor);
    let what_it_is = identity.summary();
    let mut because = Vec::new();
    let mut score = 0;

    if identity.address == local {
        because.push("This is the machine running the diagnostic.".to_owned());
    }

    // --- proven relaying ---------------------------------------------------
    if let Some(relay) = device.and_then(LanDevice::open_relay) {
        because.push(format!(
            "Port {} {} — it carried traffic for a stranger, which is the behaviour that earns a \
             blocklisting.",
            relay.port,
            relay.nature.describe()
        ));
        return Assessment {
            address: identity.address,
            what_it_is,
            standing: Standing::Responsible,
            because,
            decisive_test: Some(
                "Nothing further needs establishing. Take it off the network now.".to_owned(),
            ),
        };
    }

    // --- hardware doing what its maker shipped it to do --------------------
    //
    // Checked after the relay test above, never before: behaviour matching the
    // documentation stops being evidence, but a device caught relaying stays
    // caught.
    if let Some(stock) = stock_behaviour(identity, device) {
        let ports =
            stock.ports.iter().map(u16::to_string).collect::<Vec<_>>().join(" and ");
        because.push(format!(
            "The services it exposes are what a {} ships with — ports {ports} are stock on this \
             hardware ({}). Nothing here needs explaining, and it did not relay for us. Verify \
             the device really is one if you do not recognise it.",
            stock.product, stock.source
        ));
        return Assessment {
            address: identity.address,
            what_it_is: format!("{what_it_is} — matches {}", stock.product),
            standing: Standing::Consistent,
            because,
            decisive_test: None,
        };
    }

    // --- proxy software, weighed against what the device is ----------------
    let proxies = device.map(LanDevice::proxy_software).unwrap_or_default();
    if !proxies.is_empty() {
        let ports =
            proxies.iter().map(|open| open.port.to_string()).collect::<Vec<_>>().join(", ");
        let detail = proxies.iter().map(|open| open.nature.describe()).collect::<Vec<_>>().join("; ");

        score += match class {
            HardwareClass::Appliance => {
                because.push(format!(
                    "It is running proxy software on port {ports} ({detail}). This is \
                     fixed-function consumer hardware — nothing the owner installs runs on it, so \
                     a proxy had to arrive some other way."
                ));
                RUNS_PROXY_ON_APPLIANCE
            }
            HardwareClass::Unrecognised => {
                because.push(format!(
                    "It is running proxy software on port {ports} ({detail}), and the hardware is \
                     not recognised, so there is nothing to say this is expected."
                ));
                RUNS_PROXY_ON_UNKNOWN_HARDWARE
            }
            HardwareClass::GeneralPurpose => {
                because.push(format!(
                    "It is running proxy software on port {ports} ({detail}). On a computer this \
                     is often deliberate — Tor, a development tool, a VPN client — so it is only \
                     worth chasing if you do not recognise it."
                ));
                RUNS_PROXY_ON_COMPUTER
            }
            HardwareClass::Network => {
                because.push(format!(
                    "It is running proxy software on port {ports} ({detail}), which is what a \
                     router is for."
                ));
                0
            }
        };

        if proxies.iter().any(|open| open.nature.is_non_standard()) {
            because.push(
                "Its replies use codes the protocol does not define, so this is a custom build \
                 rather than stock software."
                    .to_owned(),
            );
            score += NON_STANDARD_PROTOCOL;
        }

        because.push(
            "It refused to relay for us, which does NOT clear it: proxy malware for hire is \
             outbound-connected, dialling its controller and relaying down that tunnel, so it \
             turns away probes from the LAN exactly as innocent hardware would."
                .to_owned(),
        );
    }

    // --- other exposed services, weighed the same way ----------------------
    let others: Vec<&crate::investigate::OpenPort> = device
        .map(|device| device.open.iter().filter(|open| !open.nature.is_proxy_software()).collect())
        .unwrap_or_default();
    if let Some(mail) = others.iter().find(|open| open.port == 25) {
        because.push(format!(
            "It is listening on port 25 ({}). A machine accepting mail here is the most direct \
             way an address earns a listing, so establish what this is.",
            mail.nature.describe()
        ));
        score += LISTENS_FOR_MAIL;
    }
    if !others.is_empty() && class == HardwareClass::Appliance {
        let ports = others
            .iter()
            .filter(|open| open.port != 25)
            .map(|open| format!("{} ({})", open.port, open.nature.describe()))
            .collect::<Vec<_>>();
        if !ports.is_empty() {
            because.push(format!(
                "It also exposes {}, which fixed-function consumer hardware has no need for.",
                ports.join(", ")
            ));
            score += EXPOSED_SERVICE_ON_APPLIANCE;
        }
    }

    // --- reachable from outside -------------------------------------------
    let forwarded: Vec<&PortMapping> = mappings
        .iter()
        .filter(|mapping| mapping.internal_client == identity.address.to_string())
        .filter(|mapping| mapping.exposes_abusable_service())
        .collect();
    if !forwarded.is_empty() {
        let ports =
            forwarded.iter().map(|m| m.external_port.to_string()).collect::<Vec<_>>().join(", ");
        because.push(format!(
            "The router forwards port {ports} from the internet to this device, so anyone can \
             reach it directly."
        ));
        score += FORWARDED_FROM_THE_INTERNET;
    }

    // --- silence, which corroborates but never initiates --------------------
    //
    // Publishing no name is not a fault. Half the devices in a house are asleep
    // or run nothing that answers, and raising every one of them buries the
    // finding that matters under a list the reader has to sift themselves. It
    // counts only where something else already points at the device.
    if score > 0 && identity.is_anonymous() && network_is_talkative && identity.address != local {
        because.push(
            "It also publishes no name and advertises nothing, while the rest of the network \
             identifies itself freely, so there is nothing to check it against."
                .to_owned(),
        );
        score += ANONYMOUS_AMONG_TALKATIVE;
    }

    let standing = if score >= SUSPECT_THRESHOLD {
        Standing::PrimeSuspect
    } else if score > 0 {
        Standing::Unresolved
    } else {
        if because.is_empty() {
            because.push(match class {
                HardwareClass::Appliance | HardwareClass::Network => {
                    "It identifies itself and runs nothing it should not.".to_owned()
                }
                _ => "Nothing about it stands out.".to_owned(),
            });
        }
        Standing::Consistent
    };

    let decisive_test = match standing {
        Standing::PrimeSuspect => Some(format!(
            "Power this device off at the wall, leave it off, and watch the router's log of \
             blocked outbound port 25. If the attempts stop, it was {}. Nothing testable from \
             this machine can settle it, because outbound-connected malware never answers us.",
            identity.address
        )),
        Standing::Unresolved if !proxies.is_empty() => Some(
            "Work out what this proxy is for. If you did not set it up deliberately, treat it as \
             a suspect."
                .to_owned(),
        ),
        _ => None,
    };

    Assessment { address: identity.address, what_it_is, standing, because, decisive_test }
}

/// States what the evidence adds up to across the whole network.
fn summarise(notable: &[Assessment], consistent: &[Assessment]) -> String {
    let total = notable.len() + consistent.len();
    let responsible: Vec<&Assessment> =
        notable.iter().filter(|a| a.standing == Standing::Responsible).collect();
    if !responsible.is_empty() {
        let addresses =
            responsible.iter().map(|a| a.address.to_string()).collect::<Vec<_>>().join(", ");
        return format!("Found it: {addresses} is relaying traffic for strangers.");
    }

    let suspects: Vec<&Assessment> =
        notable.iter().filter(|a| a.standing == Standing::PrimeSuspect).collect();
    match suspects.len() {
        0 if notable.is_empty() => format!(
            "All {total} devices behave as their hardware should. Nothing on this network \
             explains a listing, which does not mean nothing is wrong — it means the cause is not \
             visible from here."
        ),
        0 => format!(
            "Nothing is implicated outright. {} of {total} devices could not be fully ruled out.",
            notable.len()
        ),
        1 => format!(
            "One device out of {total} stands out: {} — {}.",
            suspects[0].address, suspects[0].what_it_is
        ),
        count => format!(
            "{count} devices out of {total} stand out: {}.",
            suspects.iter().map(|a| a.address.to_string()).collect::<Vec<_>>().join(", ")
        ),
    }
}

/// The single next action, chosen from what the evidence supports.
///
/// One action, not a checklist. Where the LAN cannot settle the question — which
/// is the usual case, because outbound-connected malware never answers a probe —
/// this says so and names the vantage point that can.
fn next_step(notable: &[Assessment]) -> String {
    if let Some(responsible) = notable.iter().find(|a| a.standing == Standing::Responsible) {
        return format!(
            "Take {} off the network now, then factory-reset it. Delist only once it is gone, \
             because a listing returns if the behaviour has not stopped.",
            responsible.address
        );
    }

    let suspects: Vec<&Assessment> =
        notable.iter().filter(|a| a.standing == Standing::PrimeSuspect).collect();
    let router_step = "In the router, block outbound TCP 25 for all devices with logging turned \
                       on. That stops any spam immediately, and the log then names the internal \
                       address that tried to send — which is the only vantage point that can see \
                       it, since a device relaying for its controller never answers us.";
    // The scan can only ever report what answered it. Naming the device that
    // answers nothing takes a different vantage point, so the reader is sent
    // there rather than left with a shrug.
    let watch_step = "Then run `selfhost watch-dns` and point the router's DHCP DNS at this \
                      machine. Proxy software has to look its controller up by name before it can \
                      relay anything, and that lookup names the device.";

    match suspects.first() {
        Some(suspect) => format!(
            "{router_step} Power off {} first: it is the strongest candidate, and if the log stays \
             quiet while it is off, that is your answer. {watch_step}",
            suspect.address
        ),
        None => format!("{router_step} {watch_step}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identify::Announcement;
    use crate::investigate::{OpenPort, ServiceNature};

    fn identity(last: u8, vendor: Option<&'static str>, name: Option<&str>) -> DeviceIdentity {
        DeviceIdentity {
            address: Ipv4Addr::new(192, 168, 1, last),
            mac: Some([0x14, 0x0a, 0xc5, 0x23, 0x51, last]),
            vendor,
            mdns_name: name.map(str::to_owned),
            announcement: name.map(|n| Announcement {
                server: None,
                unique_id: Some(format!("PRODUCT-{n}")),
            }),
        }
    }

    fn device(last: u8, nature: ServiceNature) -> LanDevice {
        LanDevice {
            address: Ipv4Addr::new(192, 168, 1, last),
            open: vec![OpenPort { port: 1080, note: "SOCKS proxy — test", nature }],
            identity: None,
        }
    }

    /// A network shaped like the one this was written for: talkative
    /// neighbours, one silent appliance.
    fn household(devices: Vec<LanDevice>, extra: Vec<DeviceIdentity>) -> LanSurvey {
        let mut inventory = vec![
            identity(6, Some("Sonos"), Some("Sonos-Kitchen")),
            identity(17, Some("Sonos"), Some("Sonos-Lounge")),
            identity(14, Some("Brother"), Some("BRN001BA9")),
            identity(20, Some("Amazon"), Some("firestick")),
        ];
        inventory.extend(extra);
        inventory.sort_by_key(|i| i.address);
        LanSurvey { devices, inventory }
    }

    #[test]
    fn a_proxy_on_a_streaming_stick_becomes_the_prime_suspect() {
        // The case this module exists for: fixed-function hardware that
        // publishes nothing and runs a SOCKS server refusing every destination
        // with a code the specification does not define.
        //
        // Roku rather than Amazon deliberately — Amazon's own 1080 turned out
        // to be stock Echo behaviour, so it can no longer stand for "a proxy
        // that has no business being here".
        let survey = household(
            vec![device(
                25,
                ServiceNature::Socks5 {
                    accepts_anonymous: true,
                    relayed: false,
                    refusal_code: Some(0x09),
                },
            )],
            vec![identity(25, Some("Roku"), None)],
        );

        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        let suspect = conclusion.notable.first().expect("a suspect was named");
        assert_eq!(suspect.address, Ipv4Addr::new(192, 168, 1, 25));
        assert_eq!(suspect.standing, Standing::PrimeSuspect);

        // The reasoning has to be checkable, not just a label.
        let reasoning = suspect.because.join(" ");
        assert!(reasoning.contains("fixed-function"), "must say why a proxy is odd here");
        assert!(reasoning.contains("custom build"), "the non-standard code is evidence");
        assert!(reasoning.contains("does NOT clear it"), "a refusal must never read as innocence");

        // And it must end with one action, naming the vantage point that works.
        assert!(conclusion.next_step.contains("block outbound TCP 25"));
        assert!(conclusion.next_step.contains("192.168.1.25"));
        assert!(suspect.decisive_test.as_ref().unwrap().contains("Power this device off"));
    }

    #[test]
    fn the_same_proxy_on_a_laptop_is_not_a_suspect() {
        // Identical observation, different hardware. A developer running a
        // local proxy is ordinary, and calling it a suspect would be the exact
        // false lead this tool is supposed to avoid.
        let survey = household(
            vec![device(
                30,
                ServiceNature::Socks5 {
                    accepts_anonymous: true,
                    relayed: false,
                    refusal_code: Some(0x02),
                },
            )],
            vec![identity(30, Some("Apple"), Some("macbook"))],
        );

        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        let laptop = conclusion
            .notable
            .iter()
            .chain(conclusion.consistent.iter())
            .find(|a| a.address == Ipv4Addr::new(192, 168, 1, 30))
            .expect("the laptop was assessed");
        assert_eq!(laptop.standing, Standing::Unresolved, "noted, but not accused");
        assert!(laptop.because.join(" ").contains("often deliberate"));
    }

    #[test]
    fn a_relaying_device_is_named_outright() {
        let survey = household(
            vec![device(25, ServiceNature::HttpProxy { relayed: true })],
            vec![identity(25, Some("Amazon"), None)],
        );
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));

        assert_eq!(conclusion.notable[0].standing, Standing::Responsible);
        assert!(conclusion.summary.starts_with("Found it"));
        assert!(conclusion.next_step.contains("off the network now"));
        // No further testing should be proposed once it is proven.
        assert!(!conclusion.next_step.contains("block outbound TCP 25"));
    }

    #[test]
    fn a_quiet_network_produces_a_conclusion_not_a_shrug() {
        // Nothing suspicious anywhere. The tool must still say something useful,
        // and must not imply the network has been cleared of everything.
        let conclusion = assess(&household(vec![], vec![]), &[], Ipv4Addr::new(192, 168, 1, 31));
        assert!(conclusion.notable.is_empty());
        assert_eq!(conclusion.consistent.len(), 4);
        assert!(conclusion.summary.contains("not visible from here"));
        assert!(conclusion.next_step.contains("block outbound TCP 25"));
    }

    #[test]
    fn silence_only_counts_where_the_neighbours_are_talkative() {
        // On a network where nothing publishes a name, publishing no name is
        // normal and must not accumulate suspicion.
        let silent_network = LanSurvey {
            devices: vec![],
            inventory: vec![identity(25, Some("Amazon"), None), identity(26, Some("Amazon"), None)],
        };
        let conclusion = assess(&silent_network, &[], Ipv4Addr::new(192, 168, 1, 31));
        assert!(
            conclusion.notable.is_empty(),
            "anonymity among anonymous neighbours is not evidence"
        );
    }

    #[test]
    fn a_port_forward_from_the_internet_raises_a_device() {
        let mappings = vec![PortMapping {
            external_port: 1080,
            internal_client: "192.168.1.30".to_owned(),
            internal_port: 1080,
            protocol: "TCP".to_owned(),
            description: String::new(),
            lease_seconds: 0,
        }];
        // A laptop proxy alone was Unresolved; reachable from the internet, it
        // is a different proposition entirely.
        let survey = household(
            vec![device(
                30,
                ServiceNature::Socks5 {
                    accepts_anonymous: true,
                    relayed: false,
                    refusal_code: Some(0x02),
                },
            )],
            vec![identity(30, Some("Apple"), Some("macbook"))],
        );
        let conclusion = assess(&survey, &mappings, Ipv4Addr::new(192, 168, 1, 31));
        let laptop = conclusion.notable.iter().find(|a| a.address.octets()[3] == 30).unwrap();
        assert_eq!(laptop.standing, Standing::PrimeSuspect);
        assert!(laptop.because.join(" ").contains("forwards port 1080"));
    }

    /// The mapping a real scan of this network turned up: a UPnP hole punched
    /// for an address that appeared nowhere else in the results.
    ///
    /// `lease_seconds` is explicit at every call site because it decides whether
    /// the mapping dates its owner or says nothing about it at all.
    fn teredo_mapping(last: u8, lease_seconds: u32) -> PortMapping {
        PortMapping {
            external_port: 56618,
            internal_client: format!("192.168.1.{last}"),
            internal_port: 56618,
            protocol: "UDP".to_owned(),
            description: format!("Teredo 192.168.1.{last}:56618->56618 UDP"),
            lease_seconds,
        }
    }

    #[test]
    fn a_forward_to_a_device_that_answered_nothing_is_raised() {
        // Found by running this for real: the router forwarded a port to
        // 192.168.1.5, which appeared in no other part of the output — not in
        // the inventory, not in the sweep. Two observations disagreeing is
        // exactly the finding, and the old code printed each of them separately
        // and never compared them.
        let conclusion =
            assess(&household(vec![], vec![]), &[teredo_mapping(5, 0)], Ipv4Addr::new(192, 168, 1, 31));

        let unseen = conclusion
            .notable
            .iter()
            .find(|a| a.address == Ipv4Addr::new(192, 168, 1, 5))
            .expect("an address with a forward but no device behind it is worth a line");
        assert_eq!(unseen.standing, Standing::Unresolved);

        let reasoning = unseen.because.join(" ");
        assert!(reasoning.contains("56618/UDP"), "name the hole it holds open");
        assert!(reasoning.contains("ARP cache"), "say what was looked for and not found");
        assert!(reasoning.contains("IPv6 tunnel"), "Teredo changes what reachability means");
        // The trap this whole module is built against.
        assert!(reasoning.contains("not an accusation"));
        assert!(unseen.decisive_test.as_ref().unwrap().contains("DHCP client list"));
    }

    #[test]
    fn a_permanent_mapping_dates_nothing_but_an_expiring_one_does() {
        let local = Ipv4Addr::new(192, 168, 1, 31);
        let reasoning = |mappings: &[PortMapping]| {
            assess(&household(vec![], vec![]), mappings, local)
                .notable
                .iter()
                .find(|a| a.address == Ipv4Addr::new(192, 168, 1, 5))
                .expect("a forward with nothing behind it is still worth a line")
                .because
                .join(" ")
        };

        // A lease of 0 means "until deleted", so the hole outlives its owner and
        // says nothing about whether anything is at that address now.
        let permanent = reasoning(&[teredo_mapping(5, 0)]);
        assert!(permanent.contains("no expiry"), "{permanent}");
        assert!(!permanent.contains("was awake"), "a permanent hole dates nothing: {permanent}");

        // A live countdown had to be renewed, which does date it.
        let expiring = reasoning(&[teredo_mapping(5, 7200)]);
        assert!(expiring.contains("7200s to run"), "{expiring}");
        assert!(expiring.contains("was awake within the last"), "{expiring}");
        assert!(!expiring.contains("no expiry"), "{expiring}");

        // Mixed: the expiring one is the evidence, the permanent one is not.
        let mixed = reasoning(&[teredo_mapping(5, 0), teredo_mapping(5, 90)]);
        assert!(mixed.contains("90s to run"), "one live lease outweighs a permanent one: {mixed}");
    }

    #[test]
    fn a_forward_to_a_device_the_sweep_already_saw_adds_nothing() {
        // The printer is in the inventory, so it is judged once, by the rules
        // that have its identity to work with.
        let conclusion =
            assess(&household(vec![], vec![]), &[teredo_mapping(14, 0)], Ipv4Addr::new(192, 168, 1, 31));

        let appearances = conclusion
            .notable
            .iter()
            .chain(conclusion.consistent.iter())
            .filter(|a| a.address == Ipv4Addr::new(192, 168, 1, 14))
            .count();
        assert_eq!(appearances, 1, "one device, one assessment");
    }

    #[test]
    fn a_forward_to_this_machine_is_not_a_mystery_device() {
        let local = Ipv4Addr::new(192, 168, 1, 31);
        let conclusion = assess(&household(vec![], vec![]), &[teredo_mapping(31, 0)], local);
        assert!(conclusion.notable.iter().all(|a| a.address != local));
    }

    #[test]
    fn ordinary_devices_are_counted_rather_than_listed() {
        // The failure mode being designed against: a wall of findings that
        // hands the diagnosis back to the reader.
        let survey = household(
            vec![device(
                25,
                ServiceNature::Socks5 {
                    accepts_anonymous: true,
                    relayed: false,
                    refusal_code: Some(0x09),
                },
            )],
            vec![identity(25, Some("Roku"), None)],
        );
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        assert_eq!(conclusion.notable.len(), 1, "only the device worth acting on is notable");
        assert_eq!(conclusion.consistent.len(), 4);
    }

    #[test]
    fn mixed_product_lines_are_not_guessed_at() {
        // Classifying a vendor wrongly would silently weight every assessment,
        // so ambiguous ones must stay unrecognised.
        assert_eq!(hardware_class(Some("Amazon")), HardwareClass::Appliance);
        assert_eq!(hardware_class(Some("Apple")), HardwareClass::GeneralPurpose);
        assert_eq!(hardware_class(Some("Netgear")), HardwareClass::Network);
        assert_eq!(hardware_class(Some("Samsung")), HardwareClass::Unrecognised);
        assert_eq!(hardware_class(None), HardwareClass::Unrecognised);
    }

    /// An Echo as it actually appears: SOCKS5 on 1080 that takes an anonymous
    /// session and then refuses every destination, a silent 8888, and HTTP on
    /// an unpredictable high port.
    fn an_echo(last: u8) -> LanDevice {
        LanDevice {
            address: Ipv4Addr::new(192, 168, 1, last),
            open: vec![
                OpenPort {
                    port: 1080,
                    note: "SOCKS proxy — test",
                    nature: ServiceNature::Socks5 {
                        accepts_anonymous: true,
                        relayed: false,
                        refusal_code: Some(0x09),
                    },
                },
                OpenPort { port: 8888, note: "HTTP proxy — test", nature: ServiceNature::Refused },
                OpenPort {
                    port: 55442,
                    note: "HTTP — test",
                    nature: ServiceNature::HttpServer { status: "HTTP/1.1 404 Not Found".to_owned() },
                },
            ],
            identity: None,
        }
    }

    #[test]
    fn a_stock_echo_is_not_accused() {
        // Found the hard way. This tool called a factory-normal Amazon Echo a
        // PRIME SUSPECT, because "runs a proxy" plus "is an appliance" is a
        // sound rule that breaks on an appliance whose maker ships a proxy.
        // Ports 1080 and 8888 are stock on Echo hardware — documented on the
        // Amazon device forum, r/AmazonEchoDev, and in an IACIS scan.
        //
        // Acting on the old output meant factory-resetting a device that was
        // fine, which is the same failure as clearing a guilty one.
        let survey = household(vec![an_echo(25)], vec![identity(25, Some("Amazon"), None)]);
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));

        assert!(
            conclusion.notable.is_empty(),
            "a stock Echo must not be raised: {:?}",
            conclusion.notable.iter().map(|a| a.address).collect::<Vec<_>>()
        );
        let echo = conclusion
            .consistent
            .iter()
            .find(|a| a.address.octets()[3] == 25)
            .expect("still assessed, just not accused");
        assert!(echo.what_it_is.contains("Amazon Echo"));
        // The reader must be able to check the claim rather than trust it.
        assert!(echo.because.join(" ").contains("r/AmazonEchoDev"));
    }

    #[test]
    fn a_stock_match_never_hides_an_actual_relay() {
        // The guard that keeps this from becoming the original bug again. If
        // the device genuinely carried traffic, no amount of looking like an
        // Echo may excuse it.
        let mut caught = an_echo(25);
        caught.open[0].nature =
            ServiceNature::Socks5 { accepts_anonymous: true, relayed: true, refusal_code: None };

        let survey = household(vec![caught], vec![identity(25, Some("Amazon"), None)]);
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        assert_eq!(conclusion.notable[0].standing, Standing::Responsible);
    }

    #[test]
    fn a_device_doing_more_than_its_documentation_is_no_longer_a_match() {
        // Matching requires every exposed service to be accounted for. An Echo
        // that also has telnet open is not a stock Echo, and the extra thing is
        // exactly what would matter.
        let mut tampered = an_echo(25);
        tampered.open.push(OpenPort {
            port: 23,
            note: "telnet — test",
            nature: ServiceNature::Silent,
        });

        let survey = household(vec![tampered], vec![identity(25, Some("Amazon"), None)]);
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        assert!(
            conclusion.notable.iter().any(|a| a.address.octets()[3] == 25),
            "an Echo with an extra service open is not explained by the Echo pattern"
        );
    }

    #[test]
    fn the_stock_pattern_does_not_excuse_a_different_vendor() {
        // The fingerprint has to name one product. A non-Amazon device with the
        // same ports is not an Echo and must still be judged.
        let survey =
            household(vec![an_echo(30)], vec![identity(30, Some("Roku"), Some("roku-lounge"))]);
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        assert!(conclusion.notable.iter().any(|a| a.address.octets()[3] == 30));
    }

    #[test]
    fn a_fire_tv_is_not_excused_by_the_echo_pattern() {
        // Both are Amazon, and the control scan that settled this showed a Fire
        // TV exposing 8009 and 9080 — not 1080 or 8888. Same vendor, different
        // product, so a Fire TV running a proxy is still a finding.
        let fire_tv = LanDevice {
            address: Ipv4Addr::new(192, 168, 1, 20),
            open: vec![OpenPort {
                port: 1080,
                note: "SOCKS proxy — test",
                nature: ServiceNature::Socks5 {
                    accepts_anonymous: true,
                    relayed: false,
                    refusal_code: Some(0x09),
                },
            }],
            identity: None,
        };
        // A device that matches the port fingerprint is excused; the point of
        // this test is that the excuse is anchored to the fingerprint and not
        // to the vendor alone, so an Amazon device exposing something outside
        // it still gets judged.
        let mut with_extra = fire_tv.clone();
        with_extra.open.push(OpenPort {
            port: 3389,
            note: "RDP — test",
            nature: ServiceNature::Silent,
        });
        let survey =
            household(vec![with_extra], vec![identity(20, Some("Amazon"), Some("firestick"))]);
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        assert!(conclusion.notable.iter().any(|a| a.address.octets()[3] == 20));
    }

    #[test]
    fn a_quiet_device_with_nothing_open_is_not_raised() {
        // Found by running this against a real network: a Nintendo Switch and a
        // sleeping Apple device were both raised as "not ruled out" purely for
        // publishing no name. That is the wall-of-findings failure — three
        // devices to sift, none of them actionable.
        let survey = LanSurvey {
            devices: vec![],
            inventory: vec![
                identity(6, Some("Sonos"), Some("Sonos-Kitchen")),
                identity(17, Some("Sonos"), Some("Sonos-Lounge")),
                identity(14, Some("Brother"), Some("BRN001BA9")),
                identity(8, Some("Nintendo"), None),
                identity(10, Some("Apple"), None),
            ],
        };
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        assert!(
            conclusion.notable.is_empty(),
            "silence alone must not raise a device: {:?}",
            conclusion.notable.iter().map(|a| a.address).collect::<Vec<_>>()
        );
    }

    #[test]
    fn silence_still_corroborates_a_device_already_implicated() {
        // It must not stop counting entirely — on a device that is already
        // suspicious, having nothing to check it against is part of the case.
        let survey = household(
            vec![device(
                25,
                ServiceNature::Socks5 {
                    accepts_anonymous: true,
                    relayed: false,
                    refusal_code: Some(0x09),
                },
            )],
            vec![identity(25, Some("Roku"), None)],
        );
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        let suspect = &conclusion.notable[0];
        assert!(suspect.because.join(" ").contains("also publishes no name"));
    }

    #[test]
    fn a_device_listening_for_mail_is_implicated_on_its_own() {
        // The most direct cause of a listing there is, and the previous scoring
        // missed it entirely because it only ever looked at proxy ports.
        let mail_server = LanDevice {
            address: Ipv4Addr::new(192, 168, 1, 12),
            open: vec![OpenPort {
                port: 25,
                note: "SMTP — test",
                nature: ServiceNature::HttpServer { status: "220 ready".to_owned() },
            }],
            identity: None,
        };
        let survey =
            household(vec![mail_server], vec![identity(12, Some("Amazon"), Some("echo"))]);
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        let found = conclusion.notable.iter().find(|a| a.address.octets()[3] == 12).unwrap();
        assert_eq!(found.standing, Standing::PrimeSuspect);
        assert!(found.because.join(" ").contains("port 25"));
    }

    #[test]
    fn a_router_running_a_proxy_is_doing_its_job() {
        let survey = household(
            vec![device(1, ServiceNature::HttpProxy { relayed: false })],
            vec![identity(1, Some("Netgear"), Some("router"))],
        );
        let conclusion = assess(&survey, &[], Ipv4Addr::new(192, 168, 1, 31));
        let router = conclusion
            .notable
            .iter()
            .chain(conclusion.consistent.iter())
            .find(|a| a.address.octets()[3] == 1)
            .unwrap();
        assert_eq!(router.standing, Standing::Consistent);
    }
}
