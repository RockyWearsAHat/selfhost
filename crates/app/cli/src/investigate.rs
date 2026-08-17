//! Root-cause investigation for the problems `doctor` reports.
//!
//! Reporting "you are blocklisted" is only half a diagnostic. The listing is a
//! *symptom*; the cause is a machine doing something, or a record somebody else
//! controls being wrong. This module exists to answer the next question:
//! **why**, and **who can fix it**.
//!
//! Three lines of investigation, matching the three ways these problems arise:
//!
//! - **Decode the verdict.** Blocklists answer with a specific address whose
//!   last octet says *which* list matched, and the lists mean very different
//!   things. `127.0.0.10` means "this is a residential address" — expected, and
//!   nothing to fix. `127.0.0.4` means "this machine looks compromised" — a
//!   security incident on your own network. Treating those the same wastes days.
//!
//! - **Establish blame.** If the whole surrounding address block is listed, it
//!   is the provider's problem and delisting one address achieves nothing. If
//!   only yours is, it is yours.
//!
//! - **Name the person who can fix it.** Reverse DNS cannot be changed by the
//!   address holder. The zone's `SOA` names the responsible party, so the tool
//!   prints the address to email rather than telling somebody to go look it up.
//!
//! When the cause is a machine on your own network, [`crate::identify`] turns
//! the address this module shortlists into hardware you can walk over to.

use crate::identify::{self, DeviceIdentity};
use selfhost_dns::{Resolver, blocklist_name, is_real_listing, reverse_name};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::net::TcpStream;

/// What a blocklist return code means, and whether it is actionable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listing {
    /// The code returned by the blocklist.
    pub code: Ipv4Addr,
    /// Short name of the list that matched.
    pub list: &'static str,
    /// What being on that list actually means.
    pub meaning: &'static str,
    /// What to do about it.
    pub action: &'static str,
    /// Whether this indicates a compromised machine rather than a policy label.
    pub indicates_compromise: bool,
}

/// Decodes a Spamhaus ZEN return code.
///
/// The distinction that matters most: PBL is a *policy* statement — "this is a
/// residential address, mail should not come from it directly" — and is normal
/// for a home connection. XBL is an *observation* — "this address behaved like a
/// compromised machine". One is a label; the other is an incident.
pub fn describe(code: Ipv4Addr) -> Listing {
    match code.octets() {
        [127, 0, 0, 2] => Listing {
            code,
            list: "SBL",
            meaning: "the address is on the Spamhaus Block List — a manually maintained list of \
                      addresses observed sending spam",
            action: "Request removal, and identify what sent the spam. Listings are reviewed by \
                     people, so an explanation helps.",
            indicates_compromise: false,
        },
        [127, 0, 0, 3] => Listing {
            code,
            list: "CSS",
            meaning: "detected by the Composite Snowshoe Sender heuristics — low-volume mail with \
                      the pattern of spam spread thinly across many addresses",
            action: "Often accompanies an XBL listing on the same address; fix that first. CSS \
                     expires on its own once the sending behaviour stops.",
            indicates_compromise: false,
        },
        [127, 0, 0, 4..=7] => Listing {
            code,
            list: "XBL / CBL",
            meaning: "a machine at this address looks COMPROMISED — malware, a proxy being abused, \
                      brute-force participation, or mail sent with stolen credentials",
            action: "This is a security incident on your own network, not a mail configuration \
                     problem. Find the device before requesting removal: the listing expires by \
                     itself once the behaviour stops, and returns if it does not.",
            indicates_compromise: true,
        },
        [127, 0, 0, 9] => Listing {
            code,
            list: "SBL DROP",
            meaning: "the entire netblock is listed as hijacked or spam-operated",
            action: "Nothing you can do at this address. This is between your provider and \
                     Spamhaus.",
            indicates_compromise: false,
        },
        [127, 0, 0, 10 | 11] => Listing {
            code,
            list: "PBL",
            meaning: "the address is in a range the provider designates as end-user / residential, \
                      which should not send mail directly",
            action: "Expected for a home connection and NOT a fault. It means direct delivery to \
                     strict receivers will be refused — either ask the ISP for a static business \
                     address, or send outbound through a relay.",
            indicates_compromise: false,
        },
        _ => Listing {
            code,
            list: "unknown",
            meaning: "the list returned a code this tool does not recognise",
            action: "Look the address up at check.spamhaus.org for the current explanation.",
            indicates_compromise: false,
        },
    }
}

/// Whether neighbouring addresses share the listing.
#[derive(Debug, Clone)]
pub struct BlockSurvey {
    /// Addresses sampled.
    pub sampled: usize,
    /// How many of them were listed.
    pub listed: usize,
    /// Examples of listed neighbours.
    pub examples: Vec<Ipv4Addr>,
}

impl BlockSurvey {
    /// Whether the surrounding block appears listed as a whole.
    ///
    /// A provider-wide listing cannot be fixed by delisting one address, so this
    /// is the difference between an afternoon of work and a support ticket.
    pub fn is_block_wide(&self) -> bool {
        self.sampled > 0 && self.listed * 2 >= self.sampled
    }
}

/// Samples neighbouring addresses in the same /24 against a blocklist.
pub async fn survey_block(resolver: &Resolver, address: Ipv4Addr, zone: &str) -> BlockSurvey {
    let [a, b, c, d] = address.octets();
    // A spread across the block rather than only adjacent addresses, so a
    // small listed run does not read as the whole range.
    let offsets: [u8; 8] = [1, 25, 50, 100, 150, 200, 225, 254];

    let mut listed = 0;
    let mut sampled = 0;
    let mut examples = Vec::new();

    for offset in offsets {
        if offset == d {
            continue;
        }
        let neighbour = Ipv4Addr::new(a, b, c, offset);
        let Ok(answers) = resolver.lookup_a(&blocklist_name(neighbour, zone)).await else {
            continue;
        };
        sampled += 1;
        if answers.iter().any(|answer| is_real_listing(*answer)) {
            listed += 1;
            if examples.len() < 3 {
                examples.push(neighbour);
            }
        }
    }

    BlockSurvey { sampled, listed, examples }
}

/// Who to contact about a reverse-DNS record for an address.
#[derive(Debug, Clone)]
pub struct ReverseAuthority {
    /// The reverse zone that governs the address.
    pub zone: String,
    /// Email address of the responsible party, from the zone's `SOA`.
    pub contact: Option<String>,
    /// Nameservers for the zone.
    pub nameservers: Vec<String>,
}

/// Finds who runs the reverse zone for an address.
///
/// The address holder cannot change their own `PTR`; only whoever runs the
/// reverse zone can. Printing their address turns "ask your ISP" into a specific
/// person to email.
pub async fn reverse_authority(resolver: &Resolver, address: Ipv4Addr) -> ReverseAuthority {
    let [a, b, c, _] = address.octets();
    let zone = format!("{c}.{b}.{a}.in-addr.arpa");

    // Ask for the SOA of the address's own reverse name. A name with no records
    // still returns the enclosing zone's SOA in the authority section, which is
    // exactly the case here.
    let contact = match resolver.query(&reverse_name(address), selfhost_dns::RecordType::Soa).await {
        Ok(response) => response.soa_contact(),
        Err(_) => None,
    };
    let contact = match contact {
        Some(found) => Some(found),
        None => resolver
            .query(&zone, selfhost_dns::RecordType::Soa)
            .await
            .ok()
            .and_then(|response| response.soa_contact()),
    };

    let nameservers = resolver.lookup_ns(&zone).await.unwrap_or_default();
    ReverseAuthority { zone, contact, nameservers }
}

/// A service found listening somewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenService {
    /// Address it was found on.
    pub address: Ipv4Addr,
    /// Port it was found on.
    pub port: u16,
    /// Why this port is worth knowing about.
    pub note: &'static str,
}

/// Ports worth knowing about when hunting a compromised machine.
///
/// Chosen for what earns an XBL listing: open proxies relaying somebody else's
/// traffic, an open mail relay, and remote-access services that get brute-forced
/// and then used as a foothold.
const SUSPICIOUS_PORTS: [(u16, &str); 13] = [
    (23, "telnet — unencrypted remote access, heavily targeted"),
    (25, "SMTP — an open relay here would earn a listing directly"),
    (445, "SMB — a common malware spreading path"),
    (1080, "SOCKS proxy — the classic way a machine is abused to relay traffic"),
    (3128, "Squid proxy — abused as an open proxy when unauthenticated"),
    (3389, "RDP — brute-forced constantly; a foothold once broken"),
    (5900, "VNC — often left unauthenticated"),
    (8080, "HTTP proxy — abused as an open proxy when unauthenticated"),
    (8081, "HTTP proxy alternate — same risk as 8080"),
    (8118, "Privoxy — HTTP proxy; relays for anyone if left open"),
    (8888, "HTTP proxy alternate — the default for several proxy toolkits"),
    (9050, "Tor SOCKS — expected on a Tor relay, abused if reachable from the LAN"),
    (1900, "UPnP — device control; can open port forwards without you asking"),
];

/// An open port, and what it turned out to actually be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenPort {
    /// The port number.
    pub port: u16,
    /// Why this port number is on the watch list in the first place.
    pub note: &'static str,
    /// What the service there actually speaks, established by asking it.
    pub nature: ServiceNature,
}

/// What a listening port turned out to be, established by talking to it.
///
/// # Why the port number is not the answer
///
/// A port number is a convention, not a fact. Treating `1080` as "a SOCKS proxy"
/// and `8009` as "harmless" is guessing with extra steps: the interesting device
/// is precisely the one not following convention. Every variant here records
/// what a service *did* when spoken to, so a conclusion can rest on behaviour.
///
/// These are observations only. They carry no verdict, because the same
/// observation means different things on different hardware — a SOCKS server is
/// unremarkable on a developer's laptop and alarming on a streaming stick. That
/// judgement belongs in [`crate::assess`], with the rest of the context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceNature {
    /// It speaks SOCKS5.
    Socks5 {
        /// Whether it began a session with no credentials at all.
        accepts_anonymous: bool,
        /// Whether it actually opened a connection to an external host.
        relayed: bool,
        /// The `REP` byte it answered a `CONNECT` with, when it refused.
        refusal_code: Option<u8>,
    },
    /// It understands HTTP `CONNECT` tunnelling, so it is an HTTP proxy.
    HttpProxy {
        /// Whether the tunnel it opened actually succeeded.
        relayed: bool,
    },
    /// It answers HTTP, as an ordinary web server rather than a proxy.
    HttpServer {
        /// The status line it replied with.
        status: String,
    },
    /// It accepted the connection and then said nothing to anything we asked.
    ///
    /// Common for protocols that expect the client to speak first in a format
    /// we did not guess — but also what a service does when it only answers a
    /// caller that knows the right opening.
    Silent,
    /// It closed or reset the connection as soon as we spoke.
    Refused,
}

impl ServiceNature {
    /// Whether this service relays traffic for whoever asks.
    ///
    /// The only observation on its own that proves a device is being abused.
    pub fn is_open_relay(&self) -> bool {
        matches!(
            self,
            ServiceNature::Socks5 { relayed: true, .. } | ServiceNature::HttpProxy { relayed: true }
        )
    }

    /// Whether this is proxy software at all, relaying or not.
    ///
    /// The distinction that matters for a consumer appliance: a speaker or a
    /// streaming stick has no reason to run a proxy in either state.
    pub fn is_proxy_software(&self) -> bool {
        matches!(self, ServiceNature::Socks5 { .. } | ServiceNature::HttpProxy { .. })
    }

    /// Whether it answered in a way the protocol's specification does not define.
    ///
    /// Stock software uses the reply codes in `RFC 1928`. Anything else is a
    /// custom build, which is worth knowing on a device that should be running
    /// none.
    pub fn is_non_standard(&self) -> bool {
        matches!(self, ServiceNature::Socks5 { refusal_code: Some(code), .. } if *code > 0x08)
    }

    /// A short description of what was observed, without interpreting it.
    pub fn describe(&self) -> String {
        match self {
            ServiceNature::Socks5 { accepts_anonymous, relayed, refusal_code } => {
                if *relayed {
                    return "SOCKS5 proxy that RELAYED our connection to an external host".to_owned();
                }
                let door = if *accepts_anonymous {
                    "accepted a session with no credentials"
                } else {
                    "demanded credentials"
                };
                match refusal_code {
                    Some(code) => format!("SOCKS5 proxy: {door}, then refused the destination ({code:#04x})"),
                    None => format!("SOCKS5 proxy: {door}"),
                }
            }
            ServiceNature::HttpProxy { relayed: true } => {
                "HTTP proxy that TUNNELLED to an external host".to_owned()
            }
            ServiceNature::HttpProxy { relayed: false } => {
                "HTTP proxy, but it refused to tunnel for us".to_owned()
            }
            ServiceNature::HttpServer { status } => format!("web server ({status})"),
            ServiceNature::Silent => "accepted the connection and said nothing".to_owned(),
            ServiceNature::Refused => "closed the connection as soon as we spoke".to_owned(),
        }
    }
}

/// Probes this machine's own loopback for services that could earn a listing.
///
/// Loopback rather than the LAN address on purpose: this asks "what is running
/// here", and a service bound only to loopback still counts, because malware
/// often listens locally and is driven by something else.
pub async fn local_services() -> Vec<OpenService> {
    let mut found = Vec::new();
    for (port, note) in SUSPICIOUS_PORTS {
        if probe(Ipv4Addr::LOCALHOST, port, Duration::from_millis(200)).await {
            found.push(OpenService { address: Ipv4Addr::LOCALHOST, port, note });
        }
    }
    found
}

/// This machine's address on the local network.
///
/// Found by asking the operating system which local address it would use to
/// reach a remote one. UDP, so no packet is actually sent and no service needs
/// to be reachable.
pub fn local_address() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    match socket.local_addr().ok()? {
        SocketAddr::V4(address) => Some(*address.ip()),
        SocketAddr::V6(_) => None,
    }
}

/// A device discovered on the local network.
#[derive(Debug, Clone)]
pub struct LanDevice {
    /// Its address.
    pub address: Ipv4Addr,
    /// Ports found open, each with what it turned out to actually be.
    pub open: Vec<OpenPort>,
    /// What hardware this is, so the finding names a device and not an address.
    pub identity: Option<DeviceIdentity>,
}

impl LanDevice {
    /// Any service here that relays traffic for whoever asks.
    pub fn open_relay(&self) -> Option<&OpenPort> {
        self.open.iter().find(|open| open.nature.is_open_relay())
    }

    /// Any proxy software running here, relaying or not.
    pub fn proxy_software(&self) -> Vec<&OpenPort> {
        self.open.iter().filter(|open| open.nature.is_proxy_software()).collect()
    }
}

/// The result of looking at the local network: what is on it, and what is odd.
///
/// Both halves are needed to reach a conclusion. The shortlist says which
/// devices hold interesting ports open; the inventory is what makes one of them
/// look *unusual*, because a device that publishes no name is only notable when
/// you can see that its neighbours all do.
#[derive(Debug, Clone, Default)]
pub struct LanSurvey {
    /// Devices exposing a service worth investigating.
    pub devices: Vec<LanDevice>,
    /// Every device that answered on the network, identified as far as possible.
    pub inventory: Vec<DeviceIdentity>,
}

/// Sweeps the local /24 for devices exposing services worth investigating.
///
/// This exists for one specific job: an XBL listing says *a machine on your
/// network* is compromised, and on a home network nobody has an inventory. This
/// narrows a /24 down to the handful of devices worth actually looking at.
///
/// Deliberately opt-in and bounded — a short timeout, a fixed port list, and
/// capped concurrency, so it finishes in seconds and does not look like an
/// attack to anything watching.
///
/// The port sweep runs *before* identification on purpose: touching every
/// address populates the operating system's ARP cache, which is what makes the
/// hardware behind each address readable afterwards.
pub async fn sweep_lan(local: Ipv4Addr) -> LanSurvey {
    let [a, b, c, _] = local.octets();
    let mut tasks = tokio::task::JoinSet::new();

    for host in 1_u8..=254 {
        let address = Ipv4Addr::new(a, b, c, host);
        tasks.spawn(async move {
            let mut listening = Vec::new();
            for (port, note) in SUSPICIOUS_PORTS {
                if probe(address, port, Duration::from_millis(300)).await {
                    listening.push((port, note));
                }
            }
            if listening.is_empty() {
                return None;
            }
            // An open port is only a lead. What the service actually speaks is
            // the fact worth having, so every one of them gets asked.
            let mut open = Vec::new();
            for (port, note) in listening {
                let nature = probe_service(address, port).await;
                open.push(OpenPort { port, note, nature });
            }
            Some(LanDevice { address, open, identity: None })
        });
    }

    let mut devices = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some(device)) = result {
            devices.push(device);
        }
    }
    devices.sort_by_key(|device| device.address);

    let inventory = identify::survey(local).await;
    for device in &mut devices {
        device.identity =
            inventory.iter().find(|identity| identity.address == device.address).cloned();
    }
    LanSurvey { devices, inventory }
}

/// Whether a TCP port accepts a connection.
async fn probe(address: Ipv4Addr, port: u16, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, TcpStream::connect((address, port))).await,
        Ok(Ok(_))
    )
}

/// Establishes what a listening port actually is, by speaking to it.
///
/// Tries each protocol on its own connection, because a service that does not
/// recognise an opening usually resets rather than waiting for a better one.
/// The order runs from most specific to least: SOCKS5, then HTTP tunnelling,
/// then plain HTTP, and only then falls back to describing the silence.
///
/// Nothing is sent through any tunnel that opens. The question is only whether
/// it *would* carry somebody else's traffic.
pub async fn probe_service(address: Ipv4Addr, port: u16) -> ServiceNature {
    if let Some(socks) = probe_socks5(address, port).await {
        return socks;
    }
    if let Some(http) = probe_http(address, port).await {
        return http;
    }
    match exchange(address, port, b"\r\n").await {
        Some(reply) if reply.is_empty() => ServiceNature::Silent,
        Some(_) => ServiceNature::Silent,
        None => ServiceNature::Refused,
    }
}

/// Asks whether a port speaks SOCKS5, and if so how far it will go.
async fn probe_socks5(address: Ipv4Addr, port: u16) -> Option<ServiceNature> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let work = async {
        let mut stream = TcpStream::connect((address, port)).await.ok()?;
        // Offer every method a client can claim, so a proxy that wants
        // credentials still identifies itself as SOCKS5 rather than hanging up.
        stream.write_all(&[0x05, 0x03, 0x00, 0x01, 0x02]).await.ok()?;
        let mut greeting = [0_u8; 2];
        stream.read_exact(&mut greeting).await.ok()?;
        if greeting[0] != 0x05 {
            return None;
        }
        if greeting[1] != 0x00 {
            return Some(ServiceNature::Socks5 {
                accepts_anonymous: false,
                relayed: false,
                refusal_code: None,
            });
        }

        let host = b"example.com";
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&80_u16.to_be_bytes());
        stream.write_all(&request).await.ok()?;

        let mut reply = [0_u8; 4];
        stream.read_exact(&mut reply).await.ok()?;
        // Byte 1 is the reply code; 0x00 alone means the relay succeeded.
        Some(ServiceNature::Socks5 {
            accepts_anonymous: true,
            relayed: reply[1] == 0x00,
            refusal_code: (reply[1] != 0x00).then_some(reply[1]),
        })
    };

    tokio::time::timeout(Duration::from_secs(5), work).await.ok().flatten()
}

/// Asks whether a port tunnels HTTP, or merely serves it.
///
/// `CONNECT` is the discriminator. An ordinary web server rejects it with its
/// own error; a proxy either opens the tunnel or refuses in a way that shows it
/// understood the request.
async fn probe_http(address: Ipv4Addr, port: u16) -> Option<ServiceNature> {
    let tunnel = exchange(
        address,
        port,
        b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n",
    )
    .await?;
    let status = status_line(&tunnel);

    if let Some(status) = &status
        && status.contains(" 2")
    {
        return Some(ServiceNature::HttpProxy { relayed: true });
    }

    // It answered HTTP but would not tunnel. Whether it is a proxy at all is
    // decided by whether it serves an absolute URI, which only a proxy does.
    let absolute =
        exchange(address, port, b"GET http://example.com/ HTTP/1.0\r\nHost: example.com\r\n\r\n")
            .await;
    if let Some(reply) = &absolute
        && let Some(line) = status_line(reply)
        && line.contains(" 2")
    {
        return Some(ServiceNature::HttpProxy { relayed: true });
    }

    status.map(|status| ServiceNature::HttpServer { status })
}

/// Sends bytes to a port and returns whatever came back.
///
/// `None` means the connection could not be made or was reset before anything
/// was said, which is itself a distinguishing behaviour.
async fn exchange(address: Ipv4Addr, port: u16, payload: &[u8]) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let work = async {
        let mut stream = TcpStream::connect((address, port)).await.ok()?;
        stream.write_all(payload).await.ok()?;
        let mut buffer = vec![0_u8; 512];
        let read = stream.read(&mut buffer).await.ok()?;
        Some(String::from_utf8_lossy(&buffer[..read]).into_owned())
    };

    tokio::time::timeout(Duration::from_secs(4), work).await.ok().flatten()
}

/// The HTTP status line from a reply, if the reply is HTTP at all.
fn status_line(reply: &str) -> Option<String> {
    let first = reply.lines().next()?.trim();
    first.starts_with("HTTP/").then(|| first.chars().take(60).collect())
}

/// A port forward currently configured on the router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    /// Port open on the public address.
    pub external_port: u16,
    /// Device the traffic is sent to.
    pub internal_client: String,
    /// Port on that device.
    pub internal_port: u16,
    /// `TCP` or `UDP`.
    pub protocol: String,
    /// Description supplied by whatever created the mapping.
    pub description: String,
    /// Seconds left before the router drops this mapping; `0` means permanent.
    ///
    /// This is what separates "something here is awake and renewing a hole" from
    /// "a hole was punched once and nothing has cleaned it up since". A permanent
    /// mapping says nothing about when its owner was last on the network.
    pub lease_seconds: u32,
}

impl PortMapping {
    /// Whether this mapping exposes a port commonly abused as a proxy or relay.
    pub fn exposes_abusable_service(&self) -> bool {
        SUSPICIOUS_PORTS.iter().any(|(port, _)| *port == self.internal_port)
    }

    /// Whether the router will hold this mapping open until something deletes it.
    pub fn never_expires(&self) -> bool {
        self.lease_seconds == 0
    }
}

/// What stands between this network and the internet.
///
/// A home router is assumed to *be* the edge — the box holding the public
/// address, where a port forward decides what the internet can reach. When it is
/// not, every conclusion drawn from its forwarding table is scoped to one hop of
/// a longer chain, and saying "nothing is reachable from outside" on that basis
/// is wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NetworkEdge {
    /// The address the local router believes is its own outside address.
    pub router_wan: Ipv4Addr,
    /// The address the internet actually sees traffic arrive from.
    pub public: Ipv4Addr,
}

/// How many translation layers separate this network from a routable address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Edge {
    /// The local router holds the public address; a forward here reaches the internet.
    Direct,
    /// Another router sits upstream, holding the public address on private space.
    DoubleNat,
    /// The provider shares one public address across customers (RFC 6598).
    CarrierGrade,
}

impl NetworkEdge {
    /// Classifies the edge from the two addresses.
    pub fn shape(&self) -> Edge {
        if self.router_wan == self.public {
            Edge::Direct
        } else if is_shared_address_space(self.router_wan) {
            Edge::CarrierGrade
        } else {
            // Any disagreement puts another translating hop in the path, whether
            // this router's own outside address is private or a second public one.
            Edge::DoubleNat
        }
    }

    /// Whether a port forward on the local router is enough to reach the internet.
    pub fn forwards_reach_the_internet(&self) -> bool {
        self.shape() == Edge::Direct
    }
}

/// Whether an address is in the carrier-grade NAT range, `100.64.0.0/10`.
fn is_shared_address_space(address: Ipv4Addr) -> bool {
    let [first, second, ..] = address.octets();
    first == 100 && (64..=127).contains(&second)
}

/// A router's UPnP control interface, discovered once and queried repeatedly.
///
/// Discovery costs a multicast round trip and a description fetch, so the two
/// questions worth asking a gateway — what it forwards, and what address it
/// thinks it has — share one handle rather than each paying for their own.
pub struct Gateway {
    control_url: String,
    service_type: String,
}

impl Gateway {
    /// Finds the router's UPnP gateway service on the local network.
    pub async fn discover() -> Result<Self, String> {
        let description_url = discover_gateway().await.ok_or("no UPnP gateway responded")?;
        let (control_url, service_type) = gateway_control(&description_url).await?;
        Ok(Self { control_url, service_type })
    }

    /// Reads the port forwards the router currently has open.
    ///
    /// This is the question that decides whether a service on the LAN can be
    /// abused from the internet at all. A device listening on a proxy port behind
    /// a router with no forward for it is not reachable by anyone outside — so it
    /// cannot be the cause of a blocklisting, however alarming the open port
    /// looks. That reasoning holds only while this router is the edge; see
    /// [`Gateway::external_address`].
    ///
    /// It also surfaces forwards that **nothing asked for**: UPnP lets any
    /// program on the network open a hole in the firewall silently, which is a
    /// common way a machine becomes internet-reachable without its owner knowing.
    pub async fn mappings(&self) -> Vec<PortMapping> {
        let mut mappings = Vec::new();
        for index in 0..40 {
            let Ok(response) = self
                .invoke("GetGenericPortMappingEntry", &format!("<NewPortMappingIndex>{index}</NewPortMappingIndex>"))
                .await
            else {
                break;
            };

            let field = |tag: &str| extract(&response, tag).unwrap_or_default();
            let Ok(external_port) = field("NewExternalPort").parse::<u16>() else { break };

            mappings.push(PortMapping {
                external_port,
                internal_client: field("NewInternalClient"),
                internal_port: field("NewInternalPort").parse::<u16>().unwrap_or(0),
                protocol: field("NewProtocol"),
                description: field("NewPortMappingDescription"),
                lease_seconds: field("NewLeaseDuration").parse::<u32>().unwrap_or(0),
            });
        }
        mappings
    }

    /// Asks the router what address it believes the internet sees it as.
    ///
    /// Compared against the address a public echo reports, this is the one cheap
    /// question that reveals a second layer of NAT — and with it, that the
    /// router's forwarding table describes only the inner hop.
    pub async fn external_address(&self) -> Result<Ipv4Addr, String> {
        let response = self.invoke("GetExternalIPAddress", "").await?;
        extract(&response, "NewExternalIPAddress")
            .ok_or_else(|| "gateway reported no external address".to_owned())?
            .trim()
            .parse()
            .map_err(|_| "gateway reported an unreadable external address".to_owned())
    }

    /// Calls one SOAP action on the gateway, returning the response body.
    async fn invoke(&self, action: &str, arguments: &str) -> Result<String, String> {
        let service_type = &self.service_type;
        let body = format!(
            r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:{action} xmlns:u="{service_type}">{arguments}</u:{action}></s:Body></s:Envelope>"#
        );
        soap(&self.control_url, &format!("\"{service_type}#{action}\""), &body).await
    }
}

/// Finds the router's UPnP description URL by multicast discovery.
async fn discover_gateway() -> Option<String> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let probe = b"M-SEARCH * HTTP/1.1\r\n\
HOST:239.255.255.250:1900\r\n\
ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\
MX:2\r\n\
MAN:\"ssdp:discover\"\r\n\r\n";
    socket.send_to(probe, "239.255.255.250:1900").await.ok()?;

    let mut buffer = vec![0_u8; 2048];
    let received =
        tokio::time::timeout(Duration::from_secs(4), socket.recv(&mut buffer)).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&buffer[..received]);

    text.lines()
        .find(|line| line.to_ascii_lowercase().starts_with("location:"))
        .and_then(|line| line.split_once(':').map(|(_, value)| value.trim().to_owned()))
}

/// Reads the gateway description and returns its control URL and service type.
async fn gateway_control(description_url: &str) -> Result<(String, String), String> {
    let document = http_get(description_url).await?;

    // Take the first WAN connection service; that is the one holding the
    // port-mapping table.
    for service in document.split("<service>").skip(1) {
        let Some(service_type) = extract(service, "serviceType") else { continue };
        if !service_type.contains("WANIPConnection") && !service_type.contains("WANPPPConnection") {
            continue;
        }
        let Some(control) = extract(service, "controlURL") else { continue };

        let control_url = if control.starts_with("http") {
            control
        } else {
            let base = description_url
                .split('/')
                .take(3)
                .collect::<Vec<_>>()
                .join("/");
            format!("{base}{}{control}", if control.starts_with('/') { "" } else { "/" })
        };
        return Ok((control_url, service_type));
    }
    Err("gateway exposes no WAN connection service".to_owned())
}

/// Extracts the text of the first occurrence of an XML tag.
fn extract(document: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = document.find(&open)? + open.len();
    let end = document[start..].find(&close)? + start;
    Some(document[start..end].replace("&gt;", ">").replace("&lt;", "<").replace("&amp;", "&"))
}

/// Performs a plain HTTP GET, returning the body.
async fn http_get(url: &str) -> Result<String, String> {
    let (host_port, path) = split_url(url)?;
    let request = format!("GET {path} HTTP/1.0\r\nHost: {host_port}\r\nConnection: close\r\n\r\n");
    send_http(&host_port, request.into_bytes()).await
}

/// Performs a SOAP POST, returning the body.
async fn soap(url: &str, action: &str, body: &str) -> Result<String, String> {
    let (host_port, path) = split_url(url)?;
    let request = format!(
        "POST {path} HTTP/1.0\r\nHost: {host_port}\r\n\
         Content-Type: text/xml; charset=\"utf-8\"\r\n\
         SOAPAction: {action}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    send_http(&host_port, request.into_bytes()).await
}

/// Splits `http://host:port/path` into its authority and path.
fn split_url(url: &str) -> Result<(String, String), String> {
    let rest = url.strip_prefix("http://").ok_or("only http:// gateway URLs are supported")?;
    match rest.split_once('/') {
        Some((authority, path)) => Ok((authority.to_owned(), format!("/{path}"))),
        None => Ok((rest.to_owned(), "/".to_owned())),
    }
}

/// Sends a request and returns the response body.
async fn send_http(host_port: &str, request: Vec<u8>) -> Result<String, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let work = async {
        let mut stream = TcpStream::connect(host_port).await.map_err(|e| e.to_string())?;
        stream.write_all(&request).await.map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&response).into_owned();
        Ok::<String, String>(text.split_once("\r\n\r\n").map(|(_, b)| b.to_owned()).unwrap_or(text))
    };

    tokio::time::timeout(Duration::from_secs(8), work)
        .await
        .map_err(|_| "gateway did not answer in time".to_owned())?
}

/// Which outbound ports this network permits.
///
/// Distinguishes "our software cannot send mail" from "this network does not
/// allow mail to leave", which look identical from inside an application.
pub async fn outbound_matrix() -> Vec<(u16, &'static str, bool)> {
    // Each probe targets a host that genuinely listens on that port, so a
    // failure means filtering rather than a dead endpoint.
    let targets: [(u16, &str, &str); 5] = [
        (25, "gmail-smtp-in.l.google.com", "SMTP delivery — required for direct outbound mail"),
        (587, "smtp.gmail.com", "submission — required to send through a relay"),
        (465, "smtp.gmail.com", "implicit-TLS submission"),
        (53, "one.one.one.one", "DNS over TCP — needed for large responses"),
        (443, "one.one.one.one", "HTTPS — needed for ACME certificate issuance"),
    ];

    let mut results = Vec::new();
    for (port, host, note) in targets {
        let reachable = matches!(
            tokio::time::timeout(Duration::from_secs(6), TcpStream::connect((host, port))).await,
            Ok(Ok(_))
        );
        results.push((port, note, reachable));
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xbl_is_flagged_as_a_security_incident() {
        // The distinction the whole module exists for: XBL means a machine is
        // compromised, and mistaking it for a mail-config problem wastes days.
        for last in 4..=7 {
            let listing = describe(Ipv4Addr::new(127, 0, 0, last));
            assert_eq!(listing.list, "XBL / CBL");
            assert!(listing.indicates_compromise, "code .{last} should indicate compromise");
        }
    }

    #[test]
    fn pbl_is_a_policy_label_not_a_fault() {
        // Being in a residential range is normal for a home connection. Treating
        // it as something to fix sends people chasing a non-problem.
        for last in [10, 11] {
            let listing = describe(Ipv4Addr::new(127, 0, 0, last));
            assert_eq!(listing.list, "PBL");
            assert!(!listing.indicates_compromise);
            assert!(listing.action.contains("NOT a fault"));
        }
    }

    #[test]
    fn each_known_code_is_distinguished() {
        assert_eq!(describe(Ipv4Addr::new(127, 0, 0, 2)).list, "SBL");
        assert_eq!(describe(Ipv4Addr::new(127, 0, 0, 3)).list, "CSS");
        assert_eq!(describe(Ipv4Addr::new(127, 0, 0, 9)).list, "SBL DROP");
        assert_eq!(describe(Ipv4Addr::new(127, 0, 0, 99)).list, "unknown");
    }

    #[test]
    fn a_block_wide_listing_is_recognised() {
        // Delisting one address achieves nothing when the provider's whole range
        // is listed, so this changes who the problem belongs to.
        let block_wide = BlockSurvey { sampled: 8, listed: 6, examples: vec![] };
        assert!(block_wide.is_block_wide());

        let isolated = BlockSurvey { sampled: 8, listed: 0, examples: vec![] };
        assert!(!isolated.is_block_wide());

        // No samples means no conclusion, not a clean bill of health.
        let untested = BlockSurvey { sampled: 0, listed: 0, examples: vec![] };
        assert!(!untested.is_block_wide());
    }

    #[test]
    fn the_local_address_is_discoverable_without_sending_anything() {
        // Uses a UDP socket's chosen source address; nothing is transmitted.
        if let Some(address) = local_address() {
            assert!(!address.is_loopback(), "expected a LAN address, got {address}");
        }
    }

    #[test]
    fn suspicious_ports_each_explain_why_they_matter() {
        // A port number alone tells somebody nothing. Every entry must say what
        // the service is AND why it is worth investigating, or the sweep output
        // is just a list of numbers to go and google.
        for (port, note) in SUSPICIOUS_PORTS {
            assert!(
                note.contains('—'),
                "port {port} note {note:?} does not explain why it matters"
            );
            let (name, reason) = note.split_once('—').expect("checked above");
            assert!(!name.trim().is_empty(), "port {port} has no service name");
            assert!(
                reason.trim().len() >= 15,
                "port {port} reason {reason:?} is too thin to act on"
            );
        }
    }

    #[test]
    fn the_port_list_has_no_duplicates() {
        let mut seen = std::collections::BTreeSet::new();
        for (port, _) in SUSPICIOUS_PORTS {
            assert!(seen.insert(port), "port {port} listed twice");
        }
    }
}

#[cfg(test)]
mod evidence_tests {
    use super::*;

    #[test]
    fn a_mapping_to_an_abusable_port_is_recognised() {
        let socks = PortMapping {
            external_port: 1080,
            internal_client: "192.168.1.25".into(),
            internal_port: 1080,
            protocol: "TCP".into(),
            description: "".into(),
            lease_seconds: 0,
        };
        assert!(socks.exposes_abusable_service());

        // Teredo is IPv6 tunnelling, not a relay service.
        let teredo = PortMapping {
            external_port: 56618,
            internal_client: "192.168.1.5".into(),
            internal_port: 56618,
            protocol: "UDP".into(),
            description: "Teredo".into(),
            lease_seconds: 0,
        };
        assert!(!teredo.exposes_abusable_service());
        assert!(teredo.never_expires(), "a zero lease is the router saying \"until deleted\"");
    }

    #[test]
    fn a_router_holding_the_public_address_is_the_edge() {
        let edge = NetworkEdge {
            router_wan: Ipv4Addr::new(172, 83, 7, 210),
            public: Ipv4Addr::new(172, 83, 7, 210),
        };
        assert_eq!(edge.shape(), Edge::Direct);
        assert!(edge.forwards_reach_the_internet());
    }

    #[test]
    fn a_private_wan_address_means_a_second_router_upstream() {
        // Measured on a real line: the router NATs to 10.0.12.184, and only the
        // box beyond it holds the address the internet answers to.
        let edge = NetworkEdge {
            router_wan: Ipv4Addr::new(10, 0, 12, 184),
            public: Ipv4Addr::new(172, 83, 7, 210),
        };
        assert_eq!(edge.shape(), Edge::DoubleNat);
        assert!(
            !edge.forwards_reach_the_internet(),
            "a forward on the inner router stops at the outer one"
        );
    }

    #[test]
    fn a_shared_address_space_wan_is_carrier_grade_nat() {
        for wan in [Ipv4Addr::new(100, 64, 0, 1), Ipv4Addr::new(100, 127, 255, 254)] {
            let edge = NetworkEdge { router_wan: wan, public: Ipv4Addr::new(172, 83, 7, 210) };
            assert_eq!(edge.shape(), Edge::CarrierGrade, "{wan} is RFC 6598 space");
        }
        // 100.128.0.0 is ordinary public space, one address past the range.
        let beyond = NetworkEdge {
            router_wan: Ipv4Addr::new(100, 128, 0, 1),
            public: Ipv4Addr::new(172, 83, 7, 210),
        };
        assert_eq!(beyond.shape(), Edge::DoubleNat);
    }

    #[test]
    fn the_external_address_is_read_from_the_soap_reply() {
        let reply = "<s:Body><u:GetExternalIPAddressResponse>\
                     <NewExternalIPAddress>10.0.12.184</NewExternalIPAddress>\
                     </u:GetExternalIPAddressResponse></s:Body>";
        assert_eq!(extract(reply, "NewExternalIPAddress").as_deref(), Some("10.0.12.184"));
    }

    #[test]
    fn a_lease_duration_is_read_from_a_mapping_entry() {
        let permanent = "<a><NewLeaseDuration>0</NewLeaseDuration></a>";
        let counting = "<a><NewLeaseDuration>604800</NewLeaseDuration></a>";
        assert_eq!(extract(permanent, "NewLeaseDuration").as_deref(), Some("0"));
        assert_eq!(extract(counting, "NewLeaseDuration").as_deref(), Some("604800"));
    }

    #[test]
    fn xml_fields_are_extracted_and_unescaped() {
        let document = "<a><NewInternalClient>192.168.1.5</NewInternalClient>\
                        <NewPortMappingDescription>Teredo 1.2.3.4-&gt;56618 UDP</NewPortMappingDescription></a>";
        assert_eq!(extract(document, "NewInternalClient").as_deref(), Some("192.168.1.5"));
        assert_eq!(
            extract(document, "NewPortMappingDescription").as_deref(),
            Some("Teredo 1.2.3.4->56618 UDP")
        );
        assert_eq!(extract(document, "Missing"), None);
    }

    #[test]
    fn gateway_urls_split_into_authority_and_path() {
        assert_eq!(
            split_url("http://192.168.1.1:56688/ctl/IPConn").unwrap(),
            ("192.168.1.1:56688".to_owned(), "/ctl/IPConn".to_owned())
        );
        assert_eq!(
            split_url("http://192.168.1.1:56688").unwrap(),
            ("192.168.1.1:56688".to_owned(), "/".to_owned())
        );
        assert!(split_url("https://example.com/").is_err());
    }

    /// Runs a fake service that replies with `script` to each connection it
    /// gets, and returns the port it is listening on.
    ///
    /// Each probe opens its own connection, so the script is served repeatedly
    /// rather than once.
    async fn fake_service(script: Vec<(usize, Vec<u8>)>) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else { return };
                let script = script.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    for (expect, reply) in script {
                        let mut scratch = vec![0_u8; expect.max(1)];
                        if expect > 0 && stream.read(&mut scratch).await.is_err() {
                            return;
                        }
                        if stream.write_all(&reply).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        port
    }

    #[tokio::test]
    async fn a_web_server_on_a_proxy_port_is_identified_as_a_web_server() {
        // The mistake this guards against: reading the port number instead of
        // asking the service. Plenty of devices listen on 1080 or 8888 and
        // serve ordinary HTTP.
        let port = fake_service(vec![(64, b"HTTP/1.1 404 Not Found\r\n\r\n".to_vec())]).await;

        let nature = probe_service(Ipv4Addr::LOCALHOST, port).await;
        assert_eq!(nature, ServiceNature::HttpServer { status: "HTTP/1.1 404 Not Found".to_owned() });
        assert!(!nature.is_proxy_software(), "a web server is not a proxy");
        assert!(!nature.is_open_relay());
    }

    #[tokio::test]
    async fn a_socks_proxy_that_refuses_is_still_recorded_as_a_proxy() {
        // 192.168.1.25 answered exactly like this: an anonymous session
        // accepted, then every destination refused with a code RFC 1928 does
        // not define. This was once reported as "not an open proxy and not the
        // cause", which cleared the prime suspect during an active infection.
        //
        // Residential proxy malware is outbound-connected — it relays only for
        // the controller it dialled — so refusing a probe from the LAN is what
        // the malware does too. The refusal is recorded as an observation and
        // never as an exoneration.
        let port = fake_service(vec![
            (5, vec![0x05, 0x00]),
            (32, vec![0x05, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
        ])
        .await;

        let nature = probe_service(Ipv4Addr::LOCALHOST, port).await;
        assert_eq!(
            nature,
            ServiceNature::Socks5 {
                accepts_anonymous: true,
                relayed: false,
                refusal_code: Some(0x09),
            }
        );
        assert!(nature.is_proxy_software(), "it speaks SOCKS5, refusal or not");
        assert!(!nature.is_open_relay(), "but it did not carry our traffic");
        assert!(nature.is_non_standard(), "0x09 is outside RFC 1928");
    }

    #[tokio::test]
    async fn a_socks_proxy_that_relays_is_caught() {
        let port = fake_service(vec![
            (5, vec![0x05, 0x00]),
            (32, vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]),
        ])
        .await;

        let nature = probe_service(Ipv4Addr::LOCALHOST, port).await;
        assert!(nature.is_open_relay(), "a 0x00 reply means it opened the connection");
        assert!(nature.describe().contains("RELAYED"));
    }

    #[tokio::test]
    async fn a_proxy_demanding_credentials_is_still_a_proxy() {
        let port = fake_service(vec![(5, vec![0x05, 0xFF])]).await;

        let nature = probe_service(Ipv4Addr::LOCALHOST, port).await;
        assert_eq!(
            nature,
            ServiceNature::Socks5 { accepts_anonymous: false, relayed: false, refusal_code: None }
        );
        assert!(nature.is_proxy_software());
        assert!(!nature.is_non_standard(), "declining a method is ordinary behaviour");
    }

    #[tokio::test]
    async fn an_http_proxy_that_tunnels_is_caught() {
        let port = fake_service(vec![(128, b"HTTP/1.1 200 Connection established\r\n\r\n".to_vec())]).await;

        let nature = probe_service(Ipv4Addr::LOCALHOST, port).await;
        assert_eq!(nature, ServiceNature::HttpProxy { relayed: true });
        assert!(nature.is_open_relay());
    }

    #[tokio::test]
    async fn a_port_that_says_nothing_is_reported_as_silent_not_as_clean() {
        // Port 8888 on the real device behaved this way. "We could not tell"
        // must stay distinct from "there is nothing here".
        let port = fake_service(vec![]).await;

        let nature = probe_service(Ipv4Addr::LOCALHOST, port).await;
        assert!(
            matches!(nature, ServiceNature::Silent | ServiceNature::Refused),
            "got {nature:?}"
        );
        assert!(!nature.is_open_relay(), "silence is not evidence of relaying");
        assert!(!nature.is_proxy_software(), "nor evidence of a proxy");
    }

    #[test]
    fn only_relaying_reads_as_proof() {
        // Exactly one observation is allowed to sound like proof, because only
        // one of them is.
        let observations = [
            ServiceNature::Socks5 { accepts_anonymous: true, relayed: true, refusal_code: None },
            ServiceNature::Socks5 {
                accepts_anonymous: true,
                relayed: false,
                refusal_code: Some(0x09),
            },
            ServiceNature::HttpProxy { relayed: false },
            ServiceNature::HttpServer { status: "HTTP/1.1 200 OK".to_owned() },
            ServiceNature::Silent,
            ServiceNature::Refused,
        ];
        assert_eq!(observations.iter().filter(|n| n.is_open_relay()).count(), 1);

        // And every observation has to describe itself in words.
        for nature in &observations {
            assert!(nature.describe().len() > 20, "{nature:?} describes itself too thinly");
        }
    }

    #[test]
    fn a_standard_refusal_is_not_called_non_standard() {
        // 0x02 is "connection not allowed by ruleset" — an ordinary answer.
        // Calling it exotic would manufacture suspicion out of nothing.
        let ordinary = ServiceNature::Socks5 {
            accepts_anonymous: true,
            relayed: false,
            refusal_code: Some(0x02),
        };
        assert!(!ordinary.is_non_standard());
    }
}
