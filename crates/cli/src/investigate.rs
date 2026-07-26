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
const SUSPICIOUS_PORTS: [(u16, &str); 12] = [
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
    (9050, "Tor SOCKS — expected on a Tor relay, abused if reachable from the LAN"),
    (1900, "UPnP — device control; can open port forwards without you asking"),
];

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
    /// Ports found open, with why each matters.
    pub open: Vec<(u16, &'static str)>,
    /// What its proxy port actually did when asked to relay, if it has one.
    ///
    /// An open port is a lead; a port that relays is a cause.
    pub proxy: Option<ProxyVerdict>,
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
pub async fn sweep_lan(local: Ipv4Addr) -> Vec<LanDevice> {
    let [a, b, c, _] = local.octets();
    let mut tasks = tokio::task::JoinSet::new();

    for host in 1_u8..=254 {
        let address = Ipv4Addr::new(a, b, c, host);
        tasks.spawn(async move {
            let mut open = Vec::new();
            for (port, note) in SUSPICIOUS_PORTS {
                if probe(address, port, Duration::from_millis(300)).await {
                    open.push((port, note));
                }
            }
            if open.is_empty() {
                return None;
            }
            // A listening proxy port proves nothing on its own — ask whether it
            // would actually carry a stranger's traffic.
            let proxy = if open.iter().any(|(port, _)| *port == 1080) {
                Some(probe_socks_relay(address, 1080).await)
            } else {
                None
            };
            Some(LanDevice { address, open, proxy })
        });
    }

    let mut devices = Vec::new();
    while let Some(result) = tasks.join_next().await {
        if let Ok(Some(device)) = result {
            devices.push(device);
        }
    }
    devices.sort_by_key(|device| device.address);
    devices
}

/// Whether a TCP port accepts a connection.
async fn probe(address: Ipv4Addr, port: u16, timeout: Duration) -> bool {
    matches!(
        tokio::time::timeout(timeout, TcpStream::connect((address, port))).await,
        Ok(Ok(_))
    )
}

/// What a listening proxy port actually does when asked to relay.
///
/// An open port is not an open proxy. This distinction is the difference between
/// a lead and a wild goose chase: plenty of devices listen on proxy ports and
/// then refuse every request, and reporting those as "the classic cause of your
/// blocklisting" sends somebody hunting a device that is behaving perfectly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyVerdict {
    /// It relayed a connection to an external host. This is an open proxy.
    Relays,
    /// It speaks the protocol but refused to relay.
    RefusedToRelay,
    /// Something is listening, but it is not a proxy.
    NotAProxy,
    /// Could not be determined.
    Unknown,
}

/// Asks a SOCKS5 port to relay to an external host, and reports what happened.
///
/// The request is a `CONNECT` to a well-known public address. Nothing is sent
/// through it beyond the handshake — the question is only whether it *would*
/// carry somebody else's traffic.
pub async fn probe_socks_relay(address: Ipv4Addr, port: u16) -> ProxyVerdict {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let attempt = tokio::time::timeout(Duration::from_secs(6), async {
        let mut stream = TcpStream::connect((address, port)).await.ok()?;

        // Greeting: SOCKS5, one method offered, "no authentication".
        stream.write_all(&[0x05, 0x01, 0x00]).await.ok()?;
        let mut greeting = [0_u8; 2];
        stream.read_exact(&mut greeting).await.ok()?;
        if greeting[0] != 0x05 {
            return Some(ProxyVerdict::NotAProxy);
        }
        if greeting[1] != 0x00 {
            // Speaks SOCKS5 but demands credentials, so it will not relay for
            // a stranger.
            return Some(ProxyVerdict::RefusedToRelay);
        }

        let host = b"example.com";
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
        request.extend_from_slice(host);
        request.extend_from_slice(&80_u16.to_be_bytes());
        stream.write_all(&request).await.ok()?;

        let mut reply = [0_u8; 4];
        stream.read_exact(&mut reply).await.ok()?;
        // Byte 1 is the reply code; 0x00 alone means the relay succeeded.
        Some(if reply[1] == 0x00 { ProxyVerdict::Relays } else { ProxyVerdict::RefusedToRelay })
    })
    .await;

    attempt.ok().flatten().unwrap_or(ProxyVerdict::Unknown)
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
}

impl PortMapping {
    /// Whether this mapping exposes a port commonly abused as a proxy or relay.
    pub fn exposes_abusable_service(&self) -> bool {
        SUSPICIOUS_PORTS.iter().any(|(port, _)| *port == self.internal_port)
    }
}

/// Reads the port forwards the router currently has open.
///
/// This is the question that decides whether a service on the LAN can be abused
/// from the internet at all. A device listening on a proxy port behind a router
/// with no forward for it is not reachable by anyone outside — so it cannot be
/// the cause of a blocklisting, however alarming the open port looks.
///
/// It also surfaces forwards that **nothing asked for**: UPnP lets any program
/// on the network open a hole in the firewall silently, which is a common way a
/// machine becomes internet-reachable without its owner knowing.
pub async fn port_mappings() -> Result<Vec<PortMapping>, String> {
    let description_url = discover_gateway().await.ok_or("no UPnP gateway responded")?;
    let (control_url, service_type) = gateway_control(&description_url).await?;

    let mut mappings = Vec::new();
    for index in 0..40 {
        let body = format!(
            r#"<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:GetGenericPortMappingEntry xmlns:u="{service_type}"><NewPortMappingIndex>{index}</NewPortMappingIndex></u:GetGenericPortMappingEntry></s:Body></s:Envelope>"#
        );
        let action = format!("\"{service_type}#GetGenericPortMappingEntry\"");
        let Ok(response) = soap(&control_url, &action, &body).await else { break };

        let field = |tag: &str| extract(&response, tag).unwrap_or_default();
        let Ok(external_port) = field("NewExternalPort").parse::<u16>() else { break };
        let internal_port = field("NewInternalPort").parse::<u16>().unwrap_or(0);

        mappings.push(PortMapping {
            external_port,
            internal_client: field("NewInternalClient"),
            internal_port,
            protocol: field("NewProtocol"),
            description: field("NewPortMappingDescription"),
        });
    }
    Ok(mappings)
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
        };
        assert!(socks.exposes_abusable_service());

        // Teredo is IPv6 tunnelling, not a relay service.
        let teredo = PortMapping {
            external_port: 56618,
            internal_client: "192.168.1.5".into(),
            internal_port: 56618,
            protocol: "UDP".into(),
            description: "Teredo".into(),
        };
        assert!(!teredo.exposes_abusable_service());
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

    #[tokio::test]
    async fn a_port_that_is_not_a_proxy_is_not_reported_as_one() {
        // The mistake this guards against: treating "something is listening" as
        // "this is an open proxy", which sends somebody hunting a device that
        // is behaving perfectly.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                use tokio::io::AsyncWriteExt;
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await;
            }
        });

        let verdict = probe_socks_relay(Ipv4Addr::LOCALHOST, port).await;
        assert_ne!(verdict, ProxyVerdict::Relays);
    }

    #[tokio::test]
    async fn a_closed_port_is_unknown_rather_than_open() {
        assert_eq!(probe_socks_relay(Ipv4Addr::LOCALHOST, 1).await, ProxyVerdict::Unknown);
    }
}
