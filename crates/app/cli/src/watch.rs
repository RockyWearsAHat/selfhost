//! `selfhost watch-dns` — the vantage point that can name the device.
//!
//! `doctor --scan-lan` sweeps the network and, on a real household, usually
//! reaches "nothing is implicated". That is an honest answer rather than a
//! failure: residential proxy malware is **outbound-connected**. It dials its
//! controller and relays down that tunnel, so it holds no port open, answers no
//! probe, and looks exactly like a sleeping appliance from the LAN.
//!
//! There is one moment it cannot hide. Before it can be told what to relay it
//! has to find its controller by name, and a name lookup goes to whichever
//! resolver the network handed out. Become that resolver and the question
//! "which device is doing this" has a direct answer: whichever one asks.
//!
//! # What this is, precisely
//!
//! A forwarding resolver. Every query is passed upstream unchanged and every
//! answer is returned unchanged — nothing is filtered, rewritten, or blocked,
//! because a diagnostic that breaks the household's internet gets turned off
//! before it finds anything. The only thing added is a record of who asked for
//! what, checked against [`crate::proxyware`].
//!
//! # What it cannot see
//!
//! - A device that was never pointed here. The router has to hand this machine
//!   out as the network's resolver, and devices keep their old lease until it
//!   renews.
//! - A device that resolves over DoH or DoT. That is reported separately
//!   ([`Notice::WentDark`]) because it explains an *absence* of findings.
//! - A device with a hardcoded resolver address, which some smart-TV firmware
//!   ships with. Blocking outbound 53 to everything except this machine is what
//!   closes that gap, and it is a router setting rather than something here.
//!
//! So silence here is not a clean bill of health, and [`Watch::report`] says so
//! in those words rather than printing a reassuring nothing.

use crate::proxyware::{self, ProxyService};
use selfhost_dns::wire;
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// How long to wait for the upstream resolver before giving up on one query.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest UDP payload accepted, matching the EDNS0 size clients advertise.
const MAX_UDP: usize = 4096;

/// One device caught asking for one service's domains.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sighting {
    /// The device that asked.
    pub client: Ipv4Addr,
    /// The service it asked for.
    pub service: ProxyService,
    /// The names it asked for, in the order first seen.
    pub names: Vec<String>,
    /// How many times it has asked.
    pub queries: u32,
}

/// Something worth printing the moment it happens.
///
/// Reported live rather than only at the end, because the reader is usually
/// standing in the room and can go and look at the device while it is talking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// A device asked for a residential proxy service's domain.
    Enrolled {
        /// The device that asked.
        client: Ipv4Addr,
        /// The name it asked for.
        name: String,
        /// What that name belongs to.
        service: ProxyService,
    },
    /// A device started resolving names somewhere this cannot observe.
    WentDark {
        /// The device.
        client: Ipv4Addr,
        /// The encrypted resolver it looked up.
        resolver: String,
    },
}

impl Notice {
    /// The line to print when this happens.
    pub fn render(&self) -> String {
        match self {
            Notice::Enrolled { client, name, service } => format!(
                "!! {client} asked for {name}\n   {} — {}",
                service.name, service.what_it_does
            ),
            Notice::WentDark { client, resolver } => format!(
                "·  {client} looked up {resolver}, an encrypted resolver — from here on, silence \
                 from this device proves nothing"
            ),
        }
    }
}

/// What has been observed so far.
///
/// Pure state with no I/O, so the judgement it encodes is testable without a
/// network.
#[derive(Debug, Default)]
pub struct Watch {
    /// Keyed by device and service, so one device asking twenty times is one
    /// finding rather than twenty.
    sightings: BTreeMap<(Ipv4Addr, &'static str), Sighting>,
    /// Devices seen looking up an encrypted resolver, and how often.
    elsewhere: BTreeMap<Ipv4Addr, u32>,
    /// Every device that asked anything, and how much.
    clients: BTreeMap<Ipv4Addr, u32>,
}

impl Watch {
    /// Records one question, and reports anything newly worth saying.
    ///
    /// Returns `Some` only the first time a given device is caught asking for a
    /// given service, so a device querying its controller every thirty seconds
    /// produces one line rather than a scrolling wall.
    pub fn observe(&mut self, client: Ipv4Addr, qname: &str) -> Option<Notice> {
        *self.clients.entry(client).or_default() += 1;

        if let Some(service) = proxyware::identify(qname) {
            let sighting =
                self.sightings.entry((client, service.name)).or_insert_with(|| Sighting {
                    client,
                    service,
                    names: Vec::new(),
                    queries: 0,
                });
            sighting.queries += 1;
            let name = qname.trim_end_matches('.').to_ascii_lowercase();
            if !sighting.names.contains(&name) {
                sighting.names.push(name.clone());
            }
            return (sighting.queries == 1).then_some(Notice::Enrolled { client, name, service });
        }

        if proxyware::resolves_dns_elsewhere(qname) {
            let count = self.elsewhere.entry(client).or_default();
            *count += 1;
            return (*count == 1).then(|| Notice::WentDark {
                client,
                resolver: qname.trim_end_matches('.').to_ascii_lowercase(),
            });
        }

        None
    }

    /// Devices caught asking for a proxy service, worst offender first.
    pub fn sightings(&self) -> Vec<&Sighting> {
        let mut found: Vec<&Sighting> = self.sightings.values().collect();
        found.sort_by(|a, b| b.queries.cmp(&a.queries).then(a.client.cmp(&b.client)));
        found
    }

    /// Total questions seen.
    pub fn queries(&self) -> u32 {
        self.clients.values().sum()
    }

    /// What the watch amounts to, and what to do about it.
    ///
    /// Written to be read on its own by somebody who did not run the scan, so it
    /// states the finding, the evidence, and the single next action — and, when
    /// there is no finding, the reason that is not the same as "nothing wrong".
    pub fn report(&self) -> String {
        let mut out = String::new();
        let devices = self.clients.len();
        let queries = self.queries();

        if self.sightings.is_empty() {
            out.push_str(&format!(
                "No device asked for a known residential proxy service.\n\
                 {queries} question(s) from {devices} device(s) went through here.\n\n\
                 This is not a clean bill of health, and there are three reasons it might be \
                 wrong:\n\
                 · a device is not using this machine as its resolver — check the router handed \
                 it out, and that the device's lease has renewed since;\n\
                 · a device resolves over DoH/DoT, which this cannot see;\n\
                 · the service is one this tool does not know by name.\n\
                 Close the first two by pointing the router's DHCP DNS here and blocking outbound \
                 53 and 853 for every device except this one.\n",
            ));
        } else {
            let found = self.sightings();
            // A client checks in with its controller on a timer; somebody
            // reading the service's website looks it up once and never again.
            // Calling a single lookup proof would accuse a device on the
            // strength of a browser tab.
            let repeated = found.iter().any(|sighting| sighting.queries > 1);
            out.push_str(if repeated { "Found it.\n\n" } else { "A lead, not yet a verdict.\n\n" });

            for sighting in &found {
                out.push_str(&format!(
                    "  {} is asking for {}\n    {}\n    Asked {} time(s) for {}\n",
                    sighting.client,
                    sighting.service.name,
                    sighting.service.what_it_does,
                    sighting.queries,
                    sighting.names.join(", "),
                ));
                if sighting.queries == 1 {
                    out.push_str(
                        "    Once only, so far. A browser that visited the site does exactly \
                         that — it is the coming back on a timer that tells them apart.\n",
                    );
                }
            }

            if repeated {
                out.push_str(
                    "\nRepeated lookups mean the client is running, not that somebody read the \
                     page. That is what earns an XBL listing: the device relays strangers' \
                     traffic, and some of it is spam leaving your address.\n",
                );
            } else {
                out.push_str(
                    "\nKeep this running. If the same device asks again unprompted — especially \
                     while nobody is using it — the client is running rather than somebody having \
                     read the page.\n",
                );
            }

            out.push_str(
                "\nWhat to do, in order:\n\
                 1. Take the device off the network — unplug it, or block it in the router.\n\
                 2. Work out how it was enrolled: a free VPN, a \"passive income\" app, a \
                 sideloaded streaming app, or an SDK inside something free. Uninstall it, or \
                 factory-reset the device if it is an appliance.\n\
                 3. Only then request delisting. The listing returns if the behaviour has not \
                 stopped, and a second listing is harder to clear than the first.\n",
            );
        }

        if !self.elsewhere.is_empty() {
            let devices = self
                .elsewhere
                .keys()
                .map(Ipv4Addr::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            out.push_str(&format!(
                "\nResolving elsewhere: {devices}. These looked up an encrypted resolver, so some \
                 of their traffic is invisible here.\n",
            ));
        }

        out
    }
}

/// Answers DNS for the local network, recording every question asked.
///
/// Serves UDP and TCP on the same port, because a truncated answer sends the
/// client straight to TCP and a resolver that only speaks UDP breaks large
/// lookups — which is the household's internet, not just this diagnostic.
///
/// Runs until one of the listeners fails; `Ctrl-C` handling belongs to the
/// caller, so the report can be printed on the way out.
pub async fn serve(
    bind: SocketAddr,
    upstream: SocketAddr,
    watch: Arc<Mutex<Watch>>,
) -> io::Result<()> {
    let datagram = Arc::new(UdpSocket::bind(bind).await?);
    let stream = TcpListener::bind(bind).await?;

    tokio::try_join!(
        serve_udp(Arc::clone(&datagram), upstream, Arc::clone(&watch)),
        serve_tcp(stream, upstream, watch),
    )?;
    Ok(())
}

/// The UDP half: one datagram in, one datagram out.
async fn serve_udp(
    socket: Arc<UdpSocket>,
    upstream: SocketAddr,
    watch: Arc<Mutex<Watch>>,
) -> io::Result<()> {
    let mut buffer = vec![0_u8; MAX_UDP];
    loop {
        let (read, from) = socket.recv_from(&mut buffer).await?;
        let query = buffer[..read].to_vec();
        note(&watch, from.ip(), &query);

        let socket = Arc::clone(&socket);
        tokio::spawn(async move {
            if let Some(answer) = forward_udp(&query, upstream).await {
                let _ = socket.send_to(&answer, from).await;
            }
        });
    }
}

/// Sends one query upstream and waits for its answer.
///
/// A fresh ephemeral socket per query, so answers cannot be confused between
/// concurrent lookups without tracking message ids ourselves.
async fn forward_udp(query: &[u8], upstream: SocketAddr) -> Option<Vec<u8>> {
    let work = async {
        let bind = if upstream.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind).await.ok()?;
        socket.send_to(query, upstream).await.ok()?;

        let mut buffer = vec![0_u8; MAX_UDP];
        let read = socket.recv(&mut buffer).await.ok()?;
        buffer.truncate(read);
        Some(buffer)
    };
    tokio::time::timeout(UPSTREAM_TIMEOUT, work).await.ok().flatten()
}

/// The TCP half: length-prefixed messages, as many as the client sends.
async fn serve_tcp(
    listener: TcpListener,
    upstream: SocketAddr,
    watch: Arc<Mutex<Watch>>,
) -> io::Result<()> {
    loop {
        let (client, from) = listener.accept().await?;
        let watch = Arc::clone(&watch);
        tokio::spawn(async move {
            let _ = relay_tcp(client, from.ip(), upstream, watch).await;
        });
    }
}

/// Relays one client's TCP connection, query by query.
async fn relay_tcp(
    mut client: TcpStream,
    from: IpAddr,
    upstream: SocketAddr,
    watch: Arc<Mutex<Watch>>,
) -> io::Result<()> {
    loop {
        let Some(query) = read_message(&mut client).await? else { return Ok(()) };
        note(&watch, from, &query);

        let exchange = async {
            let mut server = TcpStream::connect(upstream).await?;
            write_message(&mut server, &query).await?;
            read_message(&mut server).await
        };
        let answer = match tokio::time::timeout(UPSTREAM_TIMEOUT, exchange).await {
            Ok(Ok(Some(answer))) => answer,
            // Nothing usable came back. Closing is the honest reply: the client
            // then retries, rather than being handed a forged answer.
            _ => return Ok(()),
        };
        write_message(&mut client, &answer).await?;
    }
}

/// Reads one length-prefixed DNS message, or `None` at a clean end of stream.
async fn read_message(stream: &mut TcpStream) -> io::Result<Option<Vec<u8>>> {
    let mut length = [0_u8; 2];
    match stream.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut message = vec![0_u8; u16::from_be_bytes(length) as usize];
    stream.read_exact(&mut message).await?;
    Ok(Some(message))
}

/// Writes one length-prefixed DNS message.
async fn write_message(stream: &mut TcpStream, message: &[u8]) -> io::Result<()> {
    let length = u16::try_from(message.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "DNS message exceeds 65535 bytes"))?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(message).await
}

/// Records the question a message is asking, and prints anything new.
///
/// A message that carries no readable question is forwarded regardless — this
/// is a diagnostic sitting in the path of the household's DNS, and refusing to
/// pass anything it cannot parse would make it a fault of its own.
fn note(watch: &Mutex<Watch>, from: IpAddr, query: &[u8]) {
    let IpAddr::V4(client) = from else { return };
    let Ok(Some((name, _))) = wire::question_of(query) else { return };

    let notice = watch.lock().expect("the watch mutex is never held across a panic").observe(client, &name);
    if let Some(notice) = notice {
        println!("{}", notice.render());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(last: u8) -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, last)
    }

    #[test]
    fn a_device_asking_for_a_proxy_service_is_named() {
        // The whole point: an address, a service, and what that service does to
        // the device — enough to walk over and unplug the right box.
        let mut watch = Watch::default();
        let notice = watch.observe(device(5), "pawns.app").expect("a notice");

        match notice {
            Notice::Enrolled { client, name, service } => {
                assert_eq!(client, device(5));
                assert_eq!(name, "pawns.app");
                assert_eq!(service.name, "Pawns.app (IPRoyal)");
            }
            other => panic!("expected an enrolment notice, got {other:?}"),
        }
    }

    #[test]
    fn the_same_device_asking_again_does_not_repeat_itself() {
        // Proxy clients poll their controller constantly. One line per device
        // per service; the count carries the rest.
        let mut watch = Watch::default();
        assert!(watch.observe(device(5), "pawns.app").is_some());
        assert!(watch.observe(device(5), "api.pawns.app").is_none());
        assert!(watch.observe(device(5), "pawns.app").is_none());

        let sighting = watch.sightings()[0];
        assert_eq!(sighting.queries, 3);
        assert_eq!(sighting.names, vec!["pawns.app", "api.pawns.app"]);
    }

    #[test]
    fn ordinary_traffic_produces_nothing() {
        let mut watch = Watch::default();
        for ordinary in ["amazon.com", "device-metrics-us.amazon.com", "sonos.com", "apple.com"] {
            assert!(watch.observe(device(4), ordinary).is_none(), "{ordinary} must not be raised");
        }
        assert!(watch.sightings().is_empty());
        assert_eq!(watch.queries(), 4);
    }

    #[test]
    fn encrypted_dns_is_reported_as_an_absence_not_a_finding() {
        // A device on DoH is not doing anything wrong. It matters only because
        // silence from it afterwards proves nothing.
        let mut watch = Watch::default();
        let notice = watch.observe(device(31), "mozilla.cloudflare-dns.com").expect("a notice");
        assert!(matches!(notice, Notice::WentDark { .. }));
        assert!(watch.sightings().is_empty());
        assert!(watch.report().contains("invisible here"));
    }

    #[test]
    fn a_watch_with_no_findings_refuses_to_read_as_all_clear() {
        // The failure this module is most likely to cause: somebody leaves it
        // running, sees nothing, and concludes the network is clean when the
        // culprit simply never used this resolver.
        let mut watch = Watch::default();
        watch.observe(device(4), "amazon.com");

        let report = watch.report();
        assert!(report.contains("not a clean bill of health"));
        assert!(report.contains("DoH/DoT"));
        assert!(report.contains("router"));
    }

    #[test]
    fn a_finding_reports_the_device_the_service_and_the_order_to_do_things_in() {
        let mut watch = Watch::default();
        watch.observe(device(5), "iproyal.com");
        watch.observe(device(5), "iproyal.com");

        let report = watch.report();
        assert!(report.starts_with("Found it."));
        assert!(report.contains("192.168.1.5"));
        assert!(report.contains("IPRoyal"));
        assert!(report.contains("Asked 2 time(s)"));
        // Delisting before the cause is fixed earns a second, stickier listing.
        assert!(report.contains("Only then request delisting"));
    }

    #[test]
    fn a_single_lookup_is_a_lead_rather_than_a_verdict() {
        // Somebody reading honeygain.com in a browser produces one lookup and
        // no more. Reporting that as "found it" would accuse a device on the
        // strength of a browser tab, which is this project's recurring failure
        // pointed at a new observation.
        let mut watch = Watch::default();
        watch.observe(device(31), "honeygain.com");

        let report = watch.report();
        assert!(report.starts_with("A lead, not yet a verdict."));
        assert!(report.contains("A browser that visited the site does exactly that"));
        // The action list still stands — it is the verdict that is withheld.
        assert!(report.contains("Only then request delisting"));
    }

    #[test]
    fn two_devices_are_ranked_by_how_much_they_talk() {
        let mut watch = Watch::default();
        watch.observe(device(5), "honeygain.com");
        for _ in 0..4 {
            watch.observe(device(12), "packetstream.io");
        }

        let found = watch.sightings();
        assert_eq!(found[0].client, device(12), "the busiest device leads");
        assert_eq!(found[1].client, device(5));
    }

    #[test]
    fn a_query_recorded_from_the_wire_names_the_device() {
        // End to end across the wire format: the bytes a client actually sends
        // have to arrive as a question this can judge.
        let query = wire::encode_query(0x1234, "api.honeygain.com", wire::RecordType::A)
            .expect("a valid query");
        let (name, _) = wire::question_of(&query).expect("decodes").expect("has a question");

        let mut watch = Watch::default();
        let notice = watch.observe(device(5), &name).expect("a notice");
        assert!(matches!(notice, Notice::Enrolled { .. }));
    }
}
