//! A router's UPnP-IGD control client: discover the gateway once, then ask it
//! the two questions worth asking — what it forwards, and what WAN address it
//! believes it holds.
//!
//! Promoted out of the CLI's diagnostics so the authoritative-DNS updater can
//! reuse `GetExternalIPAddress` without the DNS crate depending on `cli`. The
//! updater treats the router as the **sovereign** source of the WAN IP: the box
//! that holds the forward is the box that knows the address, and a public
//! "what's my IP" echo answers a different question behind carrier-grade NAT —
//! it would report an address no forward points at.
//!
//! Everything on the wire here is ours. SSDP discovery, the description fetch,
//! and the SOAP POST are written directly against `tokio` sockets rather than
//! pulled from a UPnP dependency, consistent with the workspace policy that a
//! protocol on the wire is implemented in this workspace. The HTTP spoken to a
//! gateway is deliberately minimal (`HTTP/1.0`, `Connection: close`): a router's
//! control endpoint is a fixed, trusted peer on the LAN, not the adversarial
//! traffic [`selfhost_http`](../selfhost_http/index.html) is hardened against.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;

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
    /// Whether the router will hold this mapping open until something deletes it.
    pub fn never_expires(&self) -> bool {
        self.lease_seconds == 0
    }
}

/// A router's UPnP control interface, discovered once and queried repeatedly.
///
/// Discovery costs a multicast round trip and a description fetch, so the two
/// questions worth asking a gateway — what it forwards, and what address it
/// thinks it has — share one handle rather than each paying for their own. The
/// dynamic-IP updater discovers a `Gateway` once and then polls
/// [`Gateway::external_address`] on a timer, re-discovering only after a call
/// fails (routers reboot).
pub struct Gateway {
    control_url: String,
    service_type: String,
}

impl Gateway {
    /// Finds the router's UPnP gateway service on the local network.
    ///
    /// Returns a short human-readable reason on failure — no router answered the
    /// multicast probe, or the one that did exposes no WAN connection service —
    /// so a caller can log *why* it could not ask and retry, never mistaking the
    /// silence for an answer.
    pub async fn discover() -> Result<Self, String> {
        let description_url = discover_gateway().await.ok_or("no UPnP gateway responded")?;
        let (control_url, service_type) = gateway_control(&description_url).await?;
        Ok(Self { control_url, service_type })
    }

    /// Reads the port forwards the router currently has open.
    ///
    /// Surfaces forwards that **nothing asked for**: UPnP lets any program on the
    /// network open a hole in the firewall silently, which is a common way a
    /// machine becomes internet-reachable without its owner knowing.
    pub async fn mappings(&self) -> Vec<PortMapping> {
        let mut mappings = Vec::new();
        for index in 0..40 {
            let Ok(response) = self
                .invoke(
                    "GetGenericPortMappingEntry",
                    &format!("<NewPortMappingIndex>{index}</NewPortMappingIndex>"),
                )
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
    /// This is the sovereign WAN-IP source the dynamic-IP updater rewrites the
    /// apex A from: the gateway's own `GetExternalIPAddress`, not a public echo.
    /// An unreadable or absent answer is an `Err` the caller must ignore rather
    /// than write into a zone — a router that reboots yields *no* address, never
    /// `0.0.0.0`.
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
    // port-mapping table and the external address.
    for service in document.split("<service>").skip(1) {
        let Some(service_type) = extract(service, "serviceType") else { continue };
        if !service_type.contains("WANIPConnection") && !service_type.contains("WANPPPConnection") {
            continue;
        }
        let Some(control) = extract(service, "controlURL") else { continue };

        let control_url = if control.starts_with("http") {
            control
        } else {
            let base = description_url.split('/').take(3).collect::<Vec<_>>().join("/");
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

/// Sends a request to the gateway and returns the response body.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_external_address_is_read_from_the_soap_reply() {
        let reply = "<?xml version=\"1.0\"?><s:Envelope><s:Body>\
            <u:GetExternalIPAddressResponse>\
            <NewExternalIPAddress>203.0.113.7</NewExternalIPAddress>\
            </u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        assert_eq!(extract(reply, "NewExternalIPAddress").as_deref(), Some("203.0.113.7"));
    }

    #[test]
    fn xml_entities_in_a_field_are_decoded() {
        let document = "<a><NewPortMappingDescription>Teredo 1.2.3.4-&gt;56618 UDP\
            </NewPortMappingDescription></a>";
        assert_eq!(
            extract(document, "NewPortMappingDescription").as_deref(),
            Some("Teredo 1.2.3.4->56618 UDP"),
        );
    }

    #[test]
    fn a_relative_url_without_a_path_still_splits() {
        assert_eq!(split_url("http://192.168.1.1:5000"), Ok(("192.168.1.1:5000".into(), "/".into())));
        assert_eq!(
            split_url("http://192.168.1.1:5000/ctl/IPConn"),
            Ok(("192.168.1.1:5000".into(), "/ctl/IPConn".into())),
        );
        assert!(split_url("https://192.168.1.1/x").is_err());
    }
}
