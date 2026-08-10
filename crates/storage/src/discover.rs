//! Telling the network a share exists, without becoming a responder.
//!
//! **Pure.** This module derives the DNS-SD record set for the shares an
//! operator marked browsable and hands it back. It opens no socket, runs no
//! process, and answers no query. Publication belongs to the responder the
//! platform already runs, and the reason is worth stating before anything else
//! in this file, because writing an mDNS responder is the obvious implementation
//! and it is the wrong one.
//!
//! # Why we do not run a responder
//!
//! `mDNSResponder` (macOS) and Avahi (Linux) already own `224.0.0.251:5353`.
//! `std` sets `SO_REUSEADDR` but not `SO_REUSEPORT` on Darwin, so the bind
//! simply fails; and where it can be forced, the result is a *second* responder
//! that Bonjour treats as a conflicting peer and renames around — the operator's
//! share appears as "Vault (2)" and the original stops resolving. A second
//! responder on the LAN is also a new listening socket on a box whose entire
//! security posture is *one intended public surface*, which `docs/SECURITY.md`
//! would have to be amended to permit.
//!
//! So we derive and delegate. [`advertisements`] produces the service
//! descriptions in the shape a platform advertiser takes them — instance, service
//! type, host, port, and TXT pairs as separate values, which is exactly
//! `DNSServiceRegister`'s parameter list and exactly an Avahi service file's
//! elements — and [`records`] produces the same information as the DNS records
//! those advertisers will put on the wire, for the console to display and for a
//! test to assert against.
//!
//! # The honest per-platform truth, said here rather than discovered later
//!
//! [`Publication`] is the enum that refuses to pretend. Discovery behaves
//! differently on each platform and on one of them it is largely absent:
//!
//! - **macOS** — Bonjour publishes. `sharing -a` already advertises `_smb._tcp`
//!   for a share point it creates, and `DNSServiceRegister` from libSystem (an
//!   FFI declaration, no crate) registers the rest.
//! - **Linux** — Avahi publishes, from a service file in `/etc/avahi/services`.
//! - **Windows** — **it does not.** Windows has no general mDNS service
//!   responder: Explorer's *Network* node is populated by **WSD**, a
//!   SOAP-over-UDP device-discovery stack, and name resolution on the segment is
//!   **LLMNR**, neither of which is DNS-SD. `New-SmbShare` makes the machine
//!   discoverable to other Windows machines through WSD and that is all you get.
//!   A Mac on the same network will **not** see a Windows box's WebDAV share in
//!   Finder, and no amount of deriving `_webdavs._tcp` records here changes that,
//!   because nothing on that host will publish them. Implementing WSD is weeks
//!   of work for one icon in one file manager.
//!
//! # Advertisement is a disclosure, so it is opted into
//!
//! Only shares with `browsable = true` are advertised **by this module**, and
//! the configuration default is `false`. Telling every machine on the segment
//! that this box has a share called *Tax Returns* is information even when not
//! one byte of it is reachable, and it is information the operator has to ask to
//! give away.
//!
//! ## What `browsable = false` does not buy, said here rather than discovered
//!
//! It does not silence the operating system. `browsable` governs the records
//! [`advertisements`] derives and hands to a platform advertiser, and nothing
//! else — and on macOS the SMB export is a *second* advertiser this crate did
//! not start: `sharing -a` registers `_smb._tcp` with Bonjour for every share
//! point it creates, which is stated in [`crate::smb::macos`] and is why this
//! module never derives an `_smb._tcp` registration for a share the operating
//! system is already announcing. `New-SmbShare` does the equivalent through WSD.
//!
//! So a share with `browsable = false` **and** a `[shares.smb]` block is
//! announced on the segment under its SMB name, by the platform, whatever this
//! module derives. There is no flag on `sharing` or `New-SmbShare` that turns
//! that off, so it is not something this crate can enforce and pretending
//! otherwise would be the worst of both. The two switches an operator actually
//! has are: leave the `[shares.smb]` block out, and the share is reachable over
//! WebDAV and the console only, announced by nothing; or accept that exporting
//! a directory over SMB is telling the local network its name. `browsable` then
//! decides only whether *WebDAV* is announced beside it.
//!
//! # Why the records are derived rather than typed out
//!
//! [`records`] builds the `_webdavs._tcp` TXT record's `path` key from
//! [`crate::dav::multistatus::Mount`] — the same type the WebDAV responder uses
//! to build every `href` it sends. The advertised path and the served path are
//! therefore the same string by construction, mirroring the argument
//! `Mail::dns_records` makes for generating a zone from the mail configuration:
//! a service advertisement that disagrees with the service is a mount that
//! resolves and then fails, which is far harder to diagnose than no
//! advertisement at all.

use crate::dav::multistatus::Mount;
use crate::share::Shares;
use crate::smb::SMB_PORT;
use selfhost_dns::wire::{Record, RecordData};
use std::fmt;
use std::net::IpAddr;

/// The multicast DNS domain, in the trailing-dot form records are written in.
pub const LOCAL_DOMAIN: &str = "local.";

/// TTL for records that name a host — `SRV`, `A`, `AAAA`.
///
/// Two minutes, per RFC 6762 §10: a host's address can change when it moves
/// between networks, so anything pointing at one is deliberately short-lived.
pub const HOSTNAME_TTL: u32 = 120;

/// TTL for records that name a service — `PTR`, `TXT`.
///
/// Seventy-five minutes, per RFC 6762 §10. A service's *existence* is stable
/// even while the address behind it is not, and a long TTL here is what keeps a
/// browsing client from re-querying the segment every two minutes.
pub const SERVICE_TTL: u32 = 4500;

/// Longest DNS label, and so the longest host name or instance name.
pub const MAX_LABEL: usize = 63;

/// The DNS-SD service types this module derives.
///
/// A closed set. Each is a wire constant, not a name a caller may invent, and
/// each corresponds to something this deployment actually serves — an
/// advertisement for a service the box does not run is the failure this module's
/// derivation exists to make impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceType {
    /// Server Message Block file sharing, served by the operating system.
    Smb,
    /// WebDAV over plain HTTP.
    WebDav,
    /// WebDAV over TLS.
    ///
    /// A separate service type rather than a flag, because it is a separate
    /// registration in DNS-SD and clients look for one or the other. Finder in
    /// particular builds an `http://` URL from a `_webdav._tcp` record — so
    /// advertising a TLS endpoint under that type produces a mount that connects,
    /// fails to negotiate, and reports nothing useful.
    WebDavSecure,
    /// The device description Finder reads to choose an icon and a label.
    DeviceInfo,
}

impl ServiceType {
    /// The wire label, without the domain.
    pub fn label(self) -> &'static str {
        match self {
            Self::Smb => "_smb._tcp",
            Self::WebDav => "_webdav._tcp",
            Self::WebDavSecure => "_webdavs._tcp",
            Self::DeviceInfo => "_device-info._tcp",
        }
    }

    /// Reads a service type back from its label.
    pub fn from_label(text: &str) -> Option<Self> {
        match text {
            "_smb._tcp" => Some(Self::Smb),
            "_webdav._tcp" => Some(Self::WebDav),
            "_webdavs._tcp" => Some(Self::WebDavSecure),
            "_device-info._tcp" => Some(Self::DeviceInfo),
            _ => None,
        }
    }

    /// Whether this service is *browsed* for.
    ///
    /// `_device-info._tcp` is not: it carries no `PTR` and no `SRV`, and a client
    /// finds it only by querying `<host>._device-info._tcp.local.` directly after
    /// it has already found the host some other way. Emitting a `PTR` for it puts
    /// a phantom entry in every browser on the segment.
    pub fn is_browsable(self) -> bool {
        !matches!(self, Self::DeviceInfo)
    }
}

impl fmt::Display for ServiceType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.label())
    }
}

/// Why a host identity or an endpoint could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoverError {
    /// A host name is not a legal DNS label.
    BadHostname {
        /// The name refused.
        name: String,
        /// Which rule it broke.
        problem: &'static str,
    },
    /// An endpoint's target is not a legal DNS name.
    BadTarget {
        /// The name refused.
        name: String,
        /// Which rule it broke.
        problem: &'static str,
    },
    /// A device model string holds a character that cannot go in a TXT record.
    BadModel {
        /// The model refused.
        model: String,
    },
}

impl fmt::Display for DiscoverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadHostname { name, problem } => {
                write!(formatter, "{name:?} is not a usable host name: {problem}")
            }
            Self::BadTarget { name, problem } => {
                write!(formatter, "{name:?} is not a usable service host name: {problem}")
            }
            Self::BadModel { model } => write!(
                formatter,
                "the device model {model:?} holds a character a TXT record cannot carry; \
                 use printable ASCII without '=' "
            ),
        }
    }
}

impl std::error::Error for DiscoverError {}

/// Checks one DNS label.
fn check_label(text: &str) -> Result<(), &'static str> {
    if text.is_empty() {
        return Err("it is empty");
    }
    if text.len() > MAX_LABEL {
        return Err("it is longer than 63 characters");
    }
    if !text.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err("only letters, digits and hyphens are allowed");
    }
    if text.starts_with('-') || text.ends_with('-') {
        return Err("it starts or ends with a hyphen");
    }
    Ok(())
}

/// This machine, as the network is asked to know it.
///
/// Built rather than read: nothing here calls `gethostname`, because a pure
/// module that reached for the host's own name would be neither pure nor
/// testable, and because the name a deployment wants advertised is not always
/// the name the machine happens to have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostIdentity {
    hostname: String,
    model: String,
    addresses: Vec<IpAddr>,
}

impl HostIdentity {
    /// Checks a host name, a device model, and the addresses to advertise.
    ///
    /// `hostname` is the **label only** — `box`, not `box.local.` — because the
    /// domain is this module's to append and a caller that supplied both would
    /// eventually supply neither.
    ///
    /// `model` is the `_device-info._tcp` `model` key, which is what makes Finder
    /// draw a server rather than a generic box beside the name. `Xserve` and
    /// `RackMac` are the two values Apple's own clients recognise; anything else
    /// is legal and simply gets the default icon. It is a parameter rather than a
    /// constant because the right answer depends on the machine, and guessing it
    /// from `std::env::consts::OS` would be this module pretending to know
    /// something it cannot.
    pub fn new(
        hostname: &str,
        model: &str,
        addresses: Vec<IpAddr>,
    ) -> Result<Self, DiscoverError> {
        check_label(hostname).map_err(|problem| DiscoverError::BadHostname {
            name: hostname.to_owned(),
            problem,
        })?;
        // A TXT key/value pair is delimited by `=` and bounded by a length byte,
        // so a value holding either an `=` or a control character would be read
        // back as a different pair or as a truncated one.
        if model.is_empty()
            || model.contains('=')
            || model.chars().any(|c| c.is_control() || !c.is_ascii())
        {
            return Err(DiscoverError::BadModel { model: model.to_owned() });
        }
        Ok(Self {
            hostname: hostname.to_owned(),
            model: model.to_owned(),
            addresses,
        })
    }

    /// The host label, without a domain.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// The device model advertised under `_device-info._tcp`.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The addresses advertised for this host.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// The fully qualified multicast-DNS name of this host, `box.local.`.
    pub fn target(&self) -> String {
        format!("{}.{LOCAL_DOMAIN}", self.hostname)
    }
}

/// Where a WebDAV client should actually connect.
///
/// Separate from [`HostIdentity`] because it is frequently **not** the same
/// name. This deployment serves WebDAV through the console site on the reverse
/// proxy, which holds a certificate for that site's public name — so a client
/// pointed at `box.local.:443` connects, is offered a certificate for
/// `admin.example.com`, and refuses it. An operator whose LAN DNS resolves the
/// site name (this deployment's split-horizon setup does) should advertise the
/// site name; one whose does not should expect the warning and is better served
/// knowing why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DavEndpoint {
    target: String,
    port: u16,
    tls: bool,
}

impl DavEndpoint {
    /// Checks a target name and a port.
    ///
    /// `target` may be a bare label (`box`, which is completed to `box.local.`)
    /// or a fully qualified name (`admin.example.com`). Either way every label is
    /// checked, because the value ends up inside an `SRV` record.
    pub fn new(target: &str, port: u16, tls: bool) -> Result<Self, DiscoverError> {
        let trimmed = target.strip_suffix('.').unwrap_or(target);
        if trimmed.is_empty() {
            return Err(DiscoverError::BadTarget {
                name: target.to_owned(),
                problem: "it is empty",
            });
        }
        for label in trimmed.split('.') {
            check_label(label).map_err(|problem| DiscoverError::BadTarget {
                name: target.to_owned(),
                problem,
            })?;
        }
        let target = if trimmed.contains('.') {
            format!("{trimmed}.")
        } else {
            format!("{trimmed}.{LOCAL_DOMAIN}")
        };
        Ok(Self { target, port, tls })
    }

    /// The `SRV` target, fully qualified with a trailing dot.
    pub fn target(&self) -> &str {
        &self.target
    }

    /// The port WebDAV answers on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the endpoint is TLS, which decides the service type.
    pub fn tls(&self) -> bool {
        self.tls
    }

    /// The service type this endpoint must be advertised under.
    pub fn service(&self) -> ServiceType {
        if self.tls {
            ServiceType::WebDavSecure
        } else {
            ServiceType::WebDav
        }
    }
}

/// One service registration, in the shape a platform advertiser takes it.
///
/// The fields are separate rather than pre-formatted on purpose:
/// `DNSServiceRegister` takes the instance, the service type, the domain, the
/// host and the port as five arguments, and an Avahi service file has an element
/// for each. Handing an advertiser a pre-joined name would mean it had to take
/// the name apart again, and taking a DNS-SD name apart is where the escaping
/// rules bite.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    /// Which service this registers.
    pub service: ServiceType,
    /// The instance name, **unescaped** — the name a person reads.
    pub instance: String,
    /// The host the service runs on, fully qualified with a trailing dot.
    pub target: String,
    /// The port it answers on.
    pub port: u16,
    /// The TXT record's strings, each already `key=value`.
    ///
    /// Never more than one in anything this module derives, which is what makes
    /// [`Advertisement::records`]'s single-string `TXT` faithful; see that
    /// method's documentation.
    pub txt: Vec<String>,
}

impl Advertisement {
    /// The service's own name, `_smb._tcp.local.`.
    pub fn service_name(&self) -> String {
        format!("{}.{LOCAL_DOMAIN}", self.service.label())
    }

    /// This instance's full name, `Vault._smb._tcp.local.`, in presentation form.
    ///
    /// The instance label is escaped: RFC 6763 §4.3 allows any UTF-8 in an
    /// instance name, including the `.` that [`crate::share::SmbName`] permits,
    /// and a name with a dot in it read back unescaped would split into two
    /// labels and point at a service that does not exist.
    pub fn instance_name(&self) -> String {
        format!("{}.{}.{LOCAL_DOMAIN}", escape_instance(&self.instance), self.service.label())
    }

    /// The DNS records an advertiser will put on the wire for this registration.
    ///
    /// For display, for diagnostics, and for tests to assert against — **not**
    /// for encoding. Two reasons, both worth knowing before somebody feeds one of
    /// these to `selfhost_dns::wire::encode_response`:
    ///
    /// - the names are in *presentation* form, and `wire::write_name` splits on
    ///   `.` without honouring the `\.` escape this method emits;
    /// - `RecordData::Txt` holds the strings of a TXT record joined, which is
    ///   lossless here only because every advertisement this module derives
    ///   carries at most one string. That invariant is asserted in this module's
    ///   tests rather than assumed.
    ///
    /// Nothing in this project encodes them, because nothing in this project
    /// publishes them — which is the whole point of the module.
    pub fn records(&self) -> Vec<Record> {
        let instance = self.instance_name();
        let mut records = Vec::new();
        if self.service.is_browsable() {
            records.push(Record {
                name: self.service_name(),
                ttl: SERVICE_TTL,
                data: RecordData::Name(instance.clone()),
            });
            records.push(Record {
                name: instance.clone(),
                ttl: HOSTNAME_TTL,
                data: RecordData::Srv {
                    // One host offers each of these services, so there is nothing
                    // to prioritise between and nothing to weight.
                    priority: 0,
                    weight: 0,
                    port: self.port,
                    target: self.target.clone(),
                },
            });
        }
        records.push(Record {
            name: instance,
            ttl: SERVICE_TTL,
            data: RecordData::Txt(self.txt.join("")),
        });
        records
    }
}

/// Escapes an instance label for presentation form (RFC 1035 §5.1).
///
/// `\` first, then `.`, because escaping the dot introduces backslashes that
/// must not themselves be escaped again.
fn escape_instance(instance: &str) -> String {
    instance.replace('\\', "\\\\").replace('.', "\\.")
}

/// Derives every service registration for the browsable shares.
///
/// The rules, in the order they apply:
///
/// - a share that is not `browsable` contributes nothing, whatever else it has;
/// - a browsable share with an SMB export contributes `_smb._tcp` on
///   [`crate::smb::SMB_PORT`], under the export's own name — the name the
///   operating system will answer to, so the advertisement and the server agree;
/// - a browsable share contributes a WebDAV registration when `dav` is supplied,
///   under the share's id, carrying the `path` key built from the same
///   [`Mount`] the WebDAV responder answers on;
/// - one `_device-info._tcp` record is emitted for the host, and only when there
///   is at least one other registration — a device description for a box that
///   advertises nothing is an advertisement in itself.
pub fn advertisements(
    shares: &Shares,
    host: &HostIdentity,
    dav: Option<&DavEndpoint>,
) -> Vec<Advertisement> {
    let mut ads = Vec::new();

    for share in shares.all().iter().filter(|share| share.browsable()) {
        if let Some(export) = share.smb() {
            ads.push(Advertisement {
                service: ServiceType::Smb,
                instance: export.name.as_str().to_owned(),
                target: host.target(),
                port: SMB_PORT,
                // DNS-SD requires a TXT record for every registered service, and
                // `_smb._tcp` defines no keys — so it is present and empty, which
                // is one zero-length string on the wire.
                txt: Vec::new(),
            });
        }
        if let Some(dav) = dav {
            ads.push(Advertisement {
                service: dav.service(),
                instance: share.id().as_str().to_owned(),
                target: dav.target().to_owned(),
                port: dav.port(),
                txt: vec![format!("path={}", Mount::for_share(share.id()).prefix())],
            });
        }
    }

    if !ads.is_empty() {
        ads.push(Advertisement {
            service: ServiceType::DeviceInfo,
            instance: host.hostname().to_owned(),
            target: host.target(),
            // `_device-info._tcp` has no SRV record, so this port is never
            // emitted. It is written as the SMB port because that is what Apple's
            // own advertisers put there, and a reader comparing captures should
            // find the same number.
            port: SMB_PORT,
            txt: vec![format!("model={}", host.model())],
        });
    }

    ads
}

/// The whole record set: every registration's records, then the host's addresses.
///
/// The address records come last and appear once however many services point at
/// the host, because they describe the host rather than any one service — the
/// same shape a real mDNS response has, where several `SRV` records share one
/// `A`.
pub fn records(shares: &Shares, host: &HostIdentity, dav: Option<&DavEndpoint>) -> Vec<Record> {
    let ads = advertisements(shares, host, dav);
    if ads.is_empty() {
        return Vec::new();
    }
    let mut records: Vec<Record> = ads.iter().flat_map(Advertisement::records).collect();
    records.extend(address_records(host));
    records
}

/// The `A` and `AAAA` records for the host.
fn address_records(host: &HostIdentity) -> Vec<Record> {
    let name = host.target();
    host.addresses()
        .iter()
        .map(|address| Record {
            name: name.clone(),
            ttl: HOSTNAME_TTL,
            data: match address {
                IpAddr::V4(v4) => RecordData::A(*v4),
                IpAddr::V6(v6) => RecordData::Aaaa(*v6),
            },
        })
        .collect()
}

/// Who, if anyone, will actually publish these records on this platform.
///
/// The type that keeps this module honest. Deriving a record set is cheap and
/// looks like progress; whether anything puts it on the wire is the question an
/// operator is really asking, and on one of the three platforms the answer is
/// "nothing will".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Publication {
    /// macOS: `mDNSResponder`, reached through `DNSServiceRegister`, and already
    /// publishing `_smb._tcp` for any share point `sharing -a` created.
    Bonjour,
    /// Linux: Avahi, from a service file in `/etc/avahi/services`.
    Avahi,
    /// Windows: nothing publishes DNS-SD. `New-SmbShare` makes the machine
    /// visible to other Windows machines over WSD, and that is the whole of it.
    WindowsShareOnly,
    /// Everything else: no responder this module knows how to delegate to.
    None,
}

impl Publication {
    /// Whether a DNS-SD browser on the segment will see these records.
    pub fn publishes_dns_sd(self) -> bool {
        matches!(self, Self::Bonjour | Self::Avahi)
    }

    /// The wire spelling, for the console.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Bonjour => "bonjour",
            Self::Avahi => "avahi",
            Self::WindowsShareOnly => "windows-wsd",
            Self::None => "none",
        }
    }

    /// What an operator on this platform should actually expect, in one sentence.
    pub fn explanation(self) -> &'static str {
        match self {
            Self::Bonjour => {
                "Bonjour publishes these records. An SMB share point created by selfhost is \
                 already advertised by the operating system; the WebDAV registration is handed \
                 to DNSServiceRegister."
            }
            Self::Avahi => {
                "Avahi publishes these records from a service file in /etc/avahi/services. \
                 Nothing is advertised until that file is installed and Avahi is running."
            }
            Self::WindowsShareOnly => {
                "Windows does not publish DNS-SD. Its network view is built from WSD and LLMNR, \
                 neither of which carries these records, so an SMB share appears to other \
                 Windows machines and the WebDAV share is not advertised at all. Mount it by \
                 typing the address."
            }
            Self::None => {
                "No responder on this platform will publish these records. The shares are still \
                 reachable by address; they simply will not appear on their own."
            }
        }
    }
}

/// Which responder a platform has, by `std::env::consts::OS` name.
///
/// Takes the platform as a parameter rather than reading it, so the answer for
/// every platform is testable from any one of them — the same reason
/// [`HostIdentity`] takes a host name instead of asking the operating system for
/// one.
pub fn publication(platform: &str) -> Publication {
    match platform {
        "macos" | "ios" => Publication::Bonjour,
        "linux" | "freebsd" | "netbsd" | "openbsd" => Publication::Avahi,
        "windows" => Publication::WindowsShareOnly,
        _ => Publication::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{Reserved, Share, SmbExport, SmbName};
    use selfhost_dns::wire::RecordType;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::path::PathBuf;

    fn host() -> HostIdentity {
        HostIdentity::new(
            "box",
            "Xserve",
            vec![
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        )
        .expect("a legal identity")
    }

    fn share(id: &str, browsable: bool, smb: Option<&str>) -> Share {
        let reserved = Reserved::new(PathBuf::from("/var/selfhost/data"), None).expect("legal");
        let share = Share::new(
            &reserved,
            id,
            PathBuf::from(format!("/srv/{id}")),
            false,
            browsable,
            None,
        )
        .expect("a legal share");
        match smb {
            None => share,
            Some(name) => share.with_smb(SmbExport {
                name: SmbName::parse(name).expect("a legal share name"),
                encrypt: true,
                read_only: false,
            }),
        }
    }

    fn shares(list: Vec<Share>) -> Shares {
        Shares::new(list).expect("a legal set")
    }

    fn dav() -> DavEndpoint {
        DavEndpoint::new("admin.example.com", 443, true).expect("a legal endpoint")
    }

    #[test]
    fn a_share_that_was_not_marked_browsable_is_never_advertised() {
        // The configuration default is false, and this is the whole of what that
        // default buys: no record set at all, so nothing on the segment learns
        // the share exists.
        let set = shares(vec![share("vault", false, Some("Vault"))]);
        assert!(advertisements(&set, &host(), Some(&dav())).is_empty());
        assert!(records(&set, &host(), Some(&dav())).is_empty());
    }

    #[test]
    fn a_browsable_share_with_an_smb_export_is_advertised_under_the_export_name() {
        let set = shares(vec![share("vault", true, Some("Vault"))]);
        let ads = advertisements(&set, &host(), None);
        assert_eq!(ads.len(), 2, "the SMB service and the device info: {ads:?}");
        assert_eq!(ads[0].service, ServiceType::Smb);
        assert_eq!(ads[0].instance, "Vault", "the name the OS will answer to, not the share id");
        assert_eq!(ads[0].port, SMB_PORT);
        assert_eq!(ads[0].target, "box.local.");
        assert!(ads[0].txt.is_empty(), "_smb._tcp defines no TXT keys");
    }

    #[test]
    fn a_browsable_share_without_an_smb_export_is_still_advertised_over_webdav() {
        let set = shares(vec![share("photos", true, None)]);
        let ads = advertisements(&set, &host(), Some(&dav()));
        assert_eq!(ads.len(), 2);
        assert_eq!(ads[0].service, ServiceType::WebDavSecure);
        assert_eq!(ads[0].instance, "photos");
    }

    #[test]
    fn the_advertised_path_is_the_path_the_webdav_responder_actually_serves() {
        // Derived from the same Mount the responder builds every href from, so
        // the two cannot drift. A mount that resolves and then 404s is far harder
        // to diagnose than one that never appeared.
        let set = shares(vec![share("photos", true, None)]);
        let ads = advertisements(&set, &host(), Some(&dav()));
        let served = Mount::for_share(set.all()[0].id()).prefix().to_owned();
        assert_eq!(ads[0].txt, vec![format!("path={served}")]);
        assert_eq!(served, "/dav/photos");
    }

    #[test]
    fn a_tls_endpoint_is_advertised_as_webdavs_because_finder_builds_http_from_the_other() {
        let plain = DavEndpoint::new("box", 8080, false).expect("legal");
        assert_eq!(plain.service(), ServiceType::WebDav);
        assert_eq!(plain.target(), "box.local.", "a bare label is completed to .local.");
        assert_eq!(dav().service(), ServiceType::WebDavSecure);
        assert_eq!(dav().target(), "admin.example.com.", "a qualified name is left alone");
    }

    #[test]
    fn device_info_carries_no_ptr_and_no_srv_because_nobody_browses_for_it() {
        let set = shares(vec![share("vault", true, Some("Vault"))]);
        let ads = advertisements(&set, &host(), None);
        let info = ads.last().expect("a device-info advertisement");
        assert_eq!(info.service, ServiceType::DeviceInfo);
        assert_eq!(info.txt, vec!["model=Xserve".to_owned()]);

        let records = info.records();
        assert_eq!(records.len(), 1, "TXT only: {records:?}");
        assert!(matches!(records[0].data, RecordData::Txt(_)));
        assert_eq!(records[0].name, "box._device-info._tcp.local.");
    }

    #[test]
    fn a_box_that_advertises_nothing_does_not_describe_itself_either() {
        let set = shares(vec![share("vault", false, Some("Vault"))]);
        assert!(advertisements(&set, &host(), Some(&dav())).is_empty());
    }

    #[test]
    fn one_registration_becomes_a_ptr_an_srv_and_a_txt() {
        let set = shares(vec![share("vault", true, Some("Vault"))]);
        let ads = advertisements(&set, &host(), None);
        let records = ads[0].records();
        assert_eq!(records.len(), 3);

        assert_eq!(records[0].name, "_smb._tcp.local.");
        assert_eq!(records[0].ttl, SERVICE_TTL);
        assert_eq!(records[0].data, RecordData::Name("Vault._smb._tcp.local.".into()));

        assert_eq!(records[1].name, "Vault._smb._tcp.local.");
        assert_eq!(records[1].ttl, HOSTNAME_TTL);
        assert_eq!(
            records[1].data,
            RecordData::Srv {
                priority: 0,
                weight: 0,
                port: SMB_PORT,
                target: "box.local.".into()
            }
        );

        assert_eq!(records[2].data, RecordData::Txt(String::new()), "present and empty");
    }

    #[test]
    fn an_instance_name_with_a_dot_in_it_is_escaped_rather_than_split() {
        // `SmbName` permits `.`, and a DNS-SD instance label is one label however
        // many dots it holds. Unescaped, `Tax.Returns` would read back as two
        // labels and name a service nobody is running.
        let set = shares(vec![share("vault", true, Some("Tax.Returns"))]);
        let ads = advertisements(&set, &host(), None);
        assert_eq!(ads[0].instance, "Tax.Returns", "the name a person reads keeps its dot");
        assert_eq!(ads[0].instance_name(), "Tax\\.Returns._smb._tcp.local.");
    }

    #[test]
    fn every_derived_advertisement_carries_at_most_one_txt_string() {
        // The invariant that makes `records()`'s joined TXT faithful. If a future
        // key is added to any registration, this fails and the joining has to be
        // reconsidered rather than silently producing an unsplittable record.
        let set = shares(vec![
            share("vault", true, Some("Vault")),
            share("photos", true, None),
        ]);
        for ad in advertisements(&set, &host(), Some(&dav())) {
            assert!(ad.txt.len() <= 1, "{ad:?}");
        }
    }

    #[test]
    fn the_address_records_appear_once_however_many_services_point_at_the_host() {
        let set = shares(vec![
            share("vault", true, Some("Vault")),
            share("photos", true, None),
        ]);
        let records = records(&set, &host(), Some(&dav()));
        let addresses: Vec<&Record> = records
            .iter()
            .filter(|record| matches!(record.data, RecordData::A(_) | RecordData::Aaaa(_)))
            .collect();
        assert_eq!(addresses.len(), 2, "one A and one AAAA: {addresses:?}");
        assert!(addresses.iter().all(|record| record.name == "box.local."));
        assert!(addresses.iter().all(|record| record.ttl == HOSTNAME_TTL));
    }

    #[test]
    fn a_share_with_both_exports_is_advertised_under_both_services() {
        let set = shares(vec![share("vault", true, Some("Vault"))]);
        let ads = advertisements(&set, &host(), Some(&dav()));
        let services: Vec<ServiceType> = ads.iter().map(|ad| ad.service).collect();
        assert_eq!(
            services,
            vec![ServiceType::Smb, ServiceType::WebDavSecure, ServiceType::DeviceInfo]
        );
    }

    #[test]
    fn a_host_name_that_is_not_a_dns_label_is_refused() {
        for bad in ["", "-box", "box-", "box.local", "b o x", &"x".repeat(64)] {
            assert!(HostIdentity::new(bad, "Xserve", Vec::new()).is_err(), "{bad:?}");
        }
        assert!(HostIdentity::new("box", "", Vec::new()).is_err(), "an empty model");
        assert!(
            HostIdentity::new("box", "Xserve=1", Vec::new()).is_err(),
            "an = would split the TXT pair"
        );
    }

    #[test]
    fn an_endpoint_target_that_is_not_a_dns_name_is_refused() {
        for bad in ["", ".", "admin..example.com", "admin example.com", "-admin.example.com"] {
            assert!(DavEndpoint::new(bad, 443, true).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn every_service_type_survives_its_own_label() {
        for service in [
            ServiceType::Smb,
            ServiceType::WebDav,
            ServiceType::WebDavSecure,
            ServiceType::DeviceInfo,
        ] {
            assert_eq!(ServiceType::from_label(service.label()), Some(service));
            assert_eq!(service.to_string(), service.label());
        }
        assert_eq!(ServiceType::from_label("_afpovertcp._tcp"), None);
    }

    #[test]
    fn a_record_type_can_be_read_off_every_derived_record() {
        // A sanity check that the records really are the shapes the DNS crate
        // understands, rather than a private model wearing its names.
        let set = shares(vec![share("vault", true, Some("Vault"))]);
        for record in records(&set, &host(), Some(&dav())) {
            let kind = match &record.data {
                RecordData::Name(_) => RecordType::Ptr,
                RecordData::Srv { .. } => RecordType::Srv,
                RecordData::Txt(_) => RecordType::Txt,
                RecordData::A(_) => RecordType::A,
                RecordData::Aaaa(_) => RecordType::Aaaa,
                other => panic!("no other record type should be derived: {other:?}"),
            };
            assert!(kind.code() > 0);
        }
    }

    #[test]
    fn windows_is_told_the_truth_rather_than_promised_an_icon() {
        let windows = publication("windows");
        assert!(!windows.publishes_dns_sd());
        assert!(windows.explanation().contains("WSD"), "{}", windows.explanation());
        assert!(windows.explanation().contains("not advertised"), "{}", windows.explanation());
    }

    #[test]
    fn each_platform_names_its_own_responder() {
        assert_eq!(publication("macos"), Publication::Bonjour);
        assert_eq!(publication("linux"), Publication::Avahi);
        assert_eq!(publication("windows"), Publication::WindowsShareOnly);
        assert_eq!(publication("redox"), Publication::None);
        assert!(publication("macos").publishes_dns_sd());
        assert!(publication("linux").publishes_dns_sd());
        assert!(!publication("redox").publishes_dns_sd());
        for platform in ["macos", "linux", "windows", "redox"] {
            assert!(!publication(platform).tag().is_empty());
            assert!(!publication(platform).explanation().is_empty());
        }
    }
}
