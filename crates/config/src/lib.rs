//! The declarative shape of a deployment.
//!
//! This crate is the single source of truth for what a deployment *is*. The
//! proxy, the DNS server, and the mail server all read the same validated
//! [`Config`]; none of them holds a setting that does not originate here.
//!
//! Validation lives beside the schema so that a bad config fails at load with a
//! precise message, rather than as a service that refuses to bind twenty seconds
//! later with the reason buried in a log.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod autodiscover;
pub mod cidr;
pub mod desktop;
pub mod dns;
pub mod edit;
pub mod git;
pub mod home;
pub mod mail;
pub mod mesh;
pub mod pacc;
pub mod psl;
pub mod service;
pub mod storage;
pub mod validate;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

pub use cidr::Cidr;
pub use desktop::Desktop;
pub use dns::{Dns, RecordConfig, SoaConfig, ZoneConfig};
pub use git::{GitWatch, SelfUpdate};
pub use mail::{DkimConfig, Mail, MailBind, Mailbox, Relay};
pub use mesh::Mesh;
pub use service::{RestartPolicy, ServiceCatalog, ServiceSpec, StartMode};
pub use storage::{AccessConfig, AccessMode, ShareConfig, SmbConfig};
pub use validate::{ConfigError, Problem};

/// A complete deployment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Schema version. Refused if it is not `1`.
    pub version: u32,
    /// Host-wide settings.
    pub server: Server,
    /// Machines that can run workloads.
    #[serde(default)]
    pub nodes: Vec<Node>,
    /// Websites served by the proxy.
    #[serde(default)]
    pub sites: Vec<Site>,
    /// Authoritative DNS, when this machine serves its own zone. Absent → no DNS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Dns>,
    /// Mail, when this machine sends and receives for its domains. Absent → no mail.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mail: Option<Mail>,
    /// Selfhost's own repository, watched so a push updates this deployment
    /// itself — fetch, rebuild, restart. Absent → no self-update.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_update: Option<SelfUpdate>,
    /// Directories this machine serves over the console site, WebDAV and — where
    /// asked for — SMB. Empty means none: a share is declared, never discovered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub shares: Vec<ShareConfig>,
    /// Remote desktop. **Absent means the subsystem does not exist**: no agent is
    /// spawned and no route is served. This is the default, and it is the
    /// default because this is the one capability here that drives the machine
    /// rather than serving data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<Desktop>,
    /// The peer link a worker dials the owner over. Absent on the owner, which
    /// needs nothing beyond its `[[nodes]]` block; a worker with this section
    /// still binds nothing at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh: Option<Mesh>,
}

/// The smallest valid deployment, used by every module's example test as the
/// document its own `EXAMPLE` block is appended to.
///
/// Kept here rather than copied into three test modules so that a change to what
/// a minimal deployment requires breaks one line instead of three.
#[cfg(test)]
pub(crate) const BASE_DOCUMENT: &str = r#"version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "example"
domains = ["example.com"]
static_root = "./public"
"#;

/// Comments out a documented example block, so it can be shipped in a config
/// file without arming anything.
///
/// Every module that describes an opt-in section carries its example as *live*
/// TOML — [`desktop::EXAMPLE`], [`mesh::EXAMPLE`], [`storage::EXAMPLE`] — so the
/// crate's own tests parse and validate the exact text an operator is shown. The
/// shipped `selfhost.config.toml` and the `selfhost init` template then emit that
/// same text through this function, which is the only difference between the
/// documentation and the deployment.
///
/// A line that is already a comment is left alone rather than double-hashed, so
/// the prose reads as prose and the settings read as settings — the style the
/// console-site block in `selfhost.config.toml` established. The function is
/// therefore idempotent: commenting an already-commented block changes nothing.
pub fn commented(block: &str) -> String {
    let mut out = String::with_capacity(block.len() + block.lines().count());
    for line in block.lines() {
        if !(line.is_empty() || line.starts_with('#')) {
            out.push('#');
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// Host-wide settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    /// Address the proxy binds for cleartext HTTP. Also serves ACME challenges.
    #[serde(default = "default_http_bind")]
    pub http_bind: String,
    /// Address the proxy binds for TLS.
    #[serde(default = "default_https_bind")]
    pub https_bind: String,
    /// Contact address for certificate expiry notices.
    pub acme_email: String,
    /// Which ACME environment to use.
    #[serde(default)]
    pub acme: AcmeEnvironment,
    /// Directory holding persistent state: certificates, databases, mail, backups.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// Address the service-control API binds.
    ///
    /// Loopback, and refused if it is not — whoever reaches this port controls
    /// every service on the machine. The console reaches a remote daemon by
    /// tunnelling this port over SSH, so the encryption and the authentication
    /// are OpenSSH's rather than something invented here.
    #[serde(default = "default_admin_bind")]
    pub admin_bind: String,
    /// Host firewall policy for the public listeners.
    #[serde(default)]
    pub firewall: Firewall,
}

fn default_http_bind() -> String {
    "0.0.0.0:80".to_owned()
}

fn default_https_bind() -> String {
    "0.0.0.0:443".to_owned()
}

fn default_data_dir() -> PathBuf {
    PathBuf::from("./data")
}

/// The admin API's default bind: loopback, on a port unlikely to collide.
fn default_admin_bind() -> String {
    "127.0.0.1:9191".to_owned()
}

/// Which certificate authority to ask for certificates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcmeEnvironment {
    /// Untrusted certificates from a CA with generous rate limits.
    ///
    /// The default, deliberately. Production Let's Encrypt permits only five
    /// duplicate certificates per week, and a misconfigured retry loop against a
    /// domain that does not yet resolve here will exhaust that in minutes.
    #[default]
    Staging,
    /// Browser-trusted certificates, with strict rate limits.
    Production,
    /// A self-signed certificate generated locally. No network, no rate limit.
    SelfSigned,
}

/// Who, off this machine, may reach the public listeners.
///
/// The firewall's whole job is to make this true: a bind on `0.0.0.0` is
/// reachable by anyone the *network* lets through, and this narrows that to the
/// operator's intent. Modelled after the SCM/GitWatch enums — a closed set,
/// lowercase on the wire and in TOML, with a default that cannot publish
/// anything.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scope {
    /// This machine only. No inbound rule is emitted; the default block is the
    /// whole policy. The safe default, for the reason `init` binds loopback.
    #[default]
    Loopback,
    /// The local network: RFC1918, CGNAT (100.64/10), link-local, and loopback.
    Lan,
    /// Anywhere. Required before a site is reachable from outside.
    Internet,
}

impl Scope {
    /// The wire and TOML spelling of this scope.
    ///
    /// One word serves both the firewall's hand-written JSON and this crate's
    /// validation, so the two can never disagree about how a scope is spelled.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Loopback => "loopback",
            Self::Lan => "lan",
            Self::Internet => "internet",
        }
    }

    /// Parses a scope from its wire/TOML spelling, or `None` for anything else.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "loopback" => Some(Self::Loopback),
            "lan" => Some(Self::Lan),
            "internet" => Some(Self::Internet),
            _ => None,
        }
    }
}

/// Host firewall management, off by default so a first run changes no rules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Firewall {
    /// Whether the daemon reconciles the host firewall at all.
    ///
    /// Default `false`: an unmanaged firewall is left exactly as the operator
    /// set it, no inbound allowance is derived, and reconciliation asserts
    /// nothing. Turning this on hands the daemon authority to open and close
    /// inbound ports for the public listeners.
    #[serde(default)]
    pub manage: bool,
    /// Who may reach `http_bind`/`https_bind`. Ignored while `manage` is false.
    #[serde(default)]
    pub scope: Scope,
}

/// The role a node plays.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Holds every stateful service: databases, mail, certificates.
    ///
    /// Exactly one node is the owner. Two machines each running their own copy
    /// of the database is two different websites, not one load-balanced website.
    Owner,
    /// A stateless application runner.
    Worker,
}

/// A machine that can run workloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Node {
    /// Identifier referenced by site instances.
    pub name: String,
    /// What this machine is responsible for.
    pub role: Role,
    /// Private mesh address, assigned when the node joins.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mesh_ip: Option<String>,
}

/// A website.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Site {
    /// Identifier used for log files and diagnostics.
    pub name: String,
    /// Every hostname that serves this site. The first is canonical.
    pub domains: Vec<String>,
    /// Static file root, relative to the config file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_root: Option<PathBuf>,
    /// Serve `index.html` for unmatched paths, for client-side routing.
    #[serde(default)]
    pub spa: bool,
    /// Path prefixes routed to the application rather than to static files.
    #[serde(default)]
    pub app_paths: Vec<String>,
    /// Application instances the proxy balances across.
    #[serde(default)]
    pub instances: Vec<Instance>,
    /// How instances are probed for health.
    #[serde(default)]
    pub health: Health,
    /// Redirect every non-canonical domain to the canonical one.
    #[serde(default = "default_true")]
    pub canonical_redirect: bool,
    /// Client source addresses allowed to reach this site, in CIDR notation
    /// (IPv4 and IPv6, e.g. `10.66.0.0/24` or a bare address for one host).
    ///
    /// Empty — the default, so existing configs keep parsing — leaves the site
    /// open to everyone. Non-empty turns the proxy's per-site gate on: a
    /// request whose source address matches no entry is refused, except on the
    /// always-public paths (ACME challenges and deploy webhooks).
    #[serde(default)]
    pub allowed_cidrs: Vec<String>,
    /// Marks this site as the built-in admin console: the proxy serves its
    /// hand-rolled SPA from `static_root` and relays `/api/*` to the loopback
    /// admin API at `server.admin_bind`. At most one site may set this, and it
    /// must be gated by `allowed_cidrs` — a console is never left open.
    #[serde(default)]
    pub console: bool,
}

fn default_true() -> bool {
    true
}

/// One running copy of an application, pinned to a node and a port.
///
/// Instances are listed explicitly rather than derived from a count: two copies
/// on one machine must not share a port, and writing both ports makes a
/// collision visible in the config instead of at boot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    /// Name of the node running this instance.
    pub node: String,
    /// Port the instance listens on.
    pub port: u16,
}

/// Active health checking.
///
/// Probes run on their own timer rather than inferring health from failed user
/// requests. Passive checking means a visitor absorbs the error that reveals a
/// dead node; active checking removes it from rotation before anyone arrives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Health {
    /// Path probed on each instance.
    #[serde(default = "default_health_path")]
    pub path: String,
    /// Seconds between probes.
    #[serde(default = "default_interval")]
    pub interval_secs: u64,
    /// Seconds before a probe is abandoned.
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Consecutive failures before an instance leaves rotation.
    #[serde(default = "default_threshold")]
    pub unhealthy_after: u32,
    /// Consecutive successes before an instance rejoins.
    ///
    /// Greater than one so a flapping instance does not oscillate in and out of
    /// rotation on every probe.
    #[serde(default = "default_threshold")]
    pub healthy_after: u32,
}

fn default_health_path() -> String {
    "/".to_owned()
}

fn default_interval() -> u64 {
    10
}

fn default_timeout() -> u64 {
    3
}

fn default_threshold() -> u32 {
    2
}

impl Default for Health {
    fn default() -> Self {
        Self {
            path: default_health_path(),
            interval_secs: default_interval(),
            timeout_secs: default_timeout(),
            unhealthy_after: default_threshold(),
            healthy_after: default_threshold(),
        }
    }
}

impl Site {
    /// The canonical hostname, which is the first listed.
    pub fn canonical(&self) -> &str {
        self.domains.first().map(String::as_str).unwrap_or(&self.name)
    }

    /// Whether a request path should be routed to the application.
    ///
    /// A site with instances but no declared prefixes routes everything to the
    /// application, which is the shape of a site with no static assets.
    pub fn routes_to_app(&self, path: &str) -> bool {
        if self.instances.is_empty() {
            return false;
        }
        if self.app_paths.is_empty() {
            return true;
        }
        self.app_paths.iter().any(|prefix| path_matches(prefix, path))
    }

    /// Whether a client at `ip` may reach this site.
    ///
    /// An empty `allowed_cidrs` means the site is open to everyone; otherwise
    /// the address must fall inside at least one listed network. An entry that
    /// fails to parse permits nothing — validation already rejects such a
    /// config, but if one is ever reached the gate fails closed, not open.
    pub fn permits(&self, ip: IpAddr) -> bool {
        self.allowed_cidrs.is_empty()
            || self
                .allowed_cidrs
                .iter()
                .any(|entry| Cidr::parse(entry).is_ok_and(|cidr| cidr.contains(ip)))
    }
}

/// Whether `path` falls under `prefix`, where a trailing `*` matches any suffix.
///
/// A prefix without a wildcard matches the exact path or a path continuing at a
/// segment boundary, so `/api` matches `/api` and `/api/health` but never
/// `/apidocs`.
fn path_matches(prefix: &str, path: &str) -> bool {
    match prefix.strip_suffix('*') {
        Some(stem) => path.starts_with(stem),
        None => {
            path == prefix
                || (path.starts_with(prefix) && path.as_bytes().get(prefix.len()) == Some(&b'/'))
        }
    }
}

impl Config {
    /// Parses and validates a config from TOML text.
    pub fn parse(text: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(text).map_err(|e| ConfigError::Syntax(e.to_string()))?;
        config.validate()?;
        Ok(config)
    }

    /// Reads and validates a config from disk.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Unreadable {
            path: path.to_path_buf(),
            source: e.to_string(),
        })?;
        Self::parse(&text)
    }

    /// The node holding stateful services.
    ///
    /// Returns `None` only for a config that has not been validated, since
    /// validation requires exactly one owner.
    pub fn owner(&self) -> Option<&Node> {
        self.nodes.iter().find(|n| n.role == Role::Owner)
    }

    /// Looks up a node by name.
    pub fn node(&self, name: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.name == name)
    }

    /// Maps each hostname to the site serving it.
    ///
    /// Built once at load so request routing is a map lookup rather than a scan
    /// over every site's domain list on every request.
    pub fn host_map(&self) -> BTreeMap<String, &Site> {
        let mut map = BTreeMap::new();
        for site in &self.sites {
            for domain in &site.domains {
                map.insert(domain.to_ascii_lowercase(), site);
            }
        }
        map
    }

    /// The socket address an instance is reached at.
    ///
    /// An instance on the owner is reached over loopback, because that is the
    /// only interface application processes bind. An instance on a worker is
    /// reached over the private mesh — never a public address, so an application
    /// port is never exposed to the internet even on a remote machine.
    pub fn instance_address(&self, instance: &Instance) -> Option<String> {
        let node = self.node(&instance.node)?;
        match node.role {
            Role::Owner => Some(format!("127.0.0.1:{}", instance.port)),
            Role::Worker => node.mesh_ip.as_ref().map(|ip| format!("{ip}:{}", instance.port)),
        }
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} site(s) across {} node(s)", self.sites.len(), self.nodes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_server() -> Server {
        Server {
            http_bind: default_http_bind(),
            https_bind: default_https_bind(),
            acme_email: "a@b.com".into(),
            acme: AcmeEnvironment::SelfSigned,
            data_dir: default_data_dir(),
            admin_bind: default_admin_bind(),
            firewall: Firewall::default(),
        }
    }

    #[test]
    fn path_prefix_respects_segment_boundaries() {
        assert!(path_matches("/api", "/api"));
        assert!(path_matches("/api", "/api/health"));
        // The bug this guards: a prefix must not match a longer word, or
        // /apidocs would be proxied to the API and 404 there.
        assert!(!path_matches("/api", "/apidocs"));
        assert!(!path_matches("/api", "/apiv2/x"));
    }

    #[test]
    fn wildcard_prefix_matches_any_suffix() {
        assert!(path_matches("/api/*", "/api/health"));
        assert!(path_matches("/assets/*", "/assets/app.js"));
        assert!(!path_matches("/api/*", "/other"));
    }

    #[test]
    fn a_site_with_no_instances_never_routes_to_an_app() {
        let site = Site {
            name: "static".into(),
            domains: vec!["example.com".into()],
            static_root: Some("./public".into()),
            spa: false,
            app_paths: vec!["/api/*".into()],
            instances: vec![],
            health: Health::default(),
            canonical_redirect: true,
            allowed_cidrs: vec![],
            console: false,
        };
        assert!(!site.routes_to_app("/api/health"));
    }

    #[test]
    fn a_site_with_no_declared_prefixes_routes_everything_to_the_app() {
        let site = Site {
            name: "api".into(),
            domains: vec!["api.example.com".into()],
            static_root: None,
            spa: false,
            app_paths: vec![],
            instances: vec![Instance { node: "home".into(), port: 5050 }],
            health: Health::default(),
            canonical_redirect: true,
            allowed_cidrs: vec![],
            console: false,
        };
        assert!(site.routes_to_app("/anything"));
    }

    #[test]
    fn worker_instances_are_addressed_over_the_mesh_never_publicly() {
        let config = Config {
            version: 1,
            server: minimal_server(),
            nodes: vec![
                Node { name: "home".into(), role: Role::Owner, mesh_ip: None },
                Node { name: "shed".into(), role: Role::Worker, mesh_ip: Some("10.77.0.2".into()) },
            ],
            sites: vec![],
            dns: None,
            mail: None,
            self_update: None,
            shares: vec![],
            desktop: None,
            mesh: None,
        };

        assert_eq!(
            config.instance_address(&Instance { node: "home".into(), port: 5050 }).as_deref(),
            Some("127.0.0.1:5050")
        );
        assert_eq!(
            config.instance_address(&Instance { node: "shed".into(), port: 5050 }).as_deref(),
            Some("10.77.0.2:5050")
        );
        // A worker that has not joined the mesh has no address at all, rather
        // than silently falling back to something reachable from the internet.
        assert_eq!(config.instance_address(&Instance { node: "ghost".into(), port: 1 }), None);
    }

    #[test]
    fn host_map_is_case_insensitive_and_covers_every_alias() {
        let config = Config {
            version: 1,
            server: minimal_server(),
            nodes: vec![Node { name: "home".into(), role: Role::Owner, mesh_ip: None }],
            sites: vec![Site {
                name: "levelup".into(),
                domains: vec!["Example.COM".into(), "www.example.com".into()],
                static_root: None,
                spa: false,
                app_paths: vec![],
                instances: vec![Instance { node: "home".into(), port: 5050 }],
                health: Health::default(),
                canonical_redirect: true,
                allowed_cidrs: vec![],
                console: false,
            }],
            dns: None,
            mail: None,
            self_update: None,
            shares: vec![],
            desktop: None,
            mesh: None,
        };

        let map = config.host_map();
        assert!(map.contains_key("example.com"));
        assert!(map.contains_key("www.example.com"));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn round_trips_through_toml() {
        let text = r#"
version = 1

[server]
acme_email = "a@b.com"
acme = "self-signed"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "levelup"
domains = ["example.com"]
static_root = "./public"
spa = true
app_paths = ["/api/*"]

[[sites.instances]]
node = "home"
port = 5050

[sites.health]
path = "/api/health"
"#;
        let config = Config::parse(text).unwrap();
        assert_eq!(config.sites.len(), 1);
        assert_eq!(config.sites[0].canonical(), "example.com");
        assert_eq!(config.sites[0].health.path, "/api/health");
        assert_eq!(config.server.acme, AcmeEnvironment::SelfSigned);
        // Unspecified health fields fall back to defaults rather than zero.
        assert_eq!(config.sites[0].health.interval_secs, 10);
    }

    #[test]
    fn gating_fields_parse_from_toml_and_default_open() {
        let text = r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "console"
domains = ["admin.example.com"]
static_root = "./console"
console = true
allowed_cidrs = ["10.66.0.0/24", "fd00::/8"]

[[sites]]
name = "open"
domains = ["example.com"]
static_root = "./public"
"#;
        let config = Config::parse(text).unwrap();
        assert!(config.sites[0].console);
        assert_eq!(config.sites[0].allowed_cidrs, vec!["10.66.0.0/24", "fd00::/8"]);
        // Old configs never mention the new fields; they must default open.
        assert!(!config.sites[1].console);
        assert!(config.sites[1].allowed_cidrs.is_empty());
    }

    #[test]
    fn permits_is_open_when_ungated_and_matches_both_families_when_gated() {
        let mut site = Site {
            name: "console".into(),
            domains: vec!["admin.example.com".into()],
            static_root: Some("./console".into()),
            spa: false,
            app_paths: vec![],
            instances: vec![],
            health: Health::default(),
            canonical_redirect: true,
            allowed_cidrs: vec![],
            console: true,
        };
        let vpn_client: IpAddr = "10.66.0.2".parse().unwrap();
        let stranger: IpAddr = "203.0.113.9".parse().unwrap();
        let v6_client: IpAddr = "fd00::5".parse().unwrap();

        // No gate: everyone is permitted.
        assert!(site.permits(stranger));

        site.allowed_cidrs = vec!["10.66.0.0/24".into(), "fd00::/8".into()];
        assert!(site.permits(vpn_client));
        assert!(site.permits(v6_client));
        assert!(!site.permits(stranger));

        // A malformed entry permits nothing — the gate fails closed.
        site.allowed_cidrs = vec!["garbage".into()];
        assert!(!site.permits(vpn_client));
    }

    #[test]
    fn the_deployments_own_config_file_still_loads_and_arms_nothing_new() {
        // `selfhost.config.toml` is gitignored — it carries this box's hostnames
        // and mailbox addresses — so it is read at run time rather than compiled
        // in, and a checkout that does not have one simply has nothing to check.
        // Where it *is* present, the documented example blocks appended to it
        // must leave it loading exactly as before: commented out is the whole
        // point, and a stray uncommented line would arm a subsystem by accident.
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../selfhost.config.toml");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return;
        };
        let config = Config::parse(&text)
            .unwrap_or_else(|why| panic!("{} no longer loads: {why}", path.display()));
        assert!(config.shares.is_empty(), "the shares example must stay commented out");
        assert!(config.desktop.is_none(), "the desktop example must stay commented out");
        assert!(config.mesh.is_none(), "the mesh example must stay commented out");
    }

    #[test]
    fn commenting_a_block_hashes_settings_leaves_prose_and_is_idempotent() {
        let block = "# why this exists\n\nenabled = false\n  [sub.table]\n";
        let once = commented(block);
        assert_eq!(once, "# why this exists\n\n#enabled = false\n#  [sub.table]\n");
        // Idempotent, because `selfhost init` and the shipped file may both pass
        // text through this and neither should produce `##`.
        assert_eq!(commented(&once), once);
    }

    #[test]
    fn scope_defaults_closed_so_a_first_run_publishes_nothing() {
        // The whole safety argument rests on this: an omitted scope is loopback,
        // not "anywhere". If this ever flips, a bind on 0.0.0.0 becomes public
        // the moment the firewall is managed, which is the opposite of the intent.
        assert_eq!(Scope::default(), Scope::Loopback);
        assert!(!Firewall::default().manage);
        assert_eq!(Firewall::default().scope, Scope::Loopback);
    }

    #[test]
    fn a_scope_tag_round_trips_and_matches_its_serde_spelling() {
        for scope in [Scope::Loopback, Scope::Lan, Scope::Internet] {
            assert_eq!(Scope::from_tag(scope.tag()), Some(scope));
            // tag() must equal the serde wire form, or firewall JSON and config
            // TOML would spell the same scope two different ways.
            let wire = toml::to_string(&Wrap { scope }).unwrap();
            assert!(wire.contains(scope.tag()), "{wire}");
        }
        assert_eq!(Scope::from_tag("public"), None);
    }

    #[test]
    fn the_firewall_sub_table_parses_and_defaults_when_omitted() {
        let managed = Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"
acme = "self-signed"

[server.firewall]
manage = true
scope = "lan"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"
"#,
        )
        .unwrap();
        assert!(managed.server.firewall.manage);
        assert_eq!(managed.server.firewall.scope, Scope::Lan);

        // No [server.firewall] table at all falls back to the closed default
        // rather than failing to parse.
        let bare = Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"
"#,
        )
        .unwrap();
        assert!(!bare.server.firewall.manage);
        assert_eq!(bare.server.firewall.scope, Scope::Loopback);
    }

    #[derive(Serialize, Deserialize)]
    struct Wrap {
        scope: Scope,
    }
}
