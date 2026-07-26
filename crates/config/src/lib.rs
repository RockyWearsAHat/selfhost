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

pub mod validate;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

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
            }],
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
}
