//! Config validation.
//!
//! Every rule here exists because breaking it produces a deployment that starts
//! successfully and is then wrong — a port collision that kills one service at
//! boot, a site that silently answers on no hostname, a worker that would be
//! addressed over the public internet. Failing at load, with the offending field
//! named, is the whole point.
//!
//! Validation collects *all* problems rather than stopping at the first, so one
//! run of `selfhost check` reports everything that needs fixing.

use crate::{Cidr, Config, Role};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;

/// A single validation failure, naming the field responsible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// Dotted path to the offending field, e.g. `sites[0].instances[1].port`.
    pub field: String,
    /// What is wrong, in terms the author can act on.
    pub message: String,
}

impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.message)
    }
}

/// Why a config could not be loaded.
#[derive(Debug, Clone)]
pub enum ConfigError {
    /// The file could not be read.
    Unreadable {
        /// Path that was attempted.
        path: PathBuf,
        /// Underlying I/O error.
        source: String,
    },
    /// The text was not valid TOML.
    Syntax(String),
    /// The document parsed but describes an unworkable deployment.
    Invalid(Vec<Problem>),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { path, source } => {
                write!(f, "cannot read {}: {source}", path.display())
            }
            Self::Syntax(detail) => write!(f, "config is not valid TOML: {detail}"),
            Self::Invalid(problems) => {
                writeln!(f, "config describes an unworkable deployment:")?;
                for problem in problems {
                    writeln!(f, "  {problem}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Checks every structural rule, reporting all violations at once.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let mut problems = Vec::new();

        if self.version != 1 {
            problems.push(Problem {
                field: "version".into(),
                message: format!("unsupported schema version {} (expected 1)", self.version),
            });
        }

        self.check_nodes(&mut problems);
        self.check_sites(&mut problems);
        self.check_port_collisions(&mut problems);
        self.check_firewall(&mut problems);
        self.check_dns(&mut problems);
        self.check_mail(&mut problems);
        self.check_self_update(&mut problems);
        self.check_shares(&mut problems);
        self.check_desktop(&mut problems);
        self.check_mesh(&mut problems);

        if problems.is_empty() { Ok(()) } else { Err(ConfigError::Invalid(problems)) }
    }

    /// When the firewall is managed, the public binds must be real socket addresses.
    ///
    /// The daemon derives each inbound allowance by parsing `http_bind` and
    /// `https_bind` as a [`SocketAddr`]; a bind that does not parse is dropped
    /// there, silently opening no port for a listener the operator believes is
    /// exposed. Caught here instead, and named, but only while `manage` is on —
    /// an unmanaged firewall derives nothing, so an unusual bind string is then
    /// the proxy's concern alone rather than a firewall error.
    fn check_firewall(&self, problems: &mut Vec<Problem>) {
        if !self.server.firewall.manage {
            return;
        }
        for (field, bind) in [
            ("server.http_bind", &self.server.http_bind),
            ("server.https_bind", &self.server.https_bind),
        ] {
            if bind.parse::<SocketAddr>().is_err() {
                problems.push(Problem {
                    field: field.into(),
                    message: "must be a bindable address like 0.0.0.0:80 when \
                              server.firewall.manage is set"
                        .into(),
                });
            }
        }
    }

    /// Authoritative DNS, when configured, must name valid zones and records.
    ///
    /// Delegated to [`crate::dns::Dns::check`] so the schema and its rules live
    /// together, exactly as a service validates through [`crate::ServiceSpec`].
    /// Absent `[dns]` validates nothing — DNS is opt-in.
    fn check_dns(&self, problems: &mut Vec<Problem>) {
        if let Some(dns) = &self.dns {
            dns.check("dns", problems);
        }
    }

    /// Mail, when configured, must name a valid host, domains, and mailboxes.
    ///
    /// Delegated to [`crate::mail::Mail::check`] so the schema and its rules live
    /// together, exactly as DNS validates through [`crate::dns::Dns::check`].
    /// Absent `[mail]` validates nothing — mail is opt-in.
    fn check_mail(&self, problems: &mut Vec<Problem>) {
        if let Some(mail) = &self.mail {
            mail.check("mail", problems);
        }
    }

    /// The self-update section, when present, must name a runnable repository
    /// and branch. Delegated to [`crate::git::SelfUpdate::check`], exactly as
    /// the other opt-in sections validate through their own schema modules.
    fn check_self_update(&self, problems: &mut Vec<Problem>) {
        if let Some(update) = &self.self_update {
            update.check("self_update", problems);
        }
    }

    /// The shares, when any are declared, must be individually well-formed and
    /// must not collide with one another. Delegated to
    /// [`crate::storage::check_shares`], which owns both the per-block rules and
    /// the two that only exist between blocks. An empty list validates nothing —
    /// shares are opt-in.
    ///
    /// What is *not* checked here is whether a root is a safe directory to
    /// serve; `storage::share::Share::new` refuses the filesystem root, a root
    /// containing `..`, and a root that is, contains, or sits inside `data_dir`,
    /// the TLS store or this repository. That rule lives with the type whose
    /// whole purpose is to have been checked, so a share reaching the daemon by
    /// some route other than TOML cannot skip it.
    fn check_shares(&self, problems: &mut Vec<Problem>) {
        crate::storage::check_shares(&self.shares, "shares", problems);
    }

    /// The desktop section, when present, must be internally honest and within
    /// the ranges the subsystem can honour. Delegated to
    /// [`crate::desktop::Desktop::check`]. Absent `[desktop]` validates nothing,
    /// because absent means the subsystem does not exist.
    fn check_desktop(&self, problems: &mut Vec<Problem>) {
        if let Some(desktop) = &self.desktop {
            desktop.check("desktop", problems);
        }
    }

    /// The peer link, when present, must name a declared worker and reach the
    /// owner over TLS.
    ///
    /// The scheme and the token path are [`crate::mesh::Mesh::check`]'s, which
    /// can judge them alone. The two rules here need the rest of the document:
    /// the named node must be declared in `[[nodes]]`, exactly as a site
    /// instance's node must be, and it must not be the owner — the owner is what
    /// a worker dials, so an owner dialling itself describes nothing that can
    /// happen.
    fn check_mesh(&self, problems: &mut Vec<Problem>) {
        let Some(mesh) = &self.mesh else {
            return;
        };
        mesh.check("mesh", problems);

        match self.node(&mesh.node) {
            None => problems.push(Problem {
                field: "mesh.node".into(),
                message: format!(
                    "unknown node \"{}\"; mesh.node names this machine's own [[nodes]] entry, \
                     and the owner looks the link's token up by that name",
                    mesh.node
                ),
            }),
            Some(node) if node.role == Role::Owner => problems.push(Problem {
                field: "mesh.node".into(),
                message: format!(
                    "\"{}\" is the owner, and the owner is what a worker dials. The owner \
                     needs nothing beyond its [[nodes]] block: remove the [mesh] section, or \
                     name the worker this machine actually is",
                    mesh.node
                ),
            }),
            Some(_) => {}
        }
    }

    /// Exactly one owner, unique names, and a mesh address for every worker.
    fn check_nodes(&self, problems: &mut Vec<Problem>) {
        if self.nodes.is_empty() {
            problems.push(Problem {
                field: "nodes".into(),
                message: "declare at least one node".into(),
            });
            return;
        }

        let owners = self.nodes.iter().filter(|n| n.role == Role::Owner).count();
        if owners != 1 {
            problems.push(Problem {
                field: "nodes".into(),
                message: format!(
                    "exactly one node must have role \"owner\" (found {owners}); \
                     the owner holds every stateful service, and two owners means two \
                     independent deployments rather than one"
                ),
            });
        }

        let mut seen = BTreeSet::new();
        for (i, node) in self.nodes.iter().enumerate() {
            if node.name.is_empty() {
                problems.push(Problem {
                    field: format!("nodes[{i}].name"),
                    message: "must not be empty".into(),
                });
            }
            if !seen.insert(node.name.as_str()) {
                problems.push(Problem {
                    field: format!("nodes[{i}].name"),
                    message: format!("duplicate node name \"{}\"", node.name),
                });
            }
        }
    }

    /// Sites must have a hostname, something to serve, and resolvable instances.
    ///
    /// Access gating is checked here too: every `allowed_cidrs` entry must
    /// parse, and a console site must be gated, static, and unique — the
    /// console fronts the service-control API, so an open or ambiguous one is
    /// refused at load rather than discovered as an exposure later.
    fn check_sites(&self, problems: &mut Vec<Problem>) {
        let mut seen_names = BTreeSet::new();
        let mut seen_domains: BTreeMap<String, usize> = BTreeMap::new();
        let mut console_site: Option<usize> = None;

        for (i, site) in self.sites.iter().enumerate() {
            if !seen_names.insert(site.name.as_str()) {
                problems.push(Problem {
                    field: format!("sites[{i}].name"),
                    message: format!("duplicate site name \"{}\"", site.name),
                });
            }

            if site.domains.is_empty() {
                problems.push(Problem {
                    field: format!("sites[{i}].domains"),
                    message: "declare at least one domain, or the site answers on no hostname".into(),
                });
            }

            for (j, domain) in site.domains.iter().enumerate() {
                let lowered = domain.to_ascii_lowercase();
                if let Some(previous) = seen_domains.insert(lowered, i) {
                    if previous != i {
                        problems.push(Problem {
                            field: format!("sites[{i}].domains[{j}]"),
                            message: format!(
                                "\"{domain}\" is already served by sites[{previous}]; \
                                 a hostname can only route to one site"
                            ),
                        });
                    }
                }
            }

            if site.static_root.is_none() && site.instances.is_empty() {
                problems.push(Problem {
                    field: format!("sites[{i}]"),
                    message: "a site needs static_root, instances, or both — this one serves nothing"
                        .into(),
                });
            }

            if !site.app_paths.is_empty() && site.instances.is_empty() {
                problems.push(Problem {
                    field: format!("sites[{i}].app_paths"),
                    message: "app_paths route to an application, but no instances are declared".into(),
                });
            }

            for (j, prefix) in site.app_paths.iter().enumerate() {
                if !prefix.starts_with('/') {
                    problems.push(Problem {
                        field: format!("sites[{i}].app_paths[{j}]"),
                        message: format!("\"{prefix}\" must start with /"),
                    });
                }
            }

            if !site.health.path.starts_with('/') {
                problems.push(Problem {
                    field: format!("sites[{i}].health.path"),
                    message: "must start with /".into(),
                });
            }

            if site.health.interval_secs == 0 {
                problems.push(Problem {
                    field: format!("sites[{i}].health.interval_secs"),
                    message: "must be at least 1; a zero interval would probe continuously".into(),
                });
            }

            if site.health.timeout_secs >= site.health.interval_secs.max(1) {
                problems.push(Problem {
                    field: format!("sites[{i}].health.timeout_secs"),
                    message: format!(
                        "timeout ({}s) must be shorter than the interval ({}s), or probes overlap \
                         and a slow instance is judged by checks that are still in flight",
                        site.health.timeout_secs, site.health.interval_secs
                    ),
                });
            }

            if site.health.unhealthy_after == 0 || site.health.healthy_after == 0 {
                problems.push(Problem {
                    field: format!("sites[{i}].health"),
                    message: "unhealthy_after and healthy_after must be at least 1".into(),
                });
            }

            for (j, instance) in site.instances.iter().enumerate() {
                match self.node(&instance.node) {
                    None => problems.push(Problem {
                        field: format!("sites[{i}].instances[{j}].node"),
                        message: format!("unknown node \"{}\"", instance.node),
                    }),
                    Some(node) if node.role == Role::Worker && node.mesh_ip.is_none() => {
                        problems.push(Problem {
                            field: format!("sites[{i}].instances[{j}].node"),
                            message: format!(
                                "worker \"{}\" has no mesh_ip, so it cannot be reached privately; \
                                 run `selfhost node join` on it first",
                                instance.node
                            ),
                        });
                    }
                    Some(_) => {}
                }
            }

            for (j, entry) in site.allowed_cidrs.iter().enumerate() {
                if let Err(why) = Cidr::parse(entry) {
                    problems.push(Problem {
                        field: format!("sites[{i}].allowed_cidrs[{j}]"),
                        message: why,
                    });
                }
            }

            if site.console {
                if let Some(previous) = console_site {
                    problems.push(Problem {
                        field: format!("sites[{i}].console"),
                        message: format!(
                            "sites[{previous}] is already the console; \
                             only one site may be the built-in admin console"
                        ),
                    });
                } else {
                    console_site = Some(i);
                }

                if site.allowed_cidrs.is_empty() {
                    problems.push(Problem {
                        field: format!("sites[{i}].allowed_cidrs"),
                        message: "a console site must list allowed_cidrs; \
                                  the admin console is never left open to everyone"
                            .into(),
                    });
                }

                for (j, entry) in site.allowed_cidrs.iter().enumerate() {
                    if let Some(refusal) = console_gate_refusal(entry) {
                        problems.push(Problem {
                            field: format!("sites[{i}].allowed_cidrs[{j}]"),
                            message: refusal,
                        });
                    }
                }

                if site.static_root.is_none() {
                    problems.push(Problem {
                        field: format!("sites[{i}].static_root"),
                        message: "a console site needs static_root to serve the console SPA from"
                            .into(),
                    });
                }

                if !site.instances.is_empty() {
                    problems.push(Problem {
                        field: format!("sites[{i}].instances"),
                        message: "a console site declares no instances; \
                                  its /api traffic is relayed to server.admin_bind, \
                                  and its routing is built into the proxy"
                            .into(),
                    });
                }

                if !site.app_paths.is_empty() {
                    problems.push(Problem {
                        field: format!("sites[{i}].app_paths"),
                        message: "a console site declares no app_paths; \
                                  its routing is built into the proxy"
                            .into(),
                    });
                }
            }
        }
    }

    /// No two processes may claim the same port on the same machine.
    fn check_port_collisions(&self, problems: &mut Vec<Problem>) {
        let mut claimed: BTreeMap<(String, u16), String> = BTreeMap::new();

        for (i, site) in self.sites.iter().enumerate() {
            for (j, instance) in site.instances.iter().enumerate() {
                let key = (instance.node.clone(), instance.port);
                let owner = format!("sites[{i}].instances[{j}]");
                if let Some(existing) = claimed.get(&key) {
                    problems.push(Problem {
                        field: owner,
                        message: format!(
                            "port {} on node \"{}\" is already claimed by {existing}",
                            instance.port, instance.node
                        ),
                    });
                } else {
                    claimed.insert(key, owner);
                }
            }
        }
    }
}

/// The address ranges a console gate may name, and what each one is.
///
/// Loopback first because it is the deployed answer: the VPN tunnel exits on the
/// box as a connection to `127.0.0.1:443`, so the console's gate admits loopback
/// and nothing else (`docs/VPN.md`). The private and carrier-grade ranges are
/// here for a deployment whose console is reached over a LAN or an overlay
/// network instead. Every one of them shares the property that matters: no
/// packet from the public internet can carry such a source address to this
/// machine and be answered.
const CONSOLE_GATE_RANGES: [&str; 7] = [
    "127.0.0.0/8",    // IPv4 loopback — where a tunnel exits
    "::1/128",        // IPv6 loopback, the same
    "10.0.0.0/8",     // RFC 1918
    "172.16.0.0/12",  // RFC 1918
    "192.168.0.0/16", // RFC 1918
    "100.64.0.0/10",  // RFC 6598 carrier-grade NAT, and Tailscale's range
    "fc00::/7",       // RFC 4193 IPv6 unique-local
];

/// The broadest IPv4 prefix a console gate may name.
///
/// A `/24` is 256 addresses — a tunnel subnet or one LAN segment. Anything
/// broader is not a gate, it is a gesture: `10.0.0.0/8` admits sixteen million
/// hosts, and an operator who types it has almost certainly meant "the machines
/// I own" while writing "every address any router might hand out".
const CONSOLE_GATE_NARROWEST_IPV4: u8 = 24;

/// Why a console site may not name this CIDR, or `None` when it may.
///
/// # Why the console's gate is held to a rule no other site's is
///
/// The console fronts the API that starts, stops, reconfigures and — as the
/// remote-desktop work lands — *drives* this machine. `Site::permits` treats an
/// empty list as open, and until this rule existed `allowed_cidrs =
/// ["0.0.0.0/0"]` passed validation cleanly, so the one line standing between
/// the internet and the control plane could be disarmed without a single
/// warning. Named ranges and a prefix ceiling turn that from a convention into a
/// refusal at load.
///
/// # What passing this check does *not* mean
///
/// It does not mean the gate is authentication. In the deployed topology the
/// admitted range is loopback, and **everything already executing on this box
/// passes it** — every local account, and every co-hosted web application whose
/// upstream can be made to fetch a URL. The gate is a perimeter against the
/// internet and the LAN, not against the machine itself, which is why every
/// route behind it still authenticates. `docs/SECURITY.md` §3.5 states this at
/// length; it is repeated here because this function is where an operator's
/// intuition that "behind the gate" means "safe" is formed.
///
/// A syntactically broken entry yields `None`: the parse check reports it
/// already, and a second problem about the same characters would only bury the
/// first.
///
/// Public so `selfhost doctor` can report the same judgement on a running
/// deployment instead of re-deriving it. A diagnostic that disagrees with the
/// loader about what is acceptable is worse than no diagnostic.
pub fn console_gate_refusal(entry: &str) -> Option<String> {
    let (address, prefix) = console_gate_parts(entry)?;

    // `filter_map` rather than `expect`: the ranges are literals and a test
    // asserts they all parse, but a typo in one must cost a rejected config —
    // which an operator sees and fixes — rather than an abort in a process that
    // also serves 80 and 443.
    let admitted = CONSOLE_GATE_RANGES
        .iter()
        .filter_map(|range| Cidr::parse(range).ok())
        .any(|range| range.contains(address));
    if !admitted {
        return Some(format!(
            "\"{entry}\" is not a private address range, so it can only have been reached \
             from the public internet. A console site may admit loopback (the address a VPN \
             tunnel exits on), an RFC 1918 LAN range, carrier-grade NAT (100.64.0.0/10), or \
             IPv6 unique-local (fc00::/7) — nothing else. The console can control this \
             deployment; it is never routable."
        ));
    }

    if address.is_ipv4() && prefix < CONSOLE_GATE_NARROWEST_IPV4 {
        return Some(format!(
            "\"{entry}\" is /{prefix}, which is broader than the /{CONSOLE_GATE_NARROWEST_IPV4} \
             a console site may admit. Name the addresses the console is actually reached from \
             — in production that is \"127.0.0.1/32\", the address the VPN tunnel exits on — \
             rather than a whole network the console will never see a request from."
        ));
    }

    None
}

/// An entry's address and prefix length, or `None` if it does not parse.
///
/// Deliberately thin: [`Cidr::parse`] has already decided what a well-formed
/// entry is and reported the ones that are not, and [`Cidr`] keeps its parts
/// private, so this splits the text the same way rather than re-deciding
/// anything. Every judgement above is made with [`Cidr::contains`], so the
/// meaning of a range is still defined in exactly one place.
fn console_gate_parts(entry: &str) -> Option<(IpAddr, u8)> {
    let (address_text, prefix_text) = match entry.split_once('/') {
        Some((address, prefix)) => (address, Some(prefix)),
        None => (entry, None),
    };
    let address: IpAddr = address_text.parse().ok()?;
    let widest = if address.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_text {
        None => widest,
        Some(digits) => match digits.parse::<u8>() {
            Ok(prefix) if prefix <= widest => prefix,
            _ => return None,
        },
    };
    Some((address, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AcmeEnvironment, Firewall, Health, Instance, Node, Scope, Server, Site};
    use std::path::PathBuf;

    fn server() -> Server {
        Server {
            http_bind: "0.0.0.0:80".into(),
            https_bind: "0.0.0.0:443".into(),
            acme_email: "a@b.com".into(),
            acme: AcmeEnvironment::SelfSigned,
            data_dir: PathBuf::from("./data"),
            admin_bind: "127.0.0.1:9191".into(),
            firewall: Firewall::default(),
        }
    }

    fn site(name: &str, domain: &str) -> Site {
        Site {
            name: name.into(),
            domains: vec![domain.into()],
            static_root: Some(PathBuf::from("./public")),
            spa: false,
            app_paths: vec![],
            instances: vec![],
            health: Health::default(),
            canonical_redirect: true,
            allowed_cidrs: vec![],
            console: false,
        }
    }

    fn owner_node() -> Node {
        Node { name: "home".into(), role: Role::Owner, mesh_ip: None }
    }

    fn config(nodes: Vec<Node>, sites: Vec<Site>) -> Config {
        Config {
            version: 1,
            server: server(),
            nodes,
            sites,
            dns: None,
            mail: None,
            self_update: None,
            shares: vec![],
            desktop: None,
            mesh: None,
        }
    }

    fn problems_of(config: &Config) -> Vec<Problem> {
        match config.validate() {
            Ok(()) => Vec::new(),
            Err(ConfigError::Invalid(problems)) => problems,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn a_minimal_deployment_is_valid() {
        assert!(config(vec![owner_node()], vec![site("a", "example.com")]).validate().is_ok());
    }

    #[test]
    fn requires_exactly_one_owner() {
        let two_owners = config(
            vec![owner_node(), Node { name: "other".into(), role: Role::Owner, mesh_ip: None }],
            vec![site("a", "example.com")],
        );
        assert!(problems_of(&two_owners).iter().any(|p| p.field == "nodes"));

        let no_owner = config(
            vec![Node { name: "w".into(), role: Role::Worker, mesh_ip: Some("10.0.0.2".into()) }],
            vec![site("a", "example.com")],
        );
        assert!(problems_of(&no_owner).iter().any(|p| p.field == "nodes"));
    }

    #[test]
    fn rejects_a_hostname_claimed_by_two_sites() {
        let clashing = config(
            vec![owner_node()],
            vec![site("a", "example.com"), site("b", "EXAMPLE.com")],
        );
        let problems = problems_of(&clashing);
        assert!(problems.iter().any(|p| p.field == "sites[1].domains[0]"), "{problems:?}");
    }

    #[test]
    fn rejects_a_site_that_serves_nothing() {
        let mut empty = site("a", "example.com");
        empty.static_root = None;
        let problems = problems_of(&config(vec![owner_node()], vec![empty]));
        assert!(problems.iter().any(|p| p.field == "sites[0]"));
    }

    #[test]
    fn rejects_a_port_claimed_twice_on_one_node() {
        let mut first = site("a", "a.com");
        first.instances = vec![Instance { node: "home".into(), port: 5050 }];
        let mut second = site("b", "b.com");
        second.instances = vec![Instance { node: "home".into(), port: 5050 }];

        let problems = problems_of(&config(vec![owner_node()], vec![first, second]));
        assert!(
            problems.iter().any(|p| p.message.contains("already claimed")),
            "{problems:?}"
        );
    }

    #[test]
    fn the_same_port_on_different_nodes_is_fine() {
        let mut s = site("a", "a.com");
        s.instances = vec![
            Instance { node: "home".into(), port: 5050 },
            Instance { node: "shed".into(), port: 5050 },
        ];
        let nodes = vec![
            owner_node(),
            Node { name: "shed".into(), role: Role::Worker, mesh_ip: Some("10.77.0.2".into()) },
        ];
        assert!(config(nodes, vec![s]).validate().is_ok());
    }

    #[test]
    fn rejects_an_instance_on_an_unknown_node() {
        let mut s = site("a", "a.com");
        s.instances = vec![Instance { node: "ghost".into(), port: 5050 }];
        let problems = problems_of(&config(vec![owner_node()], vec![s]));
        assert!(problems.iter().any(|p| p.message.contains("unknown node")));
    }

    #[test]
    fn rejects_a_worker_that_has_not_joined_the_mesh() {
        let mut s = site("a", "a.com");
        s.instances = vec![Instance { node: "shed".into(), port: 5050 }];
        let nodes = vec![
            owner_node(),
            Node { name: "shed".into(), role: Role::Worker, mesh_ip: None },
        ];
        let problems = problems_of(&config(nodes, vec![s]));
        assert!(problems.iter().any(|p| p.message.contains("mesh_ip")), "{problems:?}");
    }

    #[test]
    fn rejects_a_health_timeout_that_outlasts_its_interval() {
        // Overlapping probes mean an instance is judged by checks still in
        // flight, which makes the healthy/unhealthy counters meaningless.
        let mut s = site("a", "a.com");
        s.health = Health { interval_secs: 5, timeout_secs: 10, ..Health::default() };
        let problems = problems_of(&config(vec![owner_node()], vec![s]));
        assert!(problems.iter().any(|p| p.field == "sites[0].health.timeout_secs"));
    }

    #[test]
    fn reports_every_problem_at_once_not_just_the_first() {
        let mut broken = site("a", "a.com");
        broken.static_root = None;
        broken.app_paths = vec!["no-leading-slash".into()];
        broken.health.path = "nope".into();

        let problems = problems_of(&config(vec![], vec![broken]));
        assert!(problems.len() >= 4, "expected several problems, got {problems:?}");
    }

    #[test]
    fn rejects_an_unsupported_schema_version() {
        let mut future = config(vec![owner_node()], vec![site("a", "a.com")]);
        future.version = 2;
        assert!(problems_of(&future).iter().any(|p| p.field == "version"));
    }

    #[test]
    fn a_managed_firewall_refuses_a_bind_that_is_not_a_socket_address() {
        // The bind is parsed as a SocketAddr to derive the port to open. A bare
        // "80" or a hostname would parse to nothing, so the port stays shut while
        // the operator thinks it is open — the exact failure this rule prevents.
        let mut broken = config(vec![owner_node()], vec![site("a", "a.com")]);
        broken.server.firewall = Firewall { manage: true, scope: Scope::Internet };
        broken.server.http_bind = "80".into();
        broken.server.https_bind = "example.com:443".into();

        let problems = problems_of(&broken);
        assert!(problems.iter().any(|p| p.field == "server.http_bind"), "{problems:?}");
        assert!(problems.iter().any(|p| p.field == "server.https_bind"), "{problems:?}");
    }

    #[test]
    fn an_unmanaged_firewall_does_not_police_the_binds() {
        // manage = false derives no rules, so the binds are never parsed as
        // socket addresses here and an unusual one is the proxy's concern alone.
        let mut lax = config(vec![owner_node()], vec![site("a", "a.com")]);
        lax.server.firewall = Firewall { manage: false, scope: Scope::Lan };
        lax.server.http_bind = "not-an-address".into();
        assert!(lax.validate().is_ok());
    }

    #[test]
    fn a_managed_firewall_with_ordinary_binds_is_valid() {
        let mut ok = config(vec![owner_node()], vec![site("a", "a.com")]);
        ok.server.firewall = Firewall { manage: true, scope: Scope::Lan };
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn a_gated_site_with_valid_cidrs_is_valid() {
        let mut gated = site("a", "a.com");
        gated.allowed_cidrs = vec!["10.66.0.0/24".into(), "fd00::/8".into(), "127.0.0.1".into()];
        assert!(config(vec![owner_node()], vec![gated]).validate().is_ok());
    }

    #[test]
    fn rejects_a_malformed_cidr_naming_the_exact_entry() {
        let mut gated = site("a", "a.com");
        gated.allowed_cidrs = vec!["10.66.0.0/24".into(), "not-a-network".into()];
        let problems = problems_of(&config(vec![owner_node()], vec![gated]));
        assert!(
            problems.iter().any(|p| p.field == "sites[0].allowed_cidrs[1]"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_console_site_must_be_gated_never_open() {
        // The console fronts the service-control API; an ungated one would
        // hand every service on the machine to anyone who resolves the domain.
        let mut console = site("console", "admin.example.com");
        console.console = true;
        let problems = problems_of(&config(vec![owner_node()], vec![console]));
        assert!(
            problems.iter().any(|p| p.field == "sites[0].allowed_cidrs"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_console_site_needs_static_root_and_forbids_instances_and_app_paths() {
        let mut console = site("console", "admin.example.com");
        console.console = true;
        console.allowed_cidrs = vec!["10.66.0.0/24".into()];
        console.static_root = None;
        console.instances = vec![Instance { node: "home".into(), port: 5050 }];
        console.app_paths = vec!["/api/*".into()];
        let problems = problems_of(&config(vec![owner_node()], vec![console]));
        for field in ["sites[0].static_root", "sites[0].instances", "sites[0].app_paths"] {
            assert!(problems.iter().any(|p| p.field == field), "missing {field}: {problems:?}");
        }
    }

    #[test]
    fn rejects_a_second_console_site() {
        let gate = |mut s: Site| {
            s.console = true;
            s.allowed_cidrs = vec!["10.66.0.0/24".into()];
            s
        };
        let doubled = config(
            vec![owner_node()],
            vec![gate(site("a", "a.com")), gate(site("b", "b.com"))],
        );
        let problems = problems_of(&doubled);
        assert!(problems.iter().any(|p| p.field == "sites[1].console"), "{problems:?}");
    }

    #[test]
    fn a_well_formed_console_site_is_valid() {
        let mut console = site("console", "admin.example.com");
        console.console = true;
        console.allowed_cidrs = vec!["10.66.0.0/24".into()];
        assert!(config(vec![owner_node()], vec![console]).validate().is_ok());
    }

    #[test]
    fn every_console_gate_range_is_a_parseable_literal() {
        // The class check silently drops a range it cannot parse, so a typo
        // would narrow the rule without saying so. This is what makes that
        // choice safe.
        for range in CONSOLE_GATE_RANGES {
            assert!(Cidr::parse(range).is_ok(), "{range} does not parse");
        }
    }

    #[test]
    fn the_deployed_console_gates_are_admitted() {
        // The values `docs/VPN.md` documents as production (the tunnel's
        // loopback exit), and the LAN and overlay forms an operator might use
        // instead. If this test ever fails, a live deployment stops loading.
        for entry in [
            "127.0.0.1/32",
            "::1/128",
            "127.0.0.1",
            "10.66.0.0/24",
            "192.168.1.0/24",
            "172.16.5.0/24",
            "100.64.1.0/24",
            "100.100.100.100/32",
            "fd00::/8",
            "fc00::/7",
            "192.168.1.9",
        ] {
            assert_eq!(console_gate_refusal(entry), None, "{entry} should be admitted");
        }
    }

    #[test]
    fn a_console_gate_may_not_name_a_routable_address() {
        // The failure this rule exists for: a gate that admits the internet.
        for entry in [
            "0.0.0.0/0",
            "::/0",
            "8.8.8.8/32",
            "172.83.6.109/32",
            "2001:db8::/32",
            "169.254.0.0/16",
            "172.32.0.0/24",
        ] {
            let refusal = console_gate_refusal(entry).unwrap_or_else(|| panic!("{entry} admitted"));
            assert!(refusal.contains(entry), "the message must name the entry: {refusal}");
        }
    }

    #[test]
    fn a_console_gate_may_not_be_broader_than_a_slash_24() {
        for (entry, prefix) in
            [("10.0.0.0/8", "/8"), ("192.168.0.0/16", "/16"), ("100.64.0.0/10", "/10")]
        {
            let refusal = console_gate_refusal(entry).unwrap_or_else(|| panic!("{entry} admitted"));
            assert!(refusal.contains(entry), "{refusal}");
            assert!(refusal.contains(prefix), "the message must say how broad it is: {refusal}");
        }
    }

    #[test]
    fn a_malformed_console_gate_is_left_to_the_parse_check() {
        // Reporting the same characters twice buries the message that says what
        // is actually wrong with them.
        for entry in ["not-a-network", "10.0.0.0/33", "10.0.0.0/x", ""] {
            let refusal = console_gate_refusal(entry);
            assert_eq!(refusal, None, "{entry} is a parse problem, not a gate one");
        }
    }

    #[test]
    fn an_open_console_gate_is_refused_naming_the_entry_and_its_index() {
        // `allowed_cidrs = ["0.0.0.0/0"]` used to pass validation cleanly. The
        // console can control this deployment, so it no longer does.
        let mut console = site("console", "admin.example.com");
        console.console = true;
        console.allowed_cidrs = vec!["127.0.0.1/32".into(), "0.0.0.0/0".into()];
        let problems = problems_of(&config(vec![owner_node()], vec![console]));
        let problem = problems
            .iter()
            .find(|p| p.field == "sites[0].allowed_cidrs[1]")
            .unwrap_or_else(|| panic!("{problems:?}"));
        assert!(problem.message.contains("0.0.0.0/0"), "{problem}");
    }

    #[test]
    fn an_ordinary_site_may_still_gate_on_anything_that_parses() {
        // The rule is about what the console fronts, not about CIDRs. A public
        // site that wants to admit one office's routable range still may.
        let mut gated = site("a", "a.com");
        gated.allowed_cidrs = vec!["8.8.8.8/32".into(), "0.0.0.0/0".into()];
        assert!(config(vec![owner_node()], vec![gated]).validate().is_ok());
    }
}
