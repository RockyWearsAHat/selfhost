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

use crate::{Config, Role};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
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

        if problems.is_empty() { Ok(()) } else { Err(ConfigError::Invalid(problems)) }
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
    fn check_sites(&self, problems: &mut Vec<Problem>) {
        let mut seen_names = BTreeSet::new();
        let mut seen_domains: BTreeMap<String, usize> = BTreeMap::new();

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AcmeEnvironment, Health, Instance, Node, Server, Site};
    use std::path::PathBuf;

    fn server() -> Server {
        Server {
            http_bind: "0.0.0.0:80".into(),
            https_bind: "0.0.0.0:443".into(),
            acme_email: "a@b.com".into(),
            acme: AcmeEnvironment::SelfSigned,
            data_dir: PathBuf::from("./data"),
            admin_bind: "127.0.0.1:9191".into(),
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
        }
    }

    fn owner_node() -> Node {
        Node { name: "home".into(), role: Role::Owner, mesh_ip: None }
    }

    fn config(nodes: Vec<Node>, sites: Vec<Site>) -> Config {
        Config { version: 1, server: server(), nodes, sites }
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
}
