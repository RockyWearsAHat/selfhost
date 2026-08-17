//! Long-running programs the supervisor starts and keeps running.
//!
//! A *service* here is any program on the machine — MongoDB, a NAS daemon, a
//! site's own backend — not only something this project wrote. That is the whole
//! point: one place that knows what is supposed to be running, and whether it is.
//!
//! # Why this is a separate document from [`Config`](crate::Config)
//!
//! Services are declared in `data/services.toml`, not in `selfhost.config.toml`,
//! and the split is by *author* rather than by subject matter:
//!
//! | file | written by | holds |
//! |---|---|---|
//! | `selfhost.config.toml` | a person, by hand | server, nodes, sites |
//! | `data/services.toml` | the daemon, only | services installed from the console |
//!
//! Serialising a parsed document back to TOML discards every comment in it, and
//! the config `selfhost init` writes carries the ACME rate-limit warning and the
//! bind-address reasoning in exactly those comments. A console that saves a
//! service must not be the thing that deletes them. Two files with one writer
//! each is a stronger guarantee than one file with two.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::git::GitWatch;
use crate::validate::Problem;

/// When a service starts.
///
/// Mirrors the Windows Service Control Manager's startup types, because that is
/// the model the operator already has in their head.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StartMode {
    /// Started when the daemon starts, and restarted per [`RestartPolicy`].
    #[default]
    Automatic,
    /// Started only when asked, but still supervised once running.
    Manual,
    /// Never started, and refused if start is requested.
    ///
    /// Distinct from deleting the service: the definition is kept so it can be
    /// switched back on without being written out again from memory.
    Disabled,
}

/// What to do when a service exits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    /// Leave it stopped however it exited.
    Never,
    /// Restart only on a non-zero exit or a signal.
    ///
    /// The default, because a clean exit is usually a program that was asked to
    /// stop, and restarting it fights the operator.
    #[default]
    OnFailure,
    /// Restart on any exit, clean or not.
    Always,
}

/// A program the supervisor runs and keeps running.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSpec {
    /// Identifier, unique across the catalogue.
    ///
    /// Also used as a log filename, so [`ServiceSpec::check`] restricts it to
    /// characters that are portable across the three target filesystems.
    pub name: String,
    /// Human-readable name shown in the console. Falls back to `name`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    /// What this service is for, in the operator's words.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// The executable to run. Not a shell command line — see [`ServiceSpec::args`].
    pub program: PathBuf,
    /// Arguments passed to `program`, already split.
    ///
    /// Split rather than a single string on purpose: a string has to be word-split
    /// by *someone*, and every implementation splits quoting and escaping slightly
    /// differently. A path containing a space is the common case that breaks, and
    /// it breaks silently, at start, on the operator's machine and not on ours.
    #[serde(default)]
    pub args: Vec<String>,
    /// Directory the process runs in. Relative paths resolve against the data directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<PathBuf>,
    /// Environment variables set for the process, on top of the daemon's own.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,

    /// Which machine runs this service. Empty means the owner node.
    ///
    /// Present from the start so pinning a service to a second machine later is a
    /// field that already exists rather than a schema migration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,

    /// When the service starts.
    #[serde(default)]
    pub start_mode: StartMode,
    /// What to do when it exits.
    #[serde(default)]
    pub restart: RestartPolicy,
    /// Seconds to wait before the first restart attempt.
    ///
    /// Subsequent attempts back off exponentially from here; see the supervisor.
    #[serde(default = "default_restart_delay")]
    pub restart_delay_secs: u64,
    /// Consecutive failed restarts before the supervisor gives up.
    ///
    /// Zero means never give up. The counter resets once the service has stayed
    /// up longer than [`ServiceSpec::restart_delay_secs`] times this value — or
    /// thirty seconds, whichever is longer, so an aggressive configuration cannot
    /// make the reset meaningless. A service healthy for a long stretch therefore
    /// gets its full budget back.
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,
    /// Seconds to wait for a graceful stop before killing the process.
    #[serde(default = "default_stop_timeout")]
    pub stop_timeout_secs: u64,
    /// A command that asks the service to shut down cleanly, run before any signal.
    ///
    /// Needed because a graceful stop is not portable. Unix has `SIGTERM`; Windows
    /// has no equivalent that reaches a process with no console, so a service there
    /// would otherwise be terminated outright — which for a database is a way to
    /// corrupt it. Many programs ship their own answer (`mongod --shutdown`,
    /// `nginx -s quit`), and naming it makes the stop clean on every platform
    /// rather than only on Unix.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_command: Option<Vec<String>>,

    /// A Git branch whose movement redeploys this service, if it has one.
    ///
    /// Optional because most services are a program already on the machine. A
    /// service that *is* a deployment — a site's backend built from a repository —
    /// carries the watch here rather than in a second catalogue, so that the thing
    /// which stops the service and the thing which updates its code are the same
    /// object and cannot disagree about which service they mean.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<GitWatch>,
}

fn default_restart_delay() -> u64 {
    5
}

fn default_max_restarts() -> u32 {
    5
}

fn default_stop_timeout() -> u64 {
    10
}

impl ServiceSpec {
    /// A service with defaults, named and pointed at a program.
    pub fn new(name: impl Into<String>, program: impl Into<PathBuf>) -> Self {
        Self {
            name: name.into(),
            display_name: None,
            description: String::new(),
            program: program.into(),
            args: Vec::new(),
            cwd: None,
            env: BTreeMap::new(),
            node: None,
            start_mode: StartMode::default(),
            restart: RestartPolicy::default(),
            restart_delay_secs: default_restart_delay(),
            max_restarts: default_max_restarts(),
            stop_timeout_secs: default_stop_timeout(),
            stop_command: None,
            git: None,
        }
    }

    /// The Git watch that should be polled for this service, if there is one.
    ///
    /// Answers `None` for a watch that is switched off, so no caller has to
    /// remember to check `enabled` — forgetting it would poll a repository the
    /// operator deliberately stopped watching.
    pub fn active_watch(&self) -> Option<&GitWatch> {
        self.git.as_ref().filter(|watch| watch.is_active())
    }

    /// The name to show in the console.
    pub fn label(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.name)
    }

    /// Whether the daemon should start this service on its own startup.
    pub fn starts_automatically(&self) -> bool {
        self.start_mode == StartMode::Automatic
    }

    /// Collects every structural problem with this service.
    ///
    /// `at` is the dotted path used to report problems, so the console can point
    /// at the offending field. `known_nodes` comes from the deployment config;
    /// pass an empty slice to skip the node check.
    pub fn check(&self, at: &str, known_nodes: &[&str], problems: &mut Vec<Problem>) {
        if let Some(message) = name_problem(&self.name) {
            problems.push(Problem { field: format!("{at}.name"), message });
        }

        if self.program.as_os_str().is_empty() {
            problems.push(Problem {
                field: format!("{at}.program"),
                message: "name the executable to run".into(),
            });
        }

        if let Some(node) = &self.node
            && !known_nodes.is_empty()
            && !known_nodes.contains(&node.as_str())
        {
            problems.push(Problem {
                field: format!("{at}.node"),
                message: format!("unknown node \"{node}\""),
            });
        }

        if self.restart_delay_secs == 0 && self.restart != RestartPolicy::Never {
            problems.push(Problem {
                field: format!("{at}.restart_delay_secs"),
                message: "must be at least 1; a zero delay respawns a crash-looping program \
                          as fast as the machine can fork, which is indistinguishable from a \
                          fork bomb"
                    .into(),
            });
        }

        if self.stop_timeout_secs == 0 {
            problems.push(Problem {
                field: format!("{at}.stop_timeout_secs"),
                message: "must be at least 1; a zero timeout kills the process before it can \
                          flush anything to disk"
                    .into(),
            });
        }

        if self.stop_command.as_ref().is_some_and(|c| c.is_empty()) {
            problems.push(Problem {
                field: format!("{at}.stop_command"),
                message: "is present but empty; omit it entirely to stop the service the \
                          ordinary way"
                    .into(),
            });
        }

        if let Some(watch) = &self.git {
            watch.check(&format!("{at}.git"), problems);
        }

        for key in self.env.keys() {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                problems.push(Problem {
                    field: format!("{at}.env"),
                    message: format!("\"{key}\" is not a usable variable name"),
                });
            }
        }
    }
}

/// Why a name cannot be used, or `None` if it is fine.
///
/// A service name becomes a log filename and, later, an operating-system service
/// identifier. Refusing the awkward characters here means neither of those has to
/// sanitise, and — as with path resolution elsewhere in this project — a name that
/// would escape its directory is rejected outright rather than quietly rewritten
/// into a different one.
fn name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some("must not be empty".into());
    }
    if name.len() > 64 {
        return Some(format!("is {} characters; keep it to 64 or fewer", name.len()));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Some(format!(
            "\"{name}\" may only contain letters, digits, dot, dash, and underscore, \
             because it is also used as a filename"
        ));
    }
    // "." and ".." are legal under the character rule above and are exactly the
    // two names that would resolve to a directory rather than a log file.
    if name.chars().all(|c| c == '.') {
        return Some(format!("\"{name}\" names a directory, not a service"));
    }
    None
}

/// Every service the operator has installed.
///
/// This is the root of `data/services.toml`. The daemon is its only writer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceCatalog {
    /// Schema version. Refused if it is not `1`.
    #[serde(default = "default_catalog_version")]
    pub version: u32,
    /// The services, in the order they were installed.
    #[serde(default, rename = "service")]
    pub services: Vec<ServiceSpec>,
}

fn default_catalog_version() -> u32 {
    1
}

/// An empty catalogue at the current schema version.
///
/// Written by hand rather than derived: a derived `Default` would set `version`
/// to zero, and since the empty catalogue is what a first run starts from, the
/// daemon would write a document that fails its own validation the next time it
/// is read. The serde default only applies while deserialising, so it does not
/// cover the value built in memory.
impl Default for ServiceCatalog {
    fn default() -> Self {
        Self { version: default_catalog_version(), services: Vec::new() }
    }
}

impl ServiceCatalog {
    /// Parses a catalogue from TOML text, validating it.
    ///
    /// `known_nodes` comes from the deployment config so a service pinned to a
    /// machine that does not exist is caught at load. Pass an empty slice when
    /// the config is not available.
    pub fn parse(text: &str, known_nodes: &[&str]) -> Result<Self, crate::ConfigError> {
        let catalog: Self =
            toml::from_str(text).map_err(|e| crate::ConfigError::Syntax(e.to_string()))?;
        catalog.validate(known_nodes)?;
        Ok(catalog)
    }

    /// Serialises the catalogue for writing to disk.
    ///
    /// The header explains where the file came from, because the operator will
    /// eventually find it and needs to know which of the two files to edit.
    pub fn to_toml(&self) -> String {
        let body = toml::to_string_pretty(self).unwrap_or_default();
        format!(
            "# Services installed through the selfhost console.\n\
             #\n\
             # This file is written by the daemon. Hand edits are read back, but the\n\
             # daemon rewrites the whole file whenever a service changes, so comments\n\
             # added here do not survive. Deployment settings — server, nodes, sites —\n\
             # live in selfhost.config.toml instead, which the daemon never writes.\n\
             \n{body}"
        )
    }

    /// Checks every rule, reporting all violations at once.
    pub fn validate(&self, known_nodes: &[&str]) -> Result<(), crate::ConfigError> {
        let mut problems = Vec::new();

        if self.version != 1 {
            problems.push(Problem {
                field: "version".into(),
                message: format!("unsupported schema version {} (expected 1)", self.version),
            });
        }

        let mut seen = std::collections::BTreeSet::new();
        for (i, service) in self.services.iter().enumerate() {
            let at = format!("service[{i}]");
            service.check(&at, known_nodes, &mut problems);
            if !service.name.is_empty() && !seen.insert(service.name.as_str()) {
                problems.push(Problem {
                    field: format!("{at}.name"),
                    message: format!("duplicate service name \"{}\"", service.name),
                });
            }
        }

        if problems.is_empty() {
            Ok(())
        } else {
            Err(crate::ConfigError::Invalid(problems))
        }
    }

    /// Looks up a service by name.
    pub fn get(&self, name: &str) -> Option<&ServiceSpec> {
        self.services.iter().find(|s| s.name == name)
    }

    /// Adds a service, or replaces the existing one with the same name.
    ///
    /// Returns whether an existing service was replaced, so the caller can tell
    /// an install from an edit without looking first.
    pub fn upsert(&mut self, spec: ServiceSpec) -> bool {
        match self.services.iter_mut().find(|s| s.name == spec.name) {
            Some(existing) => {
                *existing = spec;
                true
            }
            None => {
                self.services.push(spec);
                false
            }
        }
    }

    /// Removes a service by name, returning whether it was there.
    pub fn remove(&mut self, name: &str) -> bool {
        let before = self.services.len();
        self.services.retain(|s| s.name != name);
        self.services.len() != before
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems_of(catalog: &ServiceCatalog, nodes: &[&str]) -> Vec<Problem> {
        match catalog.validate(nodes) {
            Ok(()) => Vec::new(),
            Err(crate::ConfigError::Invalid(problems)) => problems,
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    fn catalog(services: Vec<ServiceSpec>) -> ServiceCatalog {
        ServiceCatalog { version: 1, services }
    }

    #[test]
    fn a_minimal_service_is_valid() {
        let c = catalog(vec![ServiceSpec::new("mongod", "/usr/bin/mongod")]);
        assert!(c.validate(&[]).is_ok());
    }

    #[test]
    fn a_name_that_would_escape_the_log_directory_is_refused() {
        // The same rule as path resolution in the proxy: refuse, never rewrite.
        // "../../etc/cron.d/x" as a name would otherwise pick the log file's path.
        for bad in ["../evil", "a/b", "a\\b", "..", "."] {
            let c = catalog(vec![ServiceSpec::new(bad, "/bin/true")]);
            let problems = problems_of(&c, &[]);
            assert!(
                problems.iter().any(|p| p.field == "service[0].name"),
                "expected {bad:?} to be refused, got {problems:?}"
            );
        }
    }

    #[test]
    fn an_ordinary_name_with_dots_and_dashes_is_allowed() {
        let c = catalog(vec![ServiceSpec::new("mongo-db.v7_1", "/bin/true")]);
        assert!(c.validate(&[]).is_ok());
    }

    #[test]
    fn rejects_a_duplicate_service_name() {
        let c = catalog(vec![
            ServiceSpec::new("api", "/bin/a"),
            ServiceSpec::new("api", "/bin/b"),
        ]);
        assert!(problems_of(&c, &[]).iter().any(|p| p.message.contains("duplicate")));
    }

    #[test]
    fn rejects_a_zero_restart_delay_because_it_is_a_fork_bomb() {
        let mut spec = ServiceSpec::new("api", "/bin/a");
        spec.restart_delay_secs = 0;
        spec.restart = RestartPolicy::Always;
        let problems = problems_of(&catalog(vec![spec]), &[]);
        assert!(problems.iter().any(|p| p.field == "service[0].restart_delay_secs"));
    }

    #[test]
    fn a_zero_restart_delay_is_fine_when_it_never_restarts() {
        let mut spec = ServiceSpec::new("api", "/bin/a");
        spec.restart_delay_secs = 0;
        spec.restart = RestartPolicy::Never;
        assert!(catalog(vec![spec]).validate(&[]).is_ok());
    }

    #[test]
    fn rejects_a_service_pinned_to_an_unknown_node() {
        let mut spec = ServiceSpec::new("api", "/bin/a");
        spec.node = Some("ghost".into());
        let problems = problems_of(&catalog(vec![spec]), &["home"]);
        assert!(problems.iter().any(|p| p.message.contains("unknown node")));
    }

    #[test]
    fn rejects_an_empty_program() {
        let spec = ServiceSpec::new("api", "");
        let problems = problems_of(&catalog(vec![spec]), &[]);
        assert!(problems.iter().any(|p| p.field == "service[0].program"));
    }

    #[test]
    fn reports_every_problem_at_once_not_just_the_first() {
        let mut spec = ServiceSpec::new("", "");
        spec.stop_timeout_secs = 0;
        let problems = problems_of(&catalog(vec![spec]), &[]);
        assert!(problems.len() >= 3, "expected several problems, got {problems:?}");
    }

    #[test]
    fn round_trips_through_toml() {
        let mut spec = ServiceSpec::new("mongod", "/usr/bin/mongod");
        spec.args = vec!["--config".into(), "/etc/mongod.conf".into()];
        spec.env.insert("MONGO_HOME".into(), "/var/mongo".into());
        spec.display_name = Some("MongoDB".into());
        spec.start_mode = StartMode::Manual;
        spec.restart = RestartPolicy::Always;

        let written = catalog(vec![spec.clone()]).to_toml();
        let read = ServiceCatalog::parse(&written, &[]).expect("round trip");

        assert_eq!(read.services.len(), 1);
        assert_eq!(read.services[0], spec);
        // The header has to survive being read back, not just written.
        assert!(written.contains("selfhost.config.toml"), "{written}");
    }

    #[test]
    fn unspecified_fields_fall_back_to_defaults_rather_than_zero() {
        let read = ServiceCatalog::parse(
            r#"
version = 1
[[service]]
name = "api"
program = "/bin/api"
"#,
            &[],
        )
        .expect("valid");

        let service = &read.services[0];
        assert_eq!(service.restart_delay_secs, 5);
        assert_eq!(service.stop_timeout_secs, 10);
        assert_eq!(service.max_restarts, 5);
        assert_eq!(service.start_mode, StartMode::Automatic);
        // OnFailure, not Always: a clean exit is usually a program that was told
        // to stop, and restarting it fights the operator.
        assert_eq!(service.restart, RestartPolicy::OnFailure);
    }

    #[test]
    fn upsert_replaces_by_name_and_reports_which_it_did() {
        let mut c = catalog(vec![ServiceSpec::new("api", "/bin/old")]);
        assert!(c.upsert(ServiceSpec::new("api", "/bin/new")), "should report a replacement");
        assert_eq!(c.services.len(), 1);
        assert_eq!(c.services[0].program, PathBuf::from("/bin/new"));

        assert!(!c.upsert(ServiceSpec::new("other", "/bin/x")), "should report an insert");
        assert_eq!(c.services.len(), 2);
    }

    #[test]
    fn an_empty_catalogue_is_valid_and_can_be_written_then_read() {
        // The bug this guards: a derived Default sets version to 0, so a first
        // run writes a catalogue that fails validation the next time it loads —
        // which looks exactly like every service having been deleted.
        let empty = ServiceCatalog::default();
        assert_eq!(empty.version, 1);
        assert!(empty.validate(&[]).is_ok());

        let mut catalog = ServiceCatalog::default();
        catalog.upsert(ServiceSpec::new("api", "/bin/api"));
        let written = catalog.to_toml();
        assert!(ServiceCatalog::parse(&written, &[]).is_ok(), "{written}");
    }

    #[test]
    fn a_services_git_watch_is_validated_with_it_and_reported_under_its_own_path() {
        let mut spec = ServiceSpec::new("site", "/usr/bin/node");
        let mut watch = crate::GitWatch::new("https://example.com/r.git", "site");
        watch.interval_secs = 0;
        spec.git = Some(watch);

        let problems = problems_of(&catalog(vec![spec]), &[]);
        assert!(
            problems.iter().any(|p| p.field == "service[0].git.interval_secs"),
            "{problems:?}"
        );
    }

    #[test]
    fn a_watch_round_trips_through_toml_with_the_service_that_owns_it() {
        let mut spec = ServiceSpec::new("site", "/usr/bin/node");
        let mut watch = crate::GitWatch::new("git@github.com:owner/repo.git", "checkouts/site");
        watch.branch = "release".into();
        watch.post_pull = Some(vec!["npm".into(), "ci".into()]);
        watch.auto_update = false;
        spec.git = Some(watch);

        let written = catalog(vec![spec.clone()]).to_toml();
        let read = ServiceCatalog::parse(&written, &[]).expect("round trip");
        assert_eq!(read.services[0], spec);
    }

    #[test]
    fn a_service_without_a_watch_writes_no_git_section_at_all() {
        // The catalogue is a file a person reads. An empty [service.git] table
        // would read as "this is watched, badly configured" rather than "not
        // watched", which is the wrong thing to make somebody debug.
        let written = catalog(vec![ServiceSpec::new("api", "/bin/api")]).to_toml();
        assert!(!written.contains("git"), "{written}");
    }

    #[test]
    fn a_switched_off_watch_is_kept_but_not_offered_for_polling() {
        let mut spec = ServiceSpec::new("site", "/usr/bin/node");
        let mut watch = crate::GitWatch::new("https://example.com/r.git", "site");
        watch.enabled = false;
        spec.git = Some(watch);

        assert!(spec.active_watch().is_none(), "a disabled watch must not be polled");
        assert!(spec.git.is_some(), "but its definition must survive");
    }

    #[test]
    fn remove_reports_whether_anything_was_removed() {
        let mut c = catalog(vec![ServiceSpec::new("api", "/bin/a")]);
        assert!(c.remove("api"));
        assert!(!c.remove("api"));
        assert!(c.services.is_empty());
    }
}
