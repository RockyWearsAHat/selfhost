//! What a service is doing right now, in a form the console can render.

use selfhost_config::{RestartPolicy, StartMode};
use selfhost_json::Json;

/// The lifecycle position of one service.
///
/// Deliberately more detailed than running/stopped. "Stopped" and "gave up after
/// five failed restarts" both mean no process exists, but they need completely
/// different reactions from the operator, and a console that renders them the
/// same way hides the only one that is urgent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceState {
    /// Not running, and not trying to.
    Stopped,
    /// Configured never to run. Start requests are refused.
    Disabled,
    /// Spawning.
    Starting,
    /// Up.
    Running {
        /// Operating-system process id.
        pid: u32,
        /// Seconds since it started.
        uptime_secs: u64,
    },
    /// Asked to stop, waiting for it to comply.
    Stopping,
    /// Exited and will not be restarted, by policy or because it exited cleanly.
    Exited {
        /// Exit code, absent when killed by a signal.
        code: Option<i32>,
    },
    /// Waiting out a backoff delay before the next restart attempt.
    Backoff {
        /// Seconds remaining before the next attempt.
        retry_in_secs: u64,
        /// How many restarts have already been attempted.
        attempt: u32,
    },
    /// Failed too many times in a row; the supervisor stopped trying.
    ///
    /// Requires an explicit start from the operator, which also clears the counter.
    GaveUp {
        /// How many consecutive restarts were attempted before giving up.
        attempts: u32,
        /// The last thing that went wrong, for display.
        reason: String,
    },
    /// Could not be started at all — a bad path, or no permission.
    Unstartable {
        /// What the operating system said, phrased for the operator.
        reason: String,
    },
}

impl ServiceState {
    /// Whether a process currently exists for this service.
    pub fn is_live(&self) -> bool {
        matches!(self, Self::Starting | Self::Running { .. } | Self::Stopping)
    }

    /// Whether this state needs the operator's attention.
    ///
    /// Drives the console's summary tile, so the answer is "would a person want
    /// to know" rather than "is a process absent".
    pub fn needs_attention(&self) -> bool {
        matches!(self, Self::GaveUp { .. } | Self::Unstartable { .. })
    }

    /// The wire discriminant, which is also the console's table label source.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Disabled => "disabled",
            Self::Starting => "starting",
            Self::Running { .. } => "running",
            Self::Stopping => "stopping",
            Self::Exited { .. } => "exited",
            Self::Backoff { .. } => "backoff",
            Self::GaveUp { .. } => "gave-up",
            Self::Unstartable { .. } => "unstartable",
        }
    }

    /// A short label for a table cell.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Stopped => "Stopped",
            Self::Disabled => "Disabled",
            Self::Starting => "Starting",
            Self::Running { .. } => "Running",
            Self::Stopping => "Stopping",
            Self::Exited { .. } => "Exited",
            Self::Backoff { .. } => "Restarting",
            Self::GaveUp { .. } => "Gave up",
            Self::Unstartable { .. } => "Cannot start",
        }
    }

    /// The state as it goes over the wire.
    pub fn to_json(&self) -> Json {
        let mut fields: Vec<(&str, Json)> = vec![("state", Json::string(self.tag()))];
        match self {
            Self::Running { pid, uptime_secs } => {
                fields.push(("pid", Json::Number(*pid as f64)));
                fields.push(("uptimeSecs", Json::Number(*uptime_secs as f64)));
            }
            Self::Exited { code } => {
                fields.push((
                    "code",
                    code.map(|c| Json::Number(c as f64)).unwrap_or(Json::Null),
                ));
            }
            Self::Backoff { retry_in_secs, attempt } => {
                fields.push(("retryInSecs", Json::Number(*retry_in_secs as f64)));
                fields.push(("attempt", Json::Number(*attempt as f64)));
            }
            Self::GaveUp { attempts, reason } => {
                fields.push(("attempts", Json::Number(*attempts as f64)));
                fields.push(("reason", Json::string(reason)));
            }
            Self::Unstartable { reason } => fields.push(("reason", Json::string(reason))),
            Self::Stopped | Self::Disabled | Self::Starting | Self::Stopping => {}
        }
        Json::object(fields)
    }

    /// Reads a state back from the wire, for the console.
    pub fn from_json(value: &Json) -> Option<Self> {
        let text = |key: &str| value.get(key).and_then(Json::as_str).unwrap_or_default().to_owned();
        let number = |key: &str| value.get(key).and_then(Json::as_u64).unwrap_or(0);

        Some(match value.get("state")?.as_str()? {
            "stopped" => Self::Stopped,
            "disabled" => Self::Disabled,
            "starting" => Self::Starting,
            "stopping" => Self::Stopping,
            "running" => Self::Running {
                pid: number("pid") as u32,
                uptime_secs: number("uptimeSecs"),
            },
            "exited" => Self::Exited {
                code: value.get("code").and_then(Json::as_i64).map(|c| c as i32),
            },
            "backoff" => Self::Backoff {
                retry_in_secs: number("retryInSecs"),
                attempt: number("attempt") as u32,
            },
            "gave-up" => Self::GaveUp {
                attempts: number("attempts") as u32,
                reason: text("reason"),
            },
            "unstartable" => Self::Unstartable { reason: text("reason") },
            _ => return None,
        })
    }
}

/// A service and its current state, as sent to the console.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    /// The service's identifier.
    pub name: String,
    /// The name to display.
    pub display_name: String,
    /// What the operator wrote about it.
    pub description: String,
    /// Where it is in its lifecycle.
    pub state: ServiceState,
    /// How it is configured to start.
    pub start_mode: StartMode,
    /// Total restarts since the daemon started, across all reset windows.
    pub total_restarts: u64,
    /// The sequence number of the newest captured log line.
    ///
    /// Lets the console tell there is new output without fetching it.
    pub log_seq: u64,
}

/// The wire name for a start mode.
pub fn start_mode_name(mode: StartMode) -> &'static str {
    match mode {
        StartMode::Automatic => "automatic",
        StartMode::Manual => "manual",
        StartMode::Disabled => "disabled",
    }
}

/// Reads a start mode back from the wire.
pub fn start_mode_from(name: &str) -> Option<StartMode> {
    match name {
        "automatic" => Some(StartMode::Automatic),
        "manual" => Some(StartMode::Manual),
        "disabled" => Some(StartMode::Disabled),
        _ => None,
    }
}

impl ServiceStatus {
    /// The status as it goes over the wire.
    pub fn to_json(&self) -> Json {
        let mut object = match self.state.to_json() {
            Json::Object(map) => map,
            _ => unreachable!("ServiceState::to_json always produces an object"),
        };
        object.insert("name".into(), Json::string(&self.name));
        object.insert("displayName".into(), Json::string(&self.display_name));
        object.insert("description".into(), Json::string(&self.description));
        object.insert("startMode".into(), Json::string(start_mode_name(self.start_mode)));
        object.insert("totalRestarts".into(), Json::Number(self.total_restarts as f64));
        object.insert("logSeq".into(), Json::Number(self.log_seq as f64));
        Json::Object(object)
    }

    /// Reads a status back from the wire, for the console.
    pub fn from_json(value: &Json) -> Option<Self> {
        let text = |key: &str| value.get(key).and_then(Json::as_str).unwrap_or_default().to_owned();
        Some(Self {
            name: value.get("name")?.as_str()?.to_owned(),
            display_name: text("displayName"),
            description: text("description"),
            state: ServiceState::from_json(value)?,
            start_mode: value
                .get("startMode")
                .and_then(Json::as_str)
                .and_then(start_mode_from)
                .unwrap_or(StartMode::Manual),
            total_restarts: value.get("totalRestarts").and_then(Json::as_u64).unwrap_or(0),
            log_seq: value.get("logSeq").and_then(Json::as_u64).unwrap_or(0),
        })
    }
}

/// A service definition as it goes over the wire.
///
/// Hand-written rather than derived because the wire format is a contract with
/// the console and should change only when someone means it to — a field renamed
/// in the config struct would otherwise silently rename itself in the API.
pub fn spec_to_json(spec: &selfhost_config::ServiceSpec) -> Json {
    let mut fields: Vec<(&str, Json)> = vec![
        ("name", Json::string(&spec.name)),
        ("displayName", Json::string(spec.label())),
        ("description", Json::string(&spec.description)),
        ("program", Json::string(spec.program.display().to_string())),
        ("args", Json::array(spec.args.iter().map(Json::string))),
        ("env", Json::object(spec.env.iter().map(|(k, v)| (k.clone(), Json::string(v))))),
        ("startMode", Json::string(start_mode_name(spec.start_mode))),
        ("restart", Json::string(restart_name(spec.restart))),
        ("restartDelaySecs", Json::Number(spec.restart_delay_secs as f64)),
        ("maxRestarts", Json::Number(spec.max_restarts as f64)),
        ("stopTimeoutSecs", Json::Number(spec.stop_timeout_secs as f64)),
    ];
    fields.push((
        "cwd",
        spec.cwd
            .as_ref()
            .map(|p| Json::string(p.display().to_string()))
            .unwrap_or(Json::Null),
    ));
    fields.push(("node", spec.node.as_ref().map(Json::string).unwrap_or(Json::Null)));
    fields.push((
        "stopCommand",
        spec.stop_command
            .as_ref()
            .map(|c| Json::array(c.iter().map(Json::string)))
            .unwrap_or(Json::Null),
    ));
    Json::object(fields)
}

/// Reads a service definition from the wire.
///
/// Absent fields take their defaults rather than failing, so the console can send
/// a partial definition for a new service and get sane behaviour. `name` and
/// `program` have no sensible default and are required.
pub fn spec_from_json(value: &Json) -> Option<selfhost_config::ServiceSpec> {
    let name = value.get("name")?.as_str()?;
    let program = value.get("program")?.as_str()?;
    let mut spec = selfhost_config::ServiceSpec::new(name, program);

    if let Some(label) = value.get("displayName").and_then(Json::as_str)
        && !label.is_empty()
        && label != name
    {
        spec.display_name = Some(label.to_owned());
    }
    if let Some(text) = value.get("description").and_then(Json::as_str) {
        spec.description = text.to_owned();
    }
    if let Some(args) = value.get("args").and_then(Json::as_array) {
        spec.args = args.iter().filter_map(Json::as_str).map(str::to_owned).collect();
    }
    if let Some(Json::Object(env)) = value.get("env") {
        spec.env = env
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
            .collect();
    }
    if let Some(cwd) = value.get("cwd").and_then(Json::as_str) {
        spec.cwd = Some(cwd.into());
    }
    if let Some(node) = value.get("node").and_then(Json::as_str) {
        spec.node = Some(node.to_owned());
    }
    if let Some(mode) = value.get("startMode").and_then(Json::as_str).and_then(start_mode_from) {
        spec.start_mode = mode;
    }
    if let Some(policy) = value.get("restart").and_then(Json::as_str).and_then(restart_from) {
        spec.restart = policy;
    }
    if let Some(delay) = value.get("restartDelaySecs").and_then(Json::as_u64) {
        spec.restart_delay_secs = delay;
    }
    if let Some(max) = value.get("maxRestarts").and_then(Json::as_u64) {
        spec.max_restarts = max as u32;
    }
    if let Some(timeout) = value.get("stopTimeoutSecs").and_then(Json::as_u64) {
        spec.stop_timeout_secs = timeout;
    }
    if let Some(command) = value.get("stopCommand").and_then(Json::as_array) {
        spec.stop_command =
            Some(command.iter().filter_map(Json::as_str).map(str::to_owned).collect());
    }
    Some(spec)
}

/// The wire name for a restart policy.
pub fn restart_name(policy: RestartPolicy) -> &'static str {
    match policy {
        RestartPolicy::Never => "never",
        RestartPolicy::OnFailure => "on-failure",
        RestartPolicy::Always => "always",
    }
}

/// Reads a restart policy back from the wire.
pub fn restart_from(name: &str) -> Option<RestartPolicy> {
    match name {
        "never" => Some(RestartPolicy::Never),
        "on-failure" => Some(RestartPolicy::OnFailure),
        "always" => Some(RestartPolicy::Always),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_service_definition_round_trips_over_the_wire() {
        let mut spec = selfhost_config::ServiceSpec::new("mongod", "/usr/bin/mongod");
        spec.display_name = Some("MongoDB".into());
        spec.description = "primary database".into();
        spec.args = vec!["--config".into(), "/etc/mongod.conf".into()];
        spec.env.insert("HOME".into(), "/var/mongo".into());
        spec.cwd = Some("/var/mongo".into());
        spec.node = Some("home".into());
        spec.start_mode = StartMode::Manual;
        spec.restart = RestartPolicy::Always;
        spec.restart_delay_secs = 7;
        spec.max_restarts = 9;
        spec.stop_timeout_secs = 20;
        spec.stop_command = Some(vec!["mongod".into(), "--shutdown".into()]);

        let text = spec_to_json(&spec).to_text();
        let parsed = selfhost_json::parse(&text).expect("valid json");
        assert_eq!(spec_from_json(&parsed), Some(spec));
    }

    #[test]
    fn a_minimal_definition_needs_only_a_name_and_a_program() {
        let parsed =
            selfhost_json::parse(r#"{"name":"api","program":"/bin/api"}"#).expect("valid json");
        let spec = spec_from_json(&parsed).expect("accepted");
        assert_eq!(spec.name, "api");
        assert_eq!(spec.restart_delay_secs, 5, "absent fields take their defaults");
    }

    #[test]
    fn a_definition_without_a_program_is_refused_rather_than_defaulted() {
        // Defaulting the program would install a service that cannot start and
        // report the failure at start time, far from the mistake.
        let parsed = selfhost_json::parse(r#"{"name":"api"}"#).unwrap();
        assert_eq!(spec_from_json(&parsed), None);
    }

    #[test]
    fn a_display_name_equal_to_the_name_is_not_stored_twice() {
        let parsed =
            selfhost_json::parse(r#"{"name":"api","program":"/bin/api","displayName":"api"}"#)
                .unwrap();
        assert_eq!(spec_from_json(&parsed).unwrap().display_name, None);
    }

    #[test]
    fn a_service_that_gave_up_is_distinguishable_from_one_merely_stopped() {
        // Both have no process. Only one is an emergency, and a console that
        // shows them identically hides the emergency.
        let stopped = ServiceState::Stopped;
        let gave_up = ServiceState::GaveUp { attempts: 5, reason: "exit 1".into() };

        assert!(!stopped.needs_attention());
        assert!(gave_up.needs_attention());
        assert_ne!(stopped.label(), gave_up.label());
    }

    #[test]
    fn liveness_covers_the_transitional_states() {
        assert!(ServiceState::Starting.is_live());
        assert!(ServiceState::Running { pid: 1, uptime_secs: 0 }.is_live());
        assert!(ServiceState::Stopping.is_live());

        assert!(!ServiceState::Stopped.is_live());
        assert!(!ServiceState::Backoff { retry_in_secs: 5, attempt: 1 }.is_live());
        assert!(!ServiceState::Disabled.is_live());
    }

    #[test]
    fn every_state_survives_a_round_trip_over_the_wire() {
        let states = [
            ServiceState::Stopped,
            ServiceState::Disabled,
            ServiceState::Starting,
            ServiceState::Stopping,
            ServiceState::Running { pid: 4412, uptime_secs: 90 },
            ServiceState::Exited { code: Some(1) },
            ServiceState::Exited { code: None },
            ServiceState::Backoff { retry_in_secs: 20, attempt: 2 },
            ServiceState::GaveUp { attempts: 5, reason: "exit 1".into() },
            ServiceState::Unstartable { reason: "not found".into() },
        ];
        for state in states {
            let text = state.to_json().to_text();
            let parsed = selfhost_json::parse(&text).expect("valid json");
            assert_eq!(ServiceState::from_json(&parsed).as_ref(), Some(&state), "{text}");
        }
    }

    #[test]
    fn a_signal_death_keeps_its_missing_exit_code_rather_than_becoming_zero() {
        // `code: null` and `code: 0` mean "killed" and "exited cleanly", which
        // are opposite conclusions for an operator reading the table.
        let killed = ServiceState::Exited { code: None };
        let text = killed.to_json().to_text();
        assert!(text.contains("\"code\":null"), "{text}");

        let parsed = selfhost_json::parse(&text).unwrap();
        assert_eq!(ServiceState::from_json(&parsed), Some(killed));
    }

    #[test]
    fn a_status_round_trips_whole() {
        let status = ServiceStatus {
            name: "mongod".into(),
            display_name: "MongoDB".into(),
            description: "primary database".into(),
            state: ServiceState::Running { pid: 4412, uptime_secs: 3600 },
            start_mode: StartMode::Automatic,
            total_restarts: 2,
            log_seq: 918,
        };

        let parsed = selfhost_json::parse(&status.to_json().to_text()).unwrap();
        assert_eq!(ServiceStatus::from_json(&parsed), Some(status));
    }

    #[test]
    fn states_serialise_with_a_discriminant_the_console_can_switch_on() {
        let json = ServiceState::Running { pid: 42, uptime_secs: 7 }.to_json().to_text();
        assert!(json.contains(r#""state":"running""#), "{json}");
        assert!(json.contains(r#""pid":42"#), "{json}");
    }
}
