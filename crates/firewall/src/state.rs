//! The firewall as the backend last observed it, in the form the console reads.
//!
//! Hand-written camelCase JSON, the same contract-with-the-console idiom
//! [`selfhost_supervisor::state`](../../selfhost_supervisor/state/index.html)
//! uses: a closed [`BackendKind::tag`]/[`BackendKind::from_tag`] so one spelling
//! serves wire and code, and [`RuleState`] flattened onto its [`AllowRule`] the
//! way `ServiceStatus` flattens `ServiceState`.

use crate::rule::{AllowRule, Proto};
use selfhost_config::Scope;
use selfhost_json::Json;

/// Which host firewall the daemon found and is driving.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// macOS packet filter, `pf`.
    Pf,
    /// Linux `nftables`.
    Nftables,
    /// Windows Firewall, driven through `netsh`.
    Netsh,
    /// No backend for this operating system.
    Unsupported,
}

impl BackendKind {
    /// The wire spelling.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Pf => "pf",
            Self::Nftables => "nftables",
            Self::Netsh => "netsh",
            Self::Unsupported => "unsupported",
        }
    }

    /// A label a person reads, naming the actual firewall.
    pub fn label(self) -> &'static str {
        match self {
            Self::Pf => "macOS pf",
            Self::Nftables => "nftables",
            Self::Netsh => "Windows Firewall",
            Self::Unsupported => "unsupported",
        }
    }

    /// Reads a backend kind back from its wire spelling.
    pub fn from_tag(text: &str) -> Option<Self> {
        match text {
            "pf" => Some(Self::Pf),
            "nftables" => Some(Self::Nftables),
            "netsh" => Some(Self::Netsh),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// One desired opening paired with whether the live firewall currently holds it.
///
/// Flattened on the wire the way `ServiceStatus` flattens `ServiceState`: the
/// [`AllowRule`]'s fields sit beside `applied` in one object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleState {
    /// The opening this describes.
    pub rule: AllowRule,
    /// Whether the live firewall currently holds it.
    pub applied: bool,
}

impl RuleState {
    /// The opening and its live status, as one flattened object.
    pub fn to_json(&self) -> Json {
        let mut object = match self.rule.to_json() {
            Json::Object(map) => map,
            _ => unreachable!("AllowRule::to_json always produces an object"),
        };
        object.insert("applied".into(), Json::Bool(self.applied));
        Json::Object(object)
    }

    /// Reads an opening and its status back from the wire.
    pub fn from_json(value: &Json) -> Option<Self> {
        Some(Self {
            rule: AllowRule::from_json(value)?,
            applied: value.get("applied").and_then(Json::as_bool).unwrap_or(false),
        })
    }
}

impl AllowRule {
    /// The opening as it goes over the wire.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("port", Json::Number(self.port as f64)),
            ("proto", Json::string(self.proto.tag())),
            ("scope", Json::string(self.scope.tag())),
            ("tag", Json::string(&self.tag)),
        ])
    }

    /// Reads an opening back from the wire.
    ///
    /// `port`, `proto`, and `scope` are required — an opening missing any of them
    /// is not one this crate wrote, so it is dropped rather than guessed at.
    pub fn from_json(value: &Json) -> Option<Self> {
        Some(Self {
            port: u16::try_from(value.get("port")?.as_u64()?).ok()?,
            proto: Proto::from_tag(value.get("proto")?.as_str()?)?,
            scope: Scope::from_tag(value.get("scope")?.as_str()?)?,
            tag: value.get("tag").and_then(Json::as_str).unwrap_or_default().to_owned(),
        })
    }
}

/// The firewall as the backend last observed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallState {
    /// The backend driving this host.
    pub backend: BackendKind,
    /// Whether the daemon is managing the firewall (config `manage`).
    pub managed: bool,
    /// Whether inbound is default-deny.
    pub default_inbound_block: bool,
    /// Every opening [`desired_rules`](crate::desired_rules) asked for, with its
    /// live status.
    pub rules: Vec<RuleState>,
}

impl FirewallState {
    /// A label a person reads, naming the firewall being driven.
    pub fn backend_label(&self) -> &'static str {
        self.backend.label()
    }

    /// The state as it goes over the wire.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("backend", Json::string(self.backend.tag())),
            ("managed", Json::Bool(self.managed)),
            ("defaultInboundBlock", Json::Bool(self.default_inbound_block)),
            ("rules", Json::array(self.rules.iter().map(RuleState::to_json))),
        ])
    }

    /// Reads a state back from the wire, for the console.
    pub fn from_json(value: &Json) -> Option<Self> {
        Some(Self {
            backend: BackendKind::from_tag(value.get("backend")?.as_str()?)?,
            managed: value.get("managed").and_then(Json::as_bool).unwrap_or(false),
            default_inbound_block: value
                .get("defaultInboundBlock")
                .and_then(Json::as_bool)
                .unwrap_or(false),
            rules: value
                .get("rules")
                .and_then(Json::as_array)
                .map(|items| items.iter().filter_map(RuleState::from_json).collect())
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> FirewallState {
        FirewallState {
            backend: BackendKind::Pf,
            managed: true,
            default_inbound_block: true,
            rules: vec![
                RuleState {
                    rule: AllowRule { port: 443, proto: Proto::Tcp, scope: Scope::Lan, tag: "https".into() },
                    applied: true,
                },
                RuleState {
                    rule: AllowRule { port: 80, proto: Proto::Tcp, scope: Scope::Lan, tag: "http".into() },
                    applied: false,
                },
            ],
        }
    }

    #[test]
    fn a_state_round_trips_whole_over_the_wire() {
        let parsed = selfhost_json::parse(&state().to_json().to_text()).expect("valid json");
        assert_eq!(FirewallState::from_json(&parsed), Some(state()));
    }

    #[test]
    fn a_rule_flattens_its_status_beside_its_fields() {
        let text = state().rules[0].to_json().to_text();
        assert!(text.contains(r#""port":443"#), "{text}");
        assert!(text.contains(r#""applied":true"#), "{text}");
        assert!(text.contains(r#""scope":"lan""#), "{text}");
    }

    #[test]
    fn every_backend_kind_survives_its_own_spelling() {
        for kind in [BackendKind::Pf, BackendKind::Nftables, BackendKind::Netsh, BackendKind::Unsupported] {
            assert_eq!(BackendKind::from_tag(kind.tag()), Some(kind));
        }
        assert_eq!(BackendKind::from_tag("iptables"), None);
    }

    #[test]
    fn an_opening_missing_a_required_field_is_dropped_rather_than_guessed() {
        let value = selfhost_json::parse(r#"{"port":443,"tag":"https"}"#).unwrap();
        assert_eq!(AllowRule::from_json(&value), None, "no proto, no scope: not our rule");
    }
}
