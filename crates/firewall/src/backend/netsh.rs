//! The Windows backend: Windows Firewall, driven through `netsh advfirewall`.
//!
//! Unlike `pf` and `nftables`, Windows Firewall is imperative: there is no owned
//! table to swap wholesale, only individual rules added and deleted by name, and
//! a per-profile default-inbound policy set separately. So this is the backend
//! that actually runs the [`diff`](crate::diff): it reads back the rules it owns
//! (every rule whose name begins `selfhost-`), then withdraws the stale ones and
//! adds the missing ones, leaving both the operator's own rules and the openings
//! that are already correct untouched.
//!
//! Because the desired set always includes SSH ([`with_ssh`]), the SSH rule is
//! always in the "keep" or "add" set and never in "remove" — the default-inbound
//! block can be turned on without severing a remote session, and established
//! connections survive the policy change regardless.
//!
//! | Scope | netsh `remoteip` |
//! |---|---|
//! | `Lan` | `LocalSubnet` plus the explicit RFC1918/CGNAT/link-local ranges |
//! | `Internet` | `any` |
//! | `Loopback` | never emitted — the default block is the whole policy |

use crate::backend::{FirewallBackend, FirewallError};
use crate::rule::{diff, with_ssh, AllowRule, Proto, LAN_CIDRS};
use crate::run::{self, COMMAND_TIMEOUT};
use crate::state::{BackendKind, FirewallState, RuleState};
use selfhost_config::Scope;

/// The prefix every rule this backend owns carries. Reading back only these is
/// what keeps the reconciler from ever touching a rule it did not create.
const MANAGED_PREFIX: &str = "selfhost-";

/// The Windows Firewall backend.
pub struct NetshBackend {
    program: String,
}

impl NetshBackend {
    /// A backend driving the system `netsh`.
    pub fn new() -> Self {
        Self { program: "netsh".into() }
    }
}

impl Default for NetshBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// The rule name for an opening: `selfhost-<tag>-<port>`.
pub fn managed_name(rule: &AllowRule) -> String {
    format!("{MANAGED_PREFIX}{}-{}", rule.tag, rule.port)
}

/// Whether a rule name is one this backend owns.
pub fn is_managed_name(name: &str) -> bool {
    name.starts_with(MANAGED_PREFIX)
}

/// Reconstructs the opening a managed rule name describes.
///
/// The scope is not recoverable from the name — it is only used as an opening
/// identity (transport and port) for the diff, which does not read scope — so a
/// placeholder is fine here.
pub fn parse_managed_name(name: &str) -> Option<AllowRule> {
    let rest = name.strip_prefix(MANAGED_PREFIX)?;
    let (tag, port) = rest.rsplit_once('-')?;
    Some(AllowRule {
        port: port.parse().ok()?,
        proto: Proto::Tcp,
        scope: Scope::Lan,
        tag: tag.to_owned(),
    })
}

/// The netsh `remoteip` value admitting a scope.
fn netsh_remoteip(scope: Scope) -> String {
    match scope {
        Scope::Internet => "any".into(),
        Scope::Lan => format!("LocalSubnet,{}", LAN_CIDRS.join(",")),
        Scope::Loopback => "127.0.0.0/8".into(),
    }
}

/// The arguments that add one opening as an inbound allow rule.
pub fn add_args(rule: &AllowRule) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "add".into(),
        "rule".into(),
        format!("name={}", managed_name(rule)),
        "dir=in".into(),
        "action=allow".into(),
        format!("protocol={}", rule.proto.upper()),
        format!("localport={}", rule.port),
        format!("remoteip={}", netsh_remoteip(rule.scope)),
    ]
}

/// The arguments that delete a managed rule by name.
pub fn delete_args(name: &str) -> Vec<String> {
    vec![
        "advfirewall".into(),
        "firewall".into(),
        "delete".into(),
        "rule".into(),
        format!("name={name}"),
    ]
}

/// The arguments that set, or clear, default-deny inbound on every profile.
pub fn block_args(block: bool) -> Vec<String> {
    let policy = if block { "blockinbound,allowoutbound" } else { "allowinbound,allowoutbound" };
    vec!["advfirewall".into(), "set".into(), "allprofiles".into(), "firewallpolicy".into(), policy.into()]
}

/// The managed rules named anywhere in `show rule name=all` output.
///
/// Locale-independent: rather than parse the localised "Rule Name:" label, it
/// picks out every whitespace token that reads as one of our rule names, which
/// no operator-authored rule can accidentally be.
fn parse_present(output: &str) -> Vec<AllowRule> {
    let mut present: Vec<AllowRule> = Vec::new();
    for token in output.split_whitespace() {
        if is_managed_name(token)
            && let Some(rule) = parse_managed_name(token)
            && !present.iter().any(|held| held.same_opening(&rule))
        {
            present.push(rule);
        }
    }
    present
}

impl NetshBackend {
    /// The managed rules currently installed, for the diff.
    async fn present(&self) -> Result<Vec<AllowRule>, FirewallError> {
        let shown = run::run(
            &self.program,
            &["advfirewall".into(), "firewall".into(), "show".into(), "rule".into(), "name=all".into()],
            None,
            COMMAND_TIMEOUT,
        )
        .await?
        .ok_or_error(&self.program)?;
        Ok(parse_present(&shown.stdout))
    }
}

impl FirewallBackend for NetshBackend {
    async fn snapshot(&self) -> Result<FirewallState, FirewallError> {
        let present = self.present().await?;
        let profiles = run::run(
            &self.program,
            &["advfirewall".into(), "show".into(), "allprofiles".into()],
            None,
            COMMAND_TIMEOUT,
        )
        .await?
        .ok_or_error(&self.program)?;

        let rules = present
            .into_iter()
            .map(|rule| RuleState { rule, applied: true })
            .collect();

        Ok(FirewallState {
            backend: BackendKind::Netsh,
            managed: false,
            default_inbound_block: profiles.stdout.contains("BlockInbound"),
            rules,
        })
    }

    async fn reconcile(&self, desired: &[AllowRule]) -> Result<FirewallState, FirewallError> {
        // SSH is folded in here so it is always desired, and so always kept —
        // never among the rules the diff withdraws.
        let effective = with_ssh(desired);
        let present = self.present().await?;
        let plan = diff(&present, &effective);

        for rule in &plan.remove {
            run::run(&self.program, &delete_args(&managed_name(rule)), None, COMMAND_TIMEOUT)
                .await?
                .ok_or_error(&self.program)?;
        }
        for rule in &plan.add {
            run::run(&self.program, &add_args(rule), None, COMMAND_TIMEOUT)
                .await?
                .ok_or_error(&self.program)?;
        }
        // plan.keep is deliberately left alone.
        self.snapshot().await
    }

    async fn set_default_inbound_block(&self, block: bool) -> Result<(), FirewallError> {
        run::run(&self.program, &block_args(block), None, COMMAND_TIMEOUT)
            .await?
            .ok_or_error(&self.program)
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(port: u16, scope: Scope, tag: &str) -> AllowRule {
        AllowRule { port, proto: Proto::Tcp, scope, tag: tag.into() }
    }

    #[test]
    fn a_managed_name_round_trips_through_its_opening() {
        let rule = tcp(443, Scope::Lan, "https");
        let name = managed_name(&rule);
        assert_eq!(name, "selfhost-https-443");
        let back = parse_managed_name(&name).expect("ours");
        assert!(back.same_opening(&rule));
        assert_eq!(back.tag, "https");
    }

    #[test]
    fn only_our_own_names_are_recognised_as_managed() {
        assert!(is_managed_name("selfhost-http-80"));
        assert!(!is_managed_name("Allow SSH"));
        assert!(!is_managed_name("Core Networking"));
        // A foreign rule is never reconstructed, so it can never enter the diff.
        assert!(parse_managed_name("Core Networking").is_none());
    }

    #[test]
    fn an_add_rule_opens_the_port_inbound_under_its_scope() {
        let args = add_args(&tcp(443, Scope::Lan, "https"));
        assert!(args.contains(&"name=selfhost-https-443".to_string()), "{args:?}");
        assert!(args.contains(&"dir=in".to_string()));
        assert!(args.contains(&"action=allow".to_string()));
        assert!(args.contains(&"protocol=TCP".to_string()));
        assert!(args.contains(&"localport=443".to_string()));
        assert!(args.iter().any(|a| a.starts_with("remoteip=") && a.contains("LocalSubnet")));
    }

    #[test]
    fn an_internet_opening_is_reachable_from_anywhere() {
        let args = add_args(&tcp(443, Scope::Internet, "https"));
        assert!(args.contains(&"remoteip=any".to_string()), "{args:?}");
    }

    #[test]
    fn the_default_policy_blocks_inbound_but_still_allows_outbound() {
        assert_eq!(block_args(true).last().unwrap(), "blockinbound,allowoutbound");
        assert_eq!(block_args(false).last().unwrap(), "allowinbound,allowoutbound");
    }

    #[test]
    fn present_rules_are_read_out_of_a_show_dump_ignoring_foreign_rules() {
        let dump = "Rule Name: Core Networking - DNS\n\
                    Rule Name: selfhost-https-443\n\
                    Rule Name: selfhost-ssh-22\n\
                    Rule Name: File and Printer Sharing\n";
        let present = parse_present(dump);
        assert_eq!(present.len(), 2, "{present:?}");
        assert!(present.iter().any(|r| r.port == 443));
        assert!(present.iter().any(|r| r.port == 22));
    }

    #[test]
    fn the_diff_a_reconcile_runs_never_withdraws_ssh() {
        // The scenario the backend feeds diff: present has an old opening plus
        // SSH, desired (with SSH folded in) drops the old one.
        let present = vec![tcp(8080, Scope::Lan, "old"), tcp(22, Scope::Lan, "ssh")];
        let effective = with_ssh(&[tcp(443, Scope::Lan, "https")]);
        let plan = diff(&present, &effective);
        assert!(plan.remove.iter().all(|r| r.port != 22), "SSH must survive: {plan:?}");
        assert!(plan.remove.iter().any(|r| r.port == 8080), "the stale opening goes: {plan:?}");
        assert!(plan.add.iter().any(|r| r.port == 443));
    }
}
