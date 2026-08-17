//! The Linux backend: `nftables`, driven through `nft`.
//!
//! Everything this backend owns lives in one table, `inet selfhost`. A reconcile
//! regenerates that whole table and loads it with `nft -f -`, which replaces its
//! contents atomically — new openings appear, stale ones vanish — and touches no
//! other table, so a firewall the operator or their distribution set up in a
//! different table is left exactly as it was.
//!
//! The table's `input` chain carries the default policy in its own `policy`
//! statement, so [`set_default_inbound_block`](FirewallBackend::set_default_inbound_block)
//! and [`reconcile`](FirewallBackend::reconcile) both express the deny by loading
//! a ruleset — there is no separate global switch to race. Every ruleset accepts
//! loopback, established/related traffic, and SSH before anything else, so
//! enabling the deny cannot drop the operator's session.
//!
//! | Scope | nftables source |
//! |---|---|
//! | `Lan` | `ip saddr { 10/8, 172.16/12, 192.168/16, 100.64/10, 169.254/16, 127/8 }` |
//! | `Internet` | no source match |
//! | `Loopback` | never emitted — the default drop is the whole policy |

use crate::backend::{FirewallBackend, FirewallError};
use crate::rule::{AllowRule, Proto, LAN_CIDRS, SSH_PORT};
use crate::run::{self, COMMAND_TIMEOUT};
use crate::state::{BackendKind, FirewallState, RuleState};
use selfhost_config::Scope;

/// The Linux `nftables` backend.
///
/// Everything it owns lives in the table `inet selfhost`; nothing outside that
/// table is ever read or written.
pub struct NftablesBackend {
    program: String,
}

impl NftablesBackend {
    /// A backend driving the system `nft`.
    pub fn new() -> Self {
        Self { program: "nft".into() }
    }
}

impl Default for NftablesBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// The nftables source match admitting a scope, if it needs one.
fn nft_saddr(scope: Scope) -> Option<String> {
    match scope {
        Scope::Internet => Some(String::new()),
        Scope::Lan => Some(format!("ip saddr {{ {} }} ", LAN_CIDRS.join(", "))),
        Scope::Loopback => None,
    }
}

/// One accept line for an opening, or nothing for a loopback-scoped one.
fn rule_line(rule: &AllowRule) -> Option<String> {
    let saddr = nft_saddr(rule.scope)?;
    Some(format!(
        "{saddr}{} dport {} accept comment \"selfhost-{}-{}\"",
        rule.proto.tag(),
        rule.port,
        rule.tag,
        rule.port,
    ))
}

/// The whole `inet selfhost` table for a set of openings and a default policy.
///
/// Pure and total. `add table` then `delete table` makes the reload tolerate the
/// table being absent or present, and redefining it in the same script replaces
/// it in one atomic transaction.
pub fn ruleset(rules: &[AllowRule], block: bool) -> String {
    let policy = if block { "drop" } else { "accept" };
    let mut body = String::new();
    body.push_str("add table inet selfhost\n");
    body.push_str("delete table inet selfhost\n");
    body.push_str("table inet selfhost {\n");
    body.push_str("\tchain input {\n");
    body.push_str(&format!("\t\ttype filter hook input priority 0; policy {policy};\n"));
    body.push_str("\t\tiif \"lo\" accept\n");
    body.push_str("\t\tct state established,related accept\n");
    body.push_str(&format!("\t\ttcp dport {SSH_PORT} accept comment \"selfhost-ssh\"\n"));
    for rule in rules {
        if let Some(line) = rule_line(rule) {
            body.push_str("\t\t");
            body.push_str(&line);
            body.push('\n');
        }
    }
    body.push_str("\t}\n}\n");
    body
}

/// The destination ports named by `dport` in `nft list` output.
fn parse_dports(output: &str) -> Vec<u16> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    tokens
        .iter()
        .enumerate()
        .filter(|(_, token)| **token == "dport")
        .filter_map(|(index, _)| tokens.get(index + 1))
        .filter_map(|text| text.parse::<u16>().ok())
        .collect()
}

/// Whether an nftables error means the owned table simply is not there yet.
fn table_absent(error: &FirewallError) -> bool {
    match error {
        FirewallError::Command { detail, .. } => {
            let lower = detail.to_ascii_lowercase();
            lower.contains("no such file") || lower.contains("does not exist")
        }
        _ => false,
    }
}

impl FirewallBackend for NftablesBackend {
    async fn snapshot(&self) -> Result<FirewallState, FirewallError> {
        let listed = run::run(
            &self.program,
            &["list".into(), "table".into(), "inet".into(), "selfhost".into()],
            None,
            COMMAND_TIMEOUT,
        )
        .await?
        .ok_or_error(&self.program);

        let output = match listed {
            Ok(ran) => ran.stdout,
            // No table yet is "not managing", not a failure.
            Err(error) if table_absent(&error) => {
                return Ok(FirewallState {
                    backend: BackendKind::Nftables,
                    managed: false,
                    default_inbound_block: false,
                    rules: Vec::new(),
                });
            }
            Err(error) => return Err(error),
        };

        let rules = parse_dports(&output)
            .into_iter()
            .map(|port| RuleState {
                rule: AllowRule { port, proto: Proto::Tcp, scope: Scope::Lan, tag: String::new() },
                applied: true,
            })
            .collect();

        Ok(FirewallState {
            backend: BackendKind::Nftables,
            managed: false,
            default_inbound_block: output.contains("policy drop"),
            rules,
        })
    }

    async fn reconcile(&self, desired: &[AllowRule]) -> Result<FirewallState, FirewallError> {
        let body = ruleset(desired, true);
        run::run(&self.program, &["-f".into(), "-".into()], Some(&body), COMMAND_TIMEOUT)
            .await?
            .ok_or_error(&self.program)?;
        self.snapshot().await
    }

    async fn set_default_inbound_block(&self, block: bool) -> Result<(), FirewallError> {
        let body = if block {
            ruleset(&[], true)
        } else {
            // Stop managing: drop the owned table, leaving every other table alone.
            String::from("add table inet selfhost\ndelete table inet selfhost\n")
        };
        run::run(&self.program, &["-f".into(), "-".into()], Some(&body), COMMAND_TIMEOUT)
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
    fn the_table_drops_by_default_but_admits_loopback_replies_and_ssh_first() {
        let body = ruleset(&[], true);
        assert!(body.contains("policy drop"), "{body}");
        assert!(body.contains("iif \"lo\" accept"), "{body}");
        assert!(body.contains("ct state established,related accept"), "{body}");
        assert!(body.contains(&format!("tcp dport {SSH_PORT} accept")), "SSH first:\n{body}");
    }

    #[test]
    fn an_opening_names_its_scope_source_and_carries_a_selfhost_comment() {
        let body = ruleset(&[tcp(443, Scope::Lan, "https")], true);
        assert!(body.contains("ip saddr { 10.0.0.0/8"), "lan source:\n{body}");
        assert!(body.contains("tcp dport 443 accept"), "{body}");
        assert!(body.contains("comment \"selfhost-https-443\""), "marked as ours:\n{body}");
    }

    #[test]
    fn an_internet_opening_carries_no_source_match() {
        let body = ruleset(&[tcp(443, Scope::Internet, "https")], true);
        assert!(body.contains("tcp dport 443 accept"), "{body}");
        assert!(!body.contains("saddr"), "internet is unrestricted source:\n{body}");
    }

    #[test]
    fn a_loopback_scoped_opening_is_never_written() {
        let body = ruleset(&[tcp(80, Scope::Loopback, "http")], true);
        assert!(!body.contains("dport 80"), "{body}");
    }

    #[test]
    fn the_replace_reload_tolerates_the_table_being_absent_or_present() {
        let body = ruleset(&[], true);
        let add = body.find("add table inet selfhost").expect("adds first");
        let delete = body.find("delete table inet selfhost").expect("then deletes");
        assert!(add < delete, "add must precede delete so delete cannot fail on a fresh host");
    }

    #[test]
    fn dports_are_read_back_from_an_nft_listing() {
        let dump = "tcp dport 22 accept\ntcp dport 443 accept\ntcp dport 80 accept\n";
        assert_eq!(parse_dports(dump), vec![22, 443, 80]);
    }
}
