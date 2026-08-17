//! The macOS backend: the packet filter, `pf`, driven through `pfctl`.
//!
//! Two pieces of state, loaded separately so their concerns stay apart:
//!
//! - A **base ruleset** (`pfctl -f -`) sets the default-deny skeleton — block
//!   inbound, pass out, pass SSH, and call the `com.selfhost` anchor. This is
//!   what [`set_default_inbound_block`](FirewallBackend::set_default_inbound_block)
//!   loads, and it is where the SSH-and-established safety lives, so the deny is
//!   atomic with the exceptions that keep the operator connected.
//! - The **`com.selfhost` anchor** (`pfctl -a com.selfhost -f -`) holds the
//!   public-listener openings. This is what [`reconcile`](FirewallBackend::reconcile)
//!   replaces wholesale — loading an anchor swaps its entire contents atomically,
//!   which adds new openings and drops stale ones in one step and never touches a
//!   rule outside the anchor.
//!
//! macOS ships `pf` disabled with an all-but-empty ruleset, so managing it is
//! normally taking over an unused firewall. Turning `manage` on hands this backend
//! ownership of pf's active ruleset; a host with a hand-written `/etc/pf.conf`
//! should keep `manage` off.
//!
//! | Scope | pf source |
//! |---|---|
//! | `Lan` | `{ 10/8 172.16/12 192.168/16 100.64/10 169.254/16 127/8 }` |
//! | `Internet` | `any` |
//! | `Loopback` | never emitted — the default block is the whole policy |

use crate::backend::{FirewallBackend, FirewallError};
use crate::rule::{AllowRule, Proto, LAN_CIDRS, SSH_PORT};
use crate::run::{self, COMMAND_TIMEOUT};
use crate::state::{BackendKind, FirewallState, RuleState};
use selfhost_config::Scope;

/// The anchor this backend owns. Everything it writes lives here; everything
/// outside it is the operator's and is never touched by a reconcile.
const ANCHOR: &str = "com.selfhost";

/// The macOS `pf` backend.
pub struct PfBackend {
    program: String,
}

impl PfBackend {
    /// A backend driving the system `pfctl`.
    pub fn new() -> Self {
        Self { program: "pfctl".into() }
    }
}

impl Default for PfBackend {
    fn default() -> Self {
        Self::new()
    }
}

/// The pf source expression admitting a scope.
///
/// `Loopback` has no expression: it is never emitted as a rule, because its whole
/// policy is the default block.
fn pf_source(scope: Scope) -> Option<String> {
    match scope {
        Scope::Internet => Some("any".into()),
        Scope::Lan => Some(format!("{{ {} }}", LAN_CIDRS.join(" "))),
        Scope::Loopback => None,
    }
}

/// One `pass in quick` line for an opening.
fn pass_line(rule: &AllowRule) -> Option<String> {
    let source = pf_source(rule.scope)?;
    Some(format!(
        "pass in quick proto {} from {source} to any port {} keep state # {}",
        rule.proto.tag(),
        rule.port,
        rule.tag,
    ))
}

/// The `com.selfhost` anchor body for a set of openings.
///
/// Pure and total: given the same openings it produces the same text, so what
/// the anchor will hold is asserted directly rather than read back off a host.
pub fn anchor_body(rules: &[AllowRule]) -> String {
    let mut body = String::from("# selfhost-managed anchor — regenerated on every reconcile\n");
    for rule in rules {
        if let Some(line) = pass_line(rule) {
            body.push_str(&line);
            body.push('\n');
        }
    }
    body
}

/// The default-deny base ruleset.
///
/// Block inbound, pass everything out, always pass SSH from the local network,
/// and call the anchor. Established connections survive a ruleset reload because
/// pf keeps their state, so loading this cannot drop the operator's session.
pub fn base_ruleset() -> String {
    let lan = format!("{{ {} }}", LAN_CIDRS.join(" "));
    format!(
        "# selfhost-managed base ruleset\n\
         set skip on lo0\n\
         block drop in all\n\
         pass out all keep state\n\
         pass in quick proto tcp from {lan} to any port {SSH_PORT} keep state # ssh\n\
         anchor \"{ANCHOR}\"\n",
    )
}

/// The ports named by the passes in `pfctl -sr` output.
///
/// pf prints an opening as `... to any port = 80`; this reads the number after
/// each `port`, tolerating the `=` pf inserts.
fn parse_ports(output: &str) -> Vec<u16> {
    let tokens: Vec<&str> = output.split_whitespace().collect();
    let mut ports = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if *token == "port" {
            let candidate = match tokens.get(index + 1) {
                Some(&"=") => tokens.get(index + 2),
                other => other,
            };
            if let Some(port) = candidate.and_then(|text| text.parse::<u16>().ok()) {
                ports.push(port);
            }
        }
    }
    ports
}

/// Whether a `pfctl -sr` dump blocks inbound by default.
fn blocks_inbound(main_ruleset: &str) -> bool {
    main_ruleset.lines().map(str::trim).any(|line| {
        line.starts_with("block") && line.contains(" in ") && line.contains("all")
    })
}

impl PfBackend {
    /// Enough of a non-fatal "already enabled/disabled" tolerance that toggling
    /// pf twice is not an error. `pfctl -e`/`-d` exit non-zero and say so when the
    /// state is already what was asked for.
    async fn toggle(&self, flag: &str) -> Result<(), FirewallError> {
        match run::run(&self.program, &[flag.into()], None, COMMAND_TIMEOUT).await {
            Ok(ran) if ran.succeeded() => Ok(()),
            Ok(ran) if ran.complaint().to_ascii_lowercase().contains("already") => Ok(()),
            Ok(ran) => ran.ok_or_error(&self.program).map(|_| ()),
            Err(error) => Err(error),
        }
    }
}

impl FirewallBackend for PfBackend {
    async fn snapshot(&self) -> Result<FirewallState, FirewallError> {
        let anchor = run::run(
            &self.program,
            &["-a".into(), ANCHOR.into(), "-sr".into()],
            None,
            COMMAND_TIMEOUT,
        )
        .await?
        .ok_or_error(&self.program)?;
        let main = run::run(&self.program, &["-sr".into()], None, COMMAND_TIMEOUT)
            .await?
            .ok_or_error(&self.program)?;
        let info = run::run(&self.program, &["-si".into()], None, COMMAND_TIMEOUT)
            .await?
            .ok_or_error(&self.program)?;

        let enabled = info.stdout.contains("Status: Enabled");
        let rules = parse_ports(&anchor.stdout)
            .into_iter()
            .map(|port| RuleState {
                rule: AllowRule { port, proto: Proto::Tcp, scope: Scope::Lan, tag: String::new() },
                applied: true,
            })
            .collect();

        Ok(FirewallState {
            backend: BackendKind::Pf,
            managed: false,
            default_inbound_block: enabled && blocks_inbound(&main.stdout),
            rules,
        })
    }

    async fn reconcile(&self, desired: &[AllowRule]) -> Result<FirewallState, FirewallError> {
        // The anchor holds the public-listener openings; SSH lives in the base
        // ruleset, so it is not repeated here. Loading the anchor replaces its
        // whole contents at once — stale openings vanish, new ones appear, and
        // nothing outside the anchor is affected.
        let body = anchor_body(desired);
        run::run(
            &self.program,
            &["-a".into(), ANCHOR.into(), "-f".into(), "-".into()],
            Some(&body),
            COMMAND_TIMEOUT,
        )
        .await?
        .ok_or_error(&self.program)?;
        self.snapshot().await
    }

    async fn set_default_inbound_block(&self, block: bool) -> Result<(), FirewallError> {
        if block {
            run::run(&self.program, &["-f".into(), "-".into()], Some(&base_ruleset()), COMMAND_TIMEOUT)
                .await?
                .ok_or_error(&self.program)?;
            self.toggle("-e").await
        } else {
            self.toggle("-d").await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(port: u16, scope: Scope, tag: &str) -> AllowRule {
        AllowRule { port, proto: Proto::Tcp, scope, tag: tag.into() }
    }

    #[test]
    fn the_anchor_opens_each_port_under_its_scopes_source() {
        let body = anchor_body(&[tcp(443, Scope::Lan, "https"), tcp(80, Scope::Internet, "http")]);
        assert!(body.contains("to any port 443"), "{body}");
        assert!(body.contains("10.0.0.0/8"), "lan scope names the private ranges:\n{body}");
        assert!(body.contains("from any to any port 80"), "internet scope is any:\n{body}");
    }

    #[test]
    fn a_loopback_scoped_opening_is_never_written() {
        // Loopback scope's whole policy is the default block; a pass line would
        // contradict it.
        let body = anchor_body(&[tcp(80, Scope::Loopback, "http")]);
        assert!(!body.contains("port 80"), "{body}");
    }

    #[test]
    fn the_base_ruleset_blocks_inbound_but_always_lets_ssh_and_replies_through() {
        let base = base_ruleset();
        assert!(base.contains("block drop in all"), "{base}");
        assert!(base.contains(&format!("port {SSH_PORT}")), "SSH is never blocked:\n{base}");
        assert!(base.contains("pass out all keep state"), "replies survive:\n{base}");
        assert!(base.contains(&format!("anchor \"{ANCHOR}\"")), "{base}");
    }

    #[test]
    fn ports_are_read_back_from_pfctl_output_with_or_without_the_equals() {
        let dump = "pass in quick proto tcp from any to any port = 443\n\
                    pass in quick proto tcp from any to any port 80\n";
        assert_eq!(parse_ports(dump), vec![443, 80]);
    }

    #[test]
    fn a_default_block_is_recognised_only_when_inbound_is_actually_blocked() {
        assert!(blocks_inbound("block drop in all\npass out all\n"));
        assert!(!blocks_inbound("pass in all\npass out all\n"));
    }
}
