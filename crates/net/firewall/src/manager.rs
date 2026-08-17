//! The handle the daemon and the admin API share to drive the firewall.
//!
//! A cheap-clone `Arc`, exactly like `Supervisor` and `Watches`, so the process
//! that reconciles at start-up and the endpoint that reconciles on request hold
//! one manager rather than two that could disagree. It owns the backend, the
//! openings derived from config once, and the last state it observed.

use crate::backend::{detect, FirewallBackend, FirewallError, HostFirewall};
use crate::rule::{desired_rules, AllowRule};
use crate::state::{FirewallState, RuleState};
use std::sync::Arc;
use tokio::sync::Mutex;

/// The per-opening status of `desired` against a snapshot's live rules.
///
/// Maps each desired opening to whether the snapshot holds it, matched by
/// transport and port ([`AllowRule::same_opening`](crate::AllowRule::same_opening)).
/// This is how a snapshot of the rules a backend *found* becomes a report of the
/// rules the operator *asked for*, with an honest applied/not-applied on each.
pub fn reconcile_plan(current: &FirewallState, desired: &[AllowRule]) -> Vec<RuleState> {
    desired
        .iter()
        .map(|rule| RuleState {
            rule: rule.clone(),
            applied: current.rules.iter().any(|held| held.applied && held.rule.same_opening(rule)),
        })
        .collect()
}

/// Owns the backend, the rules derived from config, and the last known state.
#[derive(Clone)]
pub struct Manager(Arc<Inner>);

struct Inner {
    backend: HostFirewall,
    desired: Vec<AllowRule>,
    managed: bool,
    last: Mutex<FirewallState>,
}

impl Manager {
    /// Detects the backend and derives the desired openings from the config —
    /// the web binds, plus the mail binds when `[mail]` is present.
    pub fn for_config(config: &selfhost_config::Config) -> Self {
        let server = &config.server;
        let backend = detect();
        let desired = desired_rules(server, config.mail.as_ref());
        let managed = server.firewall.manage;
        let last = FirewallState {
            backend: backend.kind(),
            managed,
            default_inbound_block: false,
            rules: desired.iter().map(|rule| RuleState { rule: rule.clone(), applied: false }).collect(),
        };
        Manager(Arc::new(Inner { backend, desired, managed, last: Mutex::new(last) }))
    }

    /// Applies the default inbound block then the desired openings, caching and
    /// returning the resulting state.
    ///
    /// Called once at daemon start and again by the admin `reconcile` endpoint.
    /// When the firewall is unmanaged it changes nothing and asserts nothing — it
    /// only reports what the host already holds. The `managed` flag on the
    /// returned state is the config's, not the backend's guess, so the daemon and
    /// console can trust it.
    pub async fn reconcile(&self) -> Result<FirewallState, FirewallError> {
        let inner = &self.0;
        if !inner.managed {
            // Read-only, best-effort: a host we are not managing should still be
            // reportable, but a failure to read it is not a failure to manage it.
            let block =
                inner.backend.snapshot().await.map(|state| state.default_inbound_block).unwrap_or(false);
            let state = FirewallState {
                backend: inner.backend.kind(),
                managed: false,
                default_inbound_block: block,
                rules: Vec::new(),
            };
            *inner.last.lock().await = state.clone();
            return Ok(state);
        }

        inner.backend.set_default_inbound_block(true).await?;
        let observed = inner.backend.reconcile(&inner.desired).await?;
        let state = FirewallState {
            backend: observed.backend,
            managed: true,
            default_inbound_block: observed.default_inbound_block,
            rules: reconcile_plan(&observed, &inner.desired),
        };
        *inner.last.lock().await = state.clone();
        Ok(state)
    }

    /// The last observed state, refreshed by a snapshot when one can be taken.
    ///
    /// A snapshot that fails (no privilege, or an unsupported host) falls back to
    /// the cached state rather than erroring, so a status read never breaks the
    /// console — the console shows the last truth it knew.
    pub async fn state(&self) -> FirewallState {
        let inner = &self.0;
        match inner.backend.snapshot().await {
            Ok(observed) => {
                let state = FirewallState {
                    backend: observed.backend,
                    managed: inner.managed,
                    default_inbound_block: observed.default_inbound_block,
                    rules: reconcile_plan(&observed, &inner.desired),
                };
                *inner.last.lock().await = state.clone();
                state
            }
            Err(_) => inner.last.lock().await.clone(),
        }
    }

    /// The openings this manager was built to hold, for diagnostics and tests.
    pub fn desired(&self) -> &[AllowRule] {
        &self.0.desired
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::Proto;
    use crate::state::BackendKind;
    use selfhost_config::Scope;

    fn opening(port: u16, tag: &str) -> AllowRule {
        AllowRule { port, proto: Proto::Tcp, scope: Scope::Lan, tag: tag.into() }
    }

    fn observed(present: &[u16], block: bool) -> FirewallState {
        FirewallState {
            backend: BackendKind::Nftables,
            managed: false,
            default_inbound_block: block,
            rules: present
                .iter()
                .map(|&port| RuleState { rule: opening(port, ""), applied: true })
                .collect(),
        }
    }

    #[test]
    fn a_desired_opening_the_host_holds_reads_as_applied() {
        let plan = reconcile_plan(&observed(&[80, 443], true), &[opening(80, "http"), opening(443, "https")]);
        assert!(plan.iter().all(|rule| rule.applied), "{plan:?}");
    }

    #[test]
    fn a_desired_opening_the_host_lacks_reads_as_not_applied() {
        // The host holds 80 but not 443: the report must show 443 unapplied
        // rather than hiding that the firewall is not yet what config asked for.
        let plan = reconcile_plan(&observed(&[80], true), &[opening(80, "http"), opening(443, "https")]);
        assert_eq!(plan.iter().filter(|rule| rule.applied).count(), 1);
        assert!(!plan.iter().find(|rule| rule.rule.port == 443).unwrap().applied);
    }

    #[test]
    fn a_present_rule_the_host_reports_as_inactive_does_not_count_as_applied() {
        let mut snapshot = observed(&[443], true);
        snapshot.rules[0].applied = false;
        let plan = reconcile_plan(&snapshot, &[opening(443, "https")]);
        assert!(!plan[0].applied);
    }
}
