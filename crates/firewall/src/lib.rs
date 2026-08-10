//! The host firewall, driven to match the operator's chosen scope.
//!
//! A bind on `0.0.0.0` is reachable by anyone the *network* lets through. This
//! crate's whole job is to narrow that to the operator's intent: it derives the
//! inbound allowances the public listeners need from config, and makes the live
//! firewall hold exactly those and nothing else it did not itself create.
//!
//! # The shape of the crate
//!
//! It mirrors the pure/impure split the rest of the project uses to stay
//! testable ([`selfhost_git`](../selfhost_git/index.html)'s `plan` vs `run`):
//!
//! - [`rule`] is pure. [`desired_rules`] turns a [`Server`](selfhost_config::Server)
//!   into the allowances it requires, and [`diff`] decides — with no firewall
//!   present — which managed rules to add, withdraw, or keep. These are the
//!   load-bearing decisions, and they are asserted directly.
//! - [`state`] is the wire format the console reads, hand-written camelCase JSON
//!   the same way [`selfhost_supervisor`](../selfhost_supervisor/index.html) writes
//!   a service's state.
//! - [`backend`] is the thin impure half: one [`FirewallBackend`] per platform,
//!   each shelling out through [`run`], selected at runtime by [`detect`].
//! - [`manager`] is the cheap-clone [`Manager`] handle the daemon and the admin
//!   API share, exactly like `Supervisor` and `Watches`.
//!
//! # The one rule that outranks the others
//!
//! Managing a firewall on a machine reached over SSH must never lock the operator
//! out of it. Every managed policy therefore keeps SSH ([`SSH_PORT`]) open and
//! preserves established connections, so turning default-deny on can only ever
//! narrow *new* inbound traffic to the public listeners — never the operator's
//! own way in. See [`with_ssh`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod manager;
pub mod rule;
pub mod run;
pub mod state;

pub use selfhost_config::Scope;

pub use backend::{detect, FirewallBackend, FirewallError, HostFirewall};
pub use manager::{reconcile_plan, Manager};
pub use rule::{
    desired_rules, diff, ssh_rule, with_ssh, AllowRule, Proto, Reconciliation, LAN_CIDRS, SSH_PORT,
};
pub use state::{BackendKind, FirewallState, RuleState};
