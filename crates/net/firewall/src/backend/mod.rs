//! One host's inbound firewall, and the contract every platform honours.
//!
//! The impure half of the crate. [`FirewallBackend`] is the one contract; the
//! concrete backends ([`PfBackend`], [`NftablesBackend`], [`NetshBackend`],
//! [`UnsupportedBackend`]) each implement it *and* expose a pure script/args
//! builder that carries the interesting logic, so the decisions are tested
//! without a firewall present and only the plumbing is left untested — the same
//! split as `git::plan` vs `git::run`.
//!
//! [`HostFirewall`] is a closed enum, not `Box<dyn>`: async-fn-in-trait is not
//! dyn-compatible, and this project prefers a matched set to a trait object
//! anyway. It implements the trait by delegating to whichever variant [`detect`]
//! chose for this operating system.

pub mod netsh;
pub mod nftables;
pub mod pf;
pub mod unsupported;

pub use netsh::NetshBackend;
pub use nftables::NftablesBackend;
pub use pf::PfBackend;
pub use unsupported::UnsupportedBackend;

use crate::rule::AllowRule;
use crate::state::{BackendKind, FirewallState};
use std::path::PathBuf;

/// Why the firewall could not be read or set.
///
/// Modelled on [`selfhost_git`](../../../selfhost_git/index.html)'s `RunError` and
/// the config crate's `ConfigError`: an enum whose `Display` says what to do, and
/// which is reported and continued past rather than swallowed — a firewall that
/// could not be set is worse unknown than known-unset.
#[derive(Debug)]
pub enum FirewallError {
    /// No backend for this operating system.
    Unsupported {
        /// The operating system, as `std::env::consts::OS` names it.
        platform: &'static str,
    },
    /// The firewall tool (`pfctl`/`nft`/`netsh`) is not installed or not on `PATH`.
    ToolMissing {
        /// The program that could not be started.
        program: PathBuf,
        /// What the operating system said.
        reason: std::io::Error,
    },
    /// The tool ran and refused. Carries its own most-useful line.
    Command {
        /// The program that refused.
        program: String,
        /// Its exit code, if it exited rather than being killed.
        code: Option<i32>,
        /// The most useful line it printed.
        detail: String,
    },
    /// The tool refused for want of privilege the daemon does not have.
    Denied {
        /// The program that needed the privilege.
        program: String,
    },
    /// The tool started but could not be waited for or read.
    Io(std::io::Error),
}

impl std::fmt::Display for FirewallError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported { platform } => write!(
                formatter,
                "no firewall backend for {platform}; leave server.firewall.manage off on this host"
            ),
            Self::ToolMissing { program, reason } => write!(
                formatter,
                "cannot run {}: {reason}. Install it, or put it on the daemon's PATH",
                program.display()
            ),
            Self::Command { program, code, detail } => match code {
                Some(code) => write!(formatter, "{program} exited with code {code}: {detail}"),
                None => write!(formatter, "{program} failed: {detail}"),
            },
            Self::Denied { program } => write!(
                formatter,
                "{program} needs privilege the daemon does not have; run the daemon with the \
                 privilege to set the firewall, or leave server.firewall.manage off"
            ),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for FirewallError {}

/// One host's inbound firewall, as this project drives it.
///
/// Every method is idempotent: [`reconcile`](FirewallBackend::reconcile) applies
/// the difference between the live firewall and `desired` and is safe to call on
/// every daemon start. Errors are reported, never swallowed.
///
/// Native `async fn` in trait (edition 2024, stable RPITIT). The lint that warns
/// this is not dyn-compatible is allowed on purpose: the trait is never used
/// through `dyn` — [`HostFirewall`] holds the concrete backend and delegates.
#[allow(async_fn_in_trait)]
pub trait FirewallBackend {
    /// Reads the current inbound policy and which managed rules are present.
    ///
    /// Reads only rules this backend itself created (its owned table / anchor /
    /// name-prefixed rules). Foreign rules are never reported, which is what
    /// keeps the reconciler from ever withdrawing one.
    async fn snapshot(&self) -> Result<FirewallState, FirewallError>;

    /// Makes the live firewall match `desired`, then returns the resulting state.
    ///
    /// Adds missing openings, withdraws managed openings no longer desired, and
    /// leaves every rule the daemon did not create untouched. Callers pass the
    /// config-derived set; each backend folds in the always-open SSH allowance
    /// itself, so no reconcile can lock the operator out.
    async fn reconcile(&self, desired: &[AllowRule]) -> Result<FirewallState, FirewallError>;

    /// Sets whether inbound is default-deny.
    ///
    /// Called before [`reconcile`](FirewallBackend::reconcile) so a window never
    /// opens where a port is allowed while the default is still permit-all. The
    /// default-deny skeleton itself keeps SSH and established connections open, so
    /// enabling it cannot sever the operator's session.
    async fn set_default_inbound_block(&self, block: bool) -> Result<(), FirewallError>;
}

/// The backend for this host, chosen at runtime.
pub enum HostFirewall {
    /// macOS.
    Pf(PfBackend),
    /// Linux.
    Nftables(NftablesBackend),
    /// Windows.
    Netsh(NetshBackend),
    /// Everything else.
    Unsupported(UnsupportedBackend),
}

impl HostFirewall {
    /// Which firewall this is, for display and the wire.
    pub fn kind(&self) -> BackendKind {
        match self {
            Self::Pf(_) => BackendKind::Pf,
            Self::Nftables(_) => BackendKind::Nftables,
            Self::Netsh(_) => BackendKind::Netsh,
            Self::Unsupported(_) => BackendKind::Unsupported,
        }
    }
}

impl FirewallBackend for HostFirewall {
    async fn snapshot(&self) -> Result<FirewallState, FirewallError> {
        match self {
            Self::Pf(backend) => backend.snapshot().await,
            Self::Nftables(backend) => backend.snapshot().await,
            Self::Netsh(backend) => backend.snapshot().await,
            Self::Unsupported(backend) => backend.snapshot().await,
        }
    }

    async fn reconcile(&self, desired: &[AllowRule]) -> Result<FirewallState, FirewallError> {
        match self {
            Self::Pf(backend) => backend.reconcile(desired).await,
            Self::Nftables(backend) => backend.reconcile(desired).await,
            Self::Netsh(backend) => backend.reconcile(desired).await,
            Self::Unsupported(backend) => backend.reconcile(desired).await,
        }
    }

    async fn set_default_inbound_block(&self, block: bool) -> Result<(), FirewallError> {
        match self {
            Self::Pf(backend) => backend.set_default_inbound_block(block).await,
            Self::Nftables(backend) => backend.set_default_inbound_block(block).await,
            Self::Netsh(backend) => backend.set_default_inbound_block(block).await,
            Self::Unsupported(backend) => backend.set_default_inbound_block(block).await,
        }
    }
}

/// Picks the backend that fits this operating system.
pub fn detect() -> HostFirewall {
    #[cfg(target_os = "macos")]
    {
        HostFirewall::Pf(PfBackend::new())
    }
    #[cfg(target_os = "linux")]
    {
        HostFirewall::Nftables(NftablesBackend::new())
    }
    #[cfg(windows)]
    {
        HostFirewall::Netsh(NetshBackend::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        HostFirewall::Unsupported(UnsupportedBackend)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_names_a_backend_and_kind_agrees_with_the_variant() {
        // Whatever this host is, detect() returns a concrete backend whose kind()
        // matches the variant — never a mismatch the wire would then lie about.
        let host = detect();
        let expected = match host {
            HostFirewall::Pf(_) => BackendKind::Pf,
            HostFirewall::Nftables(_) => BackendKind::Nftables,
            HostFirewall::Netsh(_) => BackendKind::Netsh,
            HostFirewall::Unsupported(_) => BackendKind::Unsupported,
        };
        assert_eq!(host.kind(), expected);
    }

    #[test]
    fn errors_say_what_to_do_rather_than_only_what_broke() {
        let denied = FirewallError::Denied { program: "nft".into() };
        assert!(denied.to_string().contains("manage off") || denied.to_string().contains("privilege"));
        let unsupported = FirewallError::Unsupported { platform: "redox" };
        assert!(unsupported.to_string().contains("redox"));
    }
}
