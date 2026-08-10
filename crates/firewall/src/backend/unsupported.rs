//! The backend for an operating system this crate has no firewall driver for.
//!
//! It refuses to *change* anything — a set that silently did nothing would be a
//! firewall the operator believes is up and is not — but its [`snapshot`] answers
//! rather than errors, so the console can say "unsupported here" instead of
//! showing a broken pane.
//!
//! [`snapshot`]: FirewallBackend::snapshot

use crate::backend::{FirewallBackend, FirewallError};
use crate::rule::AllowRule;
use crate::state::{BackendKind, FirewallState};

/// The no-op backend for an unsupported platform.
pub struct UnsupportedBackend;

impl UnsupportedBackend {
    /// The operating system this is standing in for, for the error message.
    fn platform() -> &'static str {
        std::env::consts::OS
    }
}

impl FirewallBackend for UnsupportedBackend {
    async fn snapshot(&self) -> Result<FirewallState, FirewallError> {
        Ok(FirewallState {
            backend: BackendKind::Unsupported,
            managed: false,
            default_inbound_block: false,
            rules: Vec::new(),
        })
    }

    async fn reconcile(&self, _desired: &[AllowRule]) -> Result<FirewallState, FirewallError> {
        Err(FirewallError::Unsupported { platform: Self::platform() })
    }

    async fn set_default_inbound_block(&self, _block: bool) -> Result<(), FirewallError> {
        Err(FirewallError::Unsupported { platform: Self::platform() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn it_reports_a_state_but_refuses_to_change_anything() {
        let backend = UnsupportedBackend;
        let state = backend.snapshot().await.expect("a snapshot, not an error");
        assert_eq!(state.backend, BackendKind::Unsupported);
        assert!(!state.managed);
        assert!(backend.reconcile(&[]).await.is_err(), "a silent no-op would be a lie");
        assert!(backend.set_default_inbound_block(true).await.is_err());
    }
}
