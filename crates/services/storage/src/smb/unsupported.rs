//! The backend for an operating system this crate has no SMB driver for.
//!
//! It refuses to *change* anything, because an operation that silently no-ops is
//! worse than one that refuses: the operator believes their share is exported,
//! their colleague cannot see it, and nothing anywhere says why. But
//! [`snapshot`](SmbBackend::snapshot) answers rather than errors, so the console
//! can render "no SMB driver here" instead of a broken pane, and a deployment
//! that declares no `[shares.smb]` block never sees an error at all.
//!
//! That last point is the reason [`reconcile`](SmbBackend::reconcile) is not a
//! blanket refusal. A plan that changes nothing on the host is satisfied by doing
//! nothing, on every platform including this one — so a FreeBSD box serving
//! shares over WebDAV alone reconciles cleanly, and only a box that actually
//! asked for an SMB export is told this platform cannot give it one.

use crate::smb::plan::{Action, Apply, LiveShare, Performed, Reconciliation};
use crate::smb::{SmbBackend, SmbError};

/// The no-op backend for an unsupported platform.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnsupportedBackend;

impl UnsupportedBackend {
    /// The operating system this is standing in for, for the error message.
    fn platform() -> &'static str {
        std::env::consts::OS
    }
}

impl SmbBackend for UnsupportedBackend {
    async fn snapshot(&self) -> Result<Vec<LiveShare>, SmbError> {
        Ok(Vec::new())
    }

    async fn service_running(&self) -> Result<Option<bool>, SmbError> {
        Ok(None)
    }

    async fn start_service(&self, _apply: Apply) -> Result<bool, SmbError> {
        Err(SmbError::Unsupported { platform: Self::platform() })
    }

    async fn reconcile(
        &self,
        plan: &Reconciliation,
        apply: Apply,
    ) -> Result<Vec<Performed>, SmbError> {
        if plan.changes_the_host() {
            return Err(SmbError::Unsupported { platform: Self::platform() });
        }
        // Forgetting a name is this deployment's own bookkeeping and needs no
        // SMB server, so it is honoured even here.
        Ok(plan
            .forget
            .iter()
            .map(|name| Performed {
                action: Action::Forget,
                name: name.clone(),
                applied: apply.writes(),
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::SmbName;
    use crate::smb::plan::Reconciliation;

    #[tokio::test]
    async fn it_reports_a_state_but_refuses_to_export_anything() {
        let backend = UnsupportedBackend;
        assert!(backend.snapshot().await.expect("a reading, not an error").is_empty());
        assert_eq!(backend.service_running().await.expect("no error"), None);
        assert!(backend.start_service(Apply::Write).await.is_err(), "a silent no-op would be a lie");
    }

    #[tokio::test]
    async fn a_plan_that_changes_nothing_succeeds_even_here() {
        let performed = UnsupportedBackend
            .reconcile(&Reconciliation::default(), Apply::Write)
            .await
            .expect("nothing to do is not a failure");
        assert!(performed.is_empty());
    }

    #[tokio::test]
    async fn a_plan_that_wants_an_export_is_refused_with_the_platform_named() {
        let mut plan = Reconciliation::default();
        plan.remove.push(SmbName::parse("Vault").expect("legal"));
        let error = UnsupportedBackend
            .reconcile(&plan, Apply::Write)
            .await
            .expect_err("this platform cannot do it");
        assert!(error.to_string().contains(std::env::consts::OS), "{error}");
    }

    #[tokio::test]
    async fn a_ledger_entry_can_still_be_forgotten_without_an_smb_server() {
        let mut plan = Reconciliation::default();
        plan.forget.push(SmbName::parse("Vault").expect("legal"));
        let performed =
            UnsupportedBackend.reconcile(&plan, Apply::Write).await.expect("bookkeeping only");
        assert_eq!(performed.len(), 1);
        assert_eq!(performed[0].action, Action::Forget);
        assert!(performed[0].applied);
    }
}
