//! Asking the operating system to export a share over SMB.
//!
//! **We do not implement SMB and we are not pretending to.** The protocol is a
//! decade of work, and every platform this project runs on already ships a
//! server that the platform's own clients trust, negotiate encryption with, and
//! authenticate against. What this module does is drive that server: it decides
//! what should be exported and then asks `sharing`, `New-SmbShare`, or Samba to
//! do it. Nothing here speaks SMB, opens a socket, or authenticates a client.
//!
//! # The consequence, which is user-visible and is not a bug
//!
//! Because the operating system is the server, **SMB authenticates against
//! operating-system accounts** — NTLM or Kerberos against a Windows or macOS
//! account, `smbpasswd` against a Samba one. The console password cannot open an
//! SMB session on any of the three platforms, and no amount of work in this crate
//! would change that: the credential is checked inside a service this project
//! does not run. The browser file manager, WebDAV, and the CLI all use the
//! console credential; SMB uses the OS account.
//!
//! That sentence is shipped as data — [`plan::AUTHENTICATION_NOTICE`], carried in
//! [`plan::SmbState::to_json`] — so a console plate cannot render SMB state
//! without having the caveat to hand. It is the difference between an
//! expectation and a bug report.
//!
//! # What enabling an export actually does to the box, said plainly
//!
//! The operating system's SMB server listens on **`445` on every interface it is
//! bound to**. This crate binds nothing, and starting that service is gated
//! behind [`plan::Apply::Write`] and an explicit call — but the honest way to
//! read "`[shares.smb]` is configured and applied" is *this box now answers file
//! requests on the local network*. Two things follow, and both are the operator's
//! to weigh rather than ours to hide:
//!
//! - The console's `allowed_cidrs` gate does **not** apply to it. That gate is a
//!   property of the HTTP site; SMB does not go through the proxy.
//! - `selfhost_firewall::desired_rules` does not open `445`. On a box with
//!   `server.firewall.manage = true` and default-deny inbound, an SMB export is
//!   created, advertised, and then unreachable. That is the safe failure and it
//!   is deliberate — opening a file-sharing port is not something a storage
//!   config change should do to a firewall behind the operator's back — but it
//!   means "the share does not appear" has a firewall answer as well as an SMB
//!   one.
//!
//! # The shape of the module
//!
//! A structural clone of [`selfhost_firewall`](../../../selfhost_firewall/index.html),
//! because the problem is the same problem: a desired state, a live state that
//! belongs to somebody else's software, and a diff that must be conservative in
//! exactly one direction.
//!
//! | File | Pure? | What it holds |
//! |---|---|---|
//! | [`plan`] | **pure** | the desired set, the ownership ledger, the diff, the console's wire format |
//! | [`run`] | impure | one process, with a deadline and a muzzle |
//! | [`macos`] | impure | `/usr/sbin/sharing` and `launchctl` |
//! | [`windows`] | impure | the `SmbShare` cmdlets and `icacls` |
//! | [`samba`] | impure | a generated include file and `smbcontrol` |
//! | [`unsupported`] | impure | the honest refusal |
//!
//! # The rules, and where they are enforced
//!
//! All three live in [`plan`], in the types rather than in the backends, so that
//! no backend can violate one by being written carelessly:
//!
//! - **Guest access is refused and is not configurable.** [`plan::DesiredShare`]
//!   has no guest field and no public constructor, so a backend cannot be asked
//!   for one. A share point this deployment owns that is found *with* guest
//!   access on is scheduled for repair.
//! - **Never touch a share point we did not create.** Removals are
//!   `Vec<SmbName>` drawn from [`plan::Owned`], the recorded set of names this
//!   deployment created. A share point read back from the host carries a plain
//!   `String`, and no method in this module accepts one.
//! - **Nothing reaches a command line unchecked.** Names are [`crate::share::SmbName`]
//!   and roots are refused unless absolute, UTF-8, and free of control
//!   characters. On Windows even that is not relied upon: every mutating step is
//!   a fixed script that reads its arguments from the environment, so no
//!   operator-supplied text is ever concatenated into a command.
//!
//! # Privilege, and what happens without it
//!
//! Every backend needs privilege to *change* anything and none needs it to
//! *read*. A reconcile that cannot get it returns [`SmbError::Denied`] naming
//! the privilege that platform wants; it never silently succeeds. An operation
//! that quietly no-ops when unprivileged is worse than one that refuses, because
//! the operator believes their share is up.
//!
//! | Platform | Reading | Changing |
//! |---|---|---|
//! | macOS | `sharing -l` — any user | `sharing -a/-e/-r` and `launchctl … system/` — **root** |
//! | Windows | `Get-SmbShare` — any user | `New-SmbShare`/`Remove-SmbShare`/`icacls` — **an elevated shell** (`SeSecurityPrivilege`, Administrators) |
//! | Linux | `testparm -s` — any user | writing `/etc/samba/selfhost.conf` and `smbcontrol` — **write access to the Samba config directory**, i.e. root |

pub mod macos;
pub mod plan;
pub mod run;
pub mod samba;
pub mod unsupported;
pub mod windows;

pub use macos::SharingBackend;
pub use plan::{
    desired_exports, diff, Action, Apply, BackendKind, Conflict, DesiredShare, LiveShare, Owned,
    Performed, PlanError, Reconciliation, ShareState, SmbState, Update, AUTHENTICATION_NOTICE,
    SMB_PORT,
};
pub use samba::SambaBackend;
pub use unsupported::UnsupportedBackend;
pub use windows::SmbShareBackend;

use crate::share::Shares;
use std::fmt;
use std::path::{Path, PathBuf};

/// Why the operating system's SMB exports could not be read or set.
///
/// An enum whose `Display` says what to do, in the idiom
/// [`selfhost_firewall::backend::FirewallError`](../../../selfhost_firewall/backend/enum.FirewallError.html)
/// established: reported and continued past rather than swallowed, because an
/// export that could not be set is worse unknown than known-unset.
#[derive(Debug)]
pub enum SmbError {
    /// No SMB driver for this operating system.
    Unsupported {
        /// The operating system, as `std::env::consts::OS` names it.
        platform: &'static str,
    },
    /// The tool is not installed or not on the daemon's `PATH`.
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
        /// What that platform actually wants — root, an elevated shell, write
        /// access to a directory. Named because the fix differs per platform and
        /// "run as administrator" is not advice a Linux operator can act on.
        privilege: &'static str,
    },
    /// The tool ran, succeeded, and printed something this crate could not read.
    ///
    /// Distinct from [`Self::Command`] on purpose: the tool is fine and the
    /// deployment is fine, but the output format changed under us, and reporting
    /// that as a command failure would send the operator looking in the wrong
    /// place.
    Unreadable {
        /// The program whose output could not be read.
        program: String,
        /// What was wrong with it.
        detail: String,
    },
    /// Samba is installed but the generated include file is not part of the live
    /// configuration, so writing it would change nothing.
    ///
    /// Reported rather than fixed: editing the operator's `smb.conf` is exactly
    /// the "touch something we did not create" this module refuses to do.
    IncludeMissing {
        /// The file this crate owns and writes.
        file: PathBuf,
    },
    /// A desired export could not be derived, or the ownership ledger is not
    /// trustworthy.
    Plan(PlanError),
    /// The tool started but could not be waited for, or a file could not be read
    /// or written.
    Io(std::io::Error),
}

impl fmt::Display for SmbError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported { platform } => write!(
                formatter,
                "no SMB driver for {platform}; remove the [shares.smb] blocks on this host, or \
                 export the directory with the platform's own tools"
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
            Self::Denied { program, privilege } => write!(
                formatter,
                "{program} needs {privilege}, which the daemon does not have; nothing was \
                 changed. Run the reconcile with {privilege}, or create the share point with \
                 the platform's own tools"
            ),
            Self::Unreadable { program, detail } => write!(
                formatter,
                "{program} succeeded but printed something this build cannot read: {detail}. \
                 The share table was not changed"
            ),
            Self::IncludeMissing { file } => write!(
                formatter,
                "{} is not included by the live Samba configuration, so writing it would \
                 change nothing. Add `include = {}` to the [global] section of smb.conf — \
                 this crate will not edit smb.conf itself",
                file.display(),
                file.display()
            ),
            Self::Plan(error) => write!(formatter, "{error}"),
            Self::Io(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for SmbError {}

impl From<PlanError> for SmbError {
    fn from(error: PlanError) -> Self {
        Self::Plan(error)
    }
}

/// One host's SMB exports, as this project drives them.
///
/// Every method is idempotent: [`reconcile`](SmbBackend::reconcile) applies the
/// difference between the live exports and a plan and is safe to call on every
/// daemon start. Errors are reported, never swallowed.
///
/// Native `async fn` in trait. The lint that warns this is not dyn-compatible is
/// allowed on purpose: the trait is never used through `dyn` — [`HostSmb`] holds
/// the concrete backend and delegates, the same choice `FirewallBackend` made.
///
/// **The trait is the second half of the safety argument.** Look at what it will
/// accept: [`DesiredShare`], which cannot describe a guest-accessible export,
/// and [`Reconciliation`], whose removals are [`crate::share::SmbName`]s drawn
/// from the ownership ledger. There is no method here that takes a name a
/// backend read off the host, which is why "never touch a share point we did not
/// create" holds for backends nobody has written yet.
#[allow(async_fn_in_trait)]
pub trait SmbBackend {
    /// Reads every share point the operating system currently exports.
    ///
    /// Total: it reports share points this deployment did not create, with names
    /// this crate could never have chosen, because a reading that omitted them
    /// would not be a reading of the host. What protects them is that nothing
    /// downstream can act on a name that is not in the ledger.
    async fn snapshot(&self) -> Result<Vec<LiveShare>, SmbError>;

    /// Whether the platform's SMB service is running.
    ///
    /// `None` means this backend cannot tell — which is not the same as "no",
    /// and the console renders the two differently.
    async fn service_running(&self) -> Result<Option<bool>, SmbError>;

    /// Starts the platform's SMB server, returning whether it is now running.
    ///
    /// **This is the call that makes the box answer on `445`.** Under
    /// [`Apply::DryRun`] it changes nothing and answers with the current state,
    /// so a caller can show "would start the SMB service" before doing it.
    async fn start_service(&self, apply: Apply) -> Result<bool, SmbError>;

    /// Performs a plan, returning one [`Performed`] per step attempted.
    ///
    /// Under [`Apply::DryRun`] nothing is run and every step comes back with
    /// `applied: false`, so the console renders one shape whichever mode was
    /// asked for.
    async fn reconcile(
        &self,
        plan: &Reconciliation,
        apply: Apply,
    ) -> Result<Vec<Performed>, SmbError>;
}

/// The SMB driver for this host, chosen at runtime.
pub enum HostSmb {
    /// macOS.
    Sharing(SharingBackend),
    /// Windows.
    SmbShare(SmbShareBackend),
    /// Linux.
    Samba(SambaBackend),
    /// Everything else.
    Unsupported(UnsupportedBackend),
}

impl HostSmb {
    /// Which driver this is, for display and the wire.
    pub fn kind(&self) -> BackendKind {
        match self {
            Self::Sharing(_) => BackendKind::Sharing,
            Self::SmbShare(_) => BackendKind::SmbShare,
            Self::Samba(_) => BackendKind::Samba,
            Self::Unsupported(_) => BackendKind::Unsupported,
        }
    }
}

impl SmbBackend for HostSmb {
    async fn snapshot(&self) -> Result<Vec<LiveShare>, SmbError> {
        match self {
            Self::Sharing(backend) => backend.snapshot().await,
            Self::SmbShare(backend) => backend.snapshot().await,
            Self::Samba(backend) => backend.snapshot().await,
            Self::Unsupported(backend) => backend.snapshot().await,
        }
    }

    async fn service_running(&self) -> Result<Option<bool>, SmbError> {
        match self {
            Self::Sharing(backend) => backend.service_running().await,
            Self::SmbShare(backend) => backend.service_running().await,
            Self::Samba(backend) => backend.service_running().await,
            Self::Unsupported(backend) => backend.service_running().await,
        }
    }

    async fn start_service(&self, apply: Apply) -> Result<bool, SmbError> {
        match self {
            Self::Sharing(backend) => backend.start_service(apply).await,
            Self::SmbShare(backend) => backend.start_service(apply).await,
            Self::Samba(backend) => backend.start_service(apply).await,
            Self::Unsupported(backend) => backend.start_service(apply).await,
        }
    }

    async fn reconcile(
        &self,
        plan: &Reconciliation,
        apply: Apply,
    ) -> Result<Vec<Performed>, SmbError> {
        match self {
            Self::Sharing(backend) => backend.reconcile(plan, apply).await,
            Self::SmbShare(backend) => backend.reconcile(plan, apply).await,
            Self::Samba(backend) => backend.reconcile(plan, apply).await,
            Self::Unsupported(backend) => backend.reconcile(plan, apply).await,
        }
    }
}

/// Picks the SMB driver that fits this operating system.
pub fn detect() -> HostSmb {
    #[cfg(target_os = "macos")]
    {
        HostSmb::Sharing(SharingBackend::new())
    }
    #[cfg(target_os = "linux")]
    {
        HostSmb::Samba(SambaBackend::new())
    }
    #[cfg(windows)]
    {
        HostSmb::SmbShare(SmbShareBackend::new())
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        HostSmb::Unsupported(UnsupportedBackend)
    }
}

/// The file recording which share points this deployment created.
///
/// The whole of "never touch a share point we did not create" rests on this
/// file, so it is worth being clear about what it is and is not. It is **not** a
/// security boundary — anyone who can write it can already write the daemon's
/// data directory. It is a *memory*: the answer to "did we make this?", which
/// the host itself cannot answer because a share point has nowhere to carry a
/// marker (macOS's `sharing` has no comment field, and prefixing the name would
/// change the name people see in Finder).
///
/// Both failure modes fall the safe way. A lost ledger means we forget we own a
/// share point and stop removing it, which is visible and fixable. A ledger that
/// names something we did not create can only have been written by hand, in
/// which case an operator wrote it deliberately.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipLedger {
    path: PathBuf,
}

/// The ledger's file name inside the data directory.
pub const OWNERSHIP_FILE: &str = "storage.smb-owned";

impl OwnershipLedger {
    /// The ledger for a deployment, inside its data directory.
    pub fn under(data_dir: impl AsRef<Path>) -> Self {
        Self { path: data_dir.as_ref().join(OWNERSHIP_FILE) }
    }

    /// The file this ledger lives in.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the ledger. A missing file is an empty ledger, not an error.
    ///
    /// A deployment that has never exported anything has no file, and demanding
    /// one would mean every fresh box started with an error the operator has to
    /// learn to ignore. A file that exists and cannot be *parsed* is a different
    /// matter and is refused — see [`Owned::parse`].
    pub async fn load(&self) -> Result<Owned, SmbError> {
        match tokio::fs::read_to_string(&self.path).await {
            Ok(text) => Owned::parse(&text).map_err(SmbError::Plan),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Owned::empty()),
            Err(error) => Err(SmbError::Io(error)),
        }
    }

    /// Writes the ledger, replacing it atomically.
    ///
    /// Written to a sibling temporary file and renamed, because a ledger
    /// truncated by a crash mid-write is a deployment that has forgotten which
    /// share points are its own — and the recovery from that is a human reading
    /// `sharing -l` and deciding. The rename is the same in-directory atomic
    /// replace the upload path uses.
    pub async fn save(&self, owned: &Owned) -> Result<(), SmbError> {
        let mut temporary = self.path.clone().into_os_string();
        temporary.push(".tmp");
        let temporary = PathBuf::from(temporary);
        tokio::fs::write(&temporary, owned.to_text()).await.map_err(SmbError::Io)?;
        restrict_to_owner(&temporary).await?;
        tokio::fs::rename(&temporary, &self.path).await.map_err(SmbError::Io)
    }
}

/// Narrows a freshly written file to the account the daemon runs as.
///
/// The ledger holds no secret — it is a list of share names the network is being
/// told about anyway — but it decides what a privileged reconcile will delete,
/// and a file that decides that should not be world-writable on a box whose
/// whole posture is default-deny. On platforms without POSIX modes this is a
/// no-op, and deliberately not an error.
async fn restrict_to_owner(path: &Path) -> Result<(), SmbError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .await
            .map_err(SmbError::Io)
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Everything one reconcile decided, did, and left alone.
#[derive(Debug, Clone)]
pub struct SyncReport {
    /// What the diff decided.
    pub plan: Reconciliation,
    /// What was attempted, and whether it happened. Every entry has
    /// `applied: false` on a dry run.
    pub performed: Vec<Performed>,
    /// The host's exports as they now stand, with ownership marked.
    pub state: SmbState,
    /// The ownership ledger after the run. Equal to the one before it on a dry
    /// run.
    pub owned: Owned,
}

/// Reads the host, decides, optionally acts, and records what was created.
///
/// The one call a route or a CLI subcommand should make, and it exists because
/// the ledger must be updated by whoever performs the plan. Leaving that to the
/// caller would make "never remove a share point we did not create" depend on
/// every call site remembering a step — which is the class of guarantee this
/// project puts in a function rather than in a comment.
///
/// Dry run is the default, matching every other plan-then-apply command here: pass [`Apply::Write`]
/// only when the operator has seen the plan and asked for it. A dry run writes
/// nothing at all — not the host, and not the ledger.
///
/// # Why the ledger is written twice
///
/// A real apply claims the names it is about to create **before** running the
/// backend ([`Owned::claiming`]), and writes the settled ledger again after. The
/// order matters for the one failure that would otherwise need a human: a
/// reconcile that creates two share points and dies after the first would, with a
/// single write at the end, leave this deployment having made a share point and
/// forgotten it — and the next run would see that name live, not owned, and
/// report its own work as a conflict it refuses to touch. Claiming first cannot
/// claim anybody else's share point, because `create` holds only names the host
/// was just observed not to have.
pub async fn sync(
    backend: &HostSmb,
    ledger: &OwnershipLedger,
    shares: &Shares,
    apply: Apply,
) -> Result<SyncReport, SmbError> {
    let desired = desired_exports(shares)?;
    let owned = ledger.load().await?;
    let live = backend.snapshot().await?;
    let plan = diff(&desired, &live, &owned);

    let claimed = if apply.writes() && plan.changes_the_host() {
        let claimed = owned.claiming(&plan);
        ledger.save(&claimed).await?;
        claimed
    } else {
        owned
    };

    let performed = backend.reconcile(&plan, apply).await?;
    let owned = claimed.after(&performed);
    if apply.writes() && owned != claimed {
        ledger.save(&owned).await?;
    }

    // Re-read rather than predict: the console shows what the host says, and the
    // one moment a prediction and the host disagree is the moment the operator
    // most needs the truth.
    let live = backend.snapshot().await?;
    let service_running = backend.service_running().await?;
    let state = SmbState::observed(backend.kind(), service_running, &live, &owned);

    Ok(SyncReport { plan, performed, state, owned })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::SmbName;

    #[test]
    fn detect_names_a_backend_and_kind_agrees_with_the_variant() {
        let host = detect();
        let expected = match host {
            HostSmb::Sharing(_) => BackendKind::Sharing,
            HostSmb::SmbShare(_) => BackendKind::SmbShare,
            HostSmb::Samba(_) => BackendKind::Samba,
            HostSmb::Unsupported(_) => BackendKind::Unsupported,
        };
        assert_eq!(host.kind(), expected);
    }

    #[test]
    fn errors_say_what_to_do_rather_than_only_what_broke() {
        let denied = SmbError::Denied { program: "sharing".into(), privilege: "root" };
        assert!(denied.to_string().contains("root"), "{denied}");
        assert!(denied.to_string().contains("nothing was changed"), "{denied}");

        let unsupported = SmbError::Unsupported { platform: "redox" };
        assert!(unsupported.to_string().contains("redox"), "{unsupported}");

        let missing = SmbError::IncludeMissing { file: PathBuf::from("/etc/samba/selfhost.conf") };
        assert!(missing.to_string().contains("include ="), "{missing}");
        assert!(missing.to_string().contains("will not edit smb.conf"), "{missing}");
    }

    #[tokio::test]
    async fn a_ledger_that_has_never_been_written_reads_as_owning_nothing() {
        let directory = std::env::temp_dir().join(format!("selfhost-smb-ledger-{}", std::process::id()));
        tokio::fs::create_dir_all(&directory).await.expect("a scratch directory");
        let ledger = OwnershipLedger::under(&directory);
        assert!(ledger.load().await.expect("a missing file is not an error").is_empty());
        tokio::fs::remove_dir_all(&directory).await.expect("cleanup");
    }

    #[tokio::test]
    async fn a_ledger_round_trips_through_the_disk() {
        let directory =
            std::env::temp_dir().join(format!("selfhost-smb-ledger-rt-{}", std::process::id()));
        tokio::fs::create_dir_all(&directory).await.expect("a scratch directory");
        let ledger = OwnershipLedger::under(&directory);

        let mut owned = Owned::empty();
        owned = owned.after(&[Performed {
            action: Action::Create,
            name: SmbName::parse("Vault").expect("legal"),
            applied: true,
        }]);
        ledger.save(&owned).await.expect("a writable scratch directory");
        assert_eq!(ledger.load().await.expect("what we just wrote"), owned);
        assert_eq!(ledger.path().file_name().and_then(|n| n.to_str()), Some(OWNERSHIP_FILE));

        tokio::fs::remove_dir_all(&directory).await.expect("cleanup");
    }
}
