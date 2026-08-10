//! Driving the Windows SMB server through the `SmbShare` cmdlets and `icacls`.
//!
//! Windows enforces **two** access lists on a share and a client must pass both:
//! the share-level list (`Grant-SmbShareAccess`, set at creation by
//! `New-SmbShare`'s `-FullAccess`/`-ReadAccess`) and the NTFS list on the
//! directory itself (`icacls`). A share created with only the first is visible in
//! Explorer and refuses every open; a directory given only the second is not
//! shared at all. Both are set here, which is why this backend runs two different
//! tools.
//!
//! # The default this backend exists to refuse
//!
//! `New-SmbShare` with **no** access parameter grants `Everyone: Read`. That is
//! the single most important fact in this file: the safe-looking command is the
//! unsafe one, and the guarantee "guest access is refused" is upheld here by
//! always passing an explicit principal, never by omitting the flag. The
//! principal is the built-in Administrators group, and it is named by its
//! well-known SID (`S-1-5-32-544`) translated at run time rather than by the
//! string `"Administrators"`, because that string is localised — on a German
//! install the group is `Administratoren` and a hard-coded English name would
//! make `New-SmbShare` fail, or worse, be dropped in favour of the default.
//!
//! **This crate never invents an operating-system account.** It cannot: it has
//! no way to create one, no way to set its password, and no business doing
//! either. Widening a share beyond Administrators is done with Windows' own
//! tools, and the console says so.
//!
//! # No operator string is ever concatenated into a script
//!
//! Every mutating step is a **fixed** PowerShell script — a `const &str` in this
//! file with no formatting applied — that reads its share name, directory and
//! flags from the *environment*. `Command::env` passes those to the child
//! process directly; they never pass through a shell, a quoting rule, or the
//! script text. So even though [`crate::share::SmbName`] already forbids the
//! characters that would end an argument, and [`crate::smb::DesiredShare`]
//! already forbids a root with a control character in it, there is additionally
//! no syntactic position for either value to escape from.
//!
//! # Why an update is a remove and a create
//!
//! `Set-SmbShare` cannot change `-Path`, and correcting an access list in place
//! means a sequence of `Revoke-SmbShareAccess`/`Grant-SmbShareAccess` calls whose
//! intermediate states are weaker than either end. Removing our own share point
//! and creating it again lands on exactly the state [`CREATE_SCRIPT`] produces —
//! the one that is tested to name a principal — instead of on a state assembled
//! by patches. It disconnects anyone connected at that moment, which is visible
//! and recoverable, unlike a share that quietly kept a stale grant.
//!
//! # What it needs, and what happens without it
//!
//! `Get-SmbShare` reads without privilege. `New-SmbShare`, `Remove-SmbShare`,
//! `icacls` and `Start-Service` all need an **elevated** shell — a daemon running
//! as an ordinary user gets *"Access is denied."* and this backend turns that
//! into [`SmbError::Denied`] naming the elevation. Nothing is skipped silently.

use crate::share::SmbName;
use crate::smb::plan::{Action, Apply, LiveShare, Performed, Reconciliation};
use crate::smb::run::{run, COMMAND_TIMEOUT};
use crate::smb::{DesiredShare, SmbBackend, SmbError};
use selfhost_json::Json;
use std::ffi::OsStr;

/// Windows PowerShell, which every supported Windows ships. `pwsh` is not
/// assumed: it is an optional install and its absence is not a fault.
pub const POWERSHELL: &str = "powershell.exe";

/// The NTFS access-list tool.
pub const ICACLS: &str = "icacls.exe";

/// The Windows service that answers SMB.
pub const SERVER_SERVICE: &str = "LanmanServer";

/// The privilege every mutating step needs.
const PRIVILEGE: &str = "an elevated shell (Administrators)";

/// The flags that keep PowerShell from reading a profile or asking a question.
///
/// A daemon's PowerShell must not load `$PROFILE` — it may sit on a network path
/// that is slow or gone — and must never prompt, because there is no terminal to
/// prompt at and the wait would be the deadline this module exists to bound.
const SHELL_FLAGS: [&str; 3] = ["-NoProfile", "-NonInteractive", "-Command"];

/// Environment variable carrying the share name into a script.
const NAME_VAR: &str = "SELFHOST_SMB_NAME";
/// Environment variable carrying the exported directory into a script.
const PATH_VAR: &str = "SELFHOST_SMB_PATH";
/// Environment variable carrying the encryption flag, as `0` or `1`.
const ENCRYPT_VAR: &str = "SELFHOST_SMB_ENCRYPT";
/// Environment variable carrying the read-only flag, as `0` or `1`.
const READ_ONLY_VAR: &str = "SELFHOST_SMB_READONLY";

/// The well-known SID of the built-in Administrators group.
///
/// Used rather than the name `"Administrators"` because the name is localised
/// and the SID is not.
pub const ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// The `icacls` inheritance flags: this directory, its subdirectories, and its
/// files.
const INHERIT: &str = "(OI)(CI)";

/// Reads the share table, and for each share whether it is open to anyone and
/// whether it is writable.
///
/// One invocation rather than one per share, because a file server with fifty
/// shares would otherwise mean fifty process spawns on every console refresh.
/// Guest exposure is decided by **SID**, not by account name, so it is found on a
/// localised install where the group is not called "Everyone".
pub const LIST_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
function Get-SidOf([string]$account) {
  try { (New-Object System.Security.Principal.NTAccount($account)).Translate([System.Security.Principal.SecurityIdentifier]).Value }
  catch { '' }
}
$open = @('S-1-1-0', 'S-1-5-7', 'S-1-5-32-546')
$rows = foreach ($share in @(Get-SmbShare)) {
  $allow = @(Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue | Where-Object { $_.AccessControlType -eq 'Allow' })
  $sids = @($allow | ForEach-Object { Get-SidOf $_.AccountName })
  [pscustomobject]@{
    Name = [string]$share.Name
    Path = [string]$share.Path
    Encrypted = [bool]$share.EncryptData
    Guest = [bool](@($sids | Where-Object { $open -contains $_ }).Count)
    Writable = [bool](@($allow | Where-Object { $_.AccessRight -eq 'Full' -or $_.AccessRight -eq 'Change' }).Count)
  }
}
@($rows) | ConvertTo-Json -Compress -Depth 3
"#;

/// Creates one share point, naming the principal explicitly.
///
/// The `-FullAccess`/`-ReadAccess` argument is not optional and is the whole
/// point: omitting it is what makes `New-SmbShare` grant `Everyone: Read`.
pub const CREATE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$name = $env:SELFHOST_SMB_NAME
$path = $env:SELFHOST_SMB_PATH
$encrypt = $env:SELFHOST_SMB_ENCRYPT -eq '1'
$admins = (New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value
if ($env:SELFHOST_SMB_READONLY -eq '1') {
  New-SmbShare -Name $name -Path $path -ReadAccess $admins -EncryptData:$encrypt | Out-Null
} else {
  New-SmbShare -Name $name -Path $path -FullAccess $admins -EncryptData:$encrypt | Out-Null
}
"#;

/// Removes one share point by name.
pub const REMOVE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
Remove-SmbShare -Name $env:SELFHOST_SMB_NAME -Force | Out-Null
"#;

/// Reports whether the SMB server service is running.
pub const SERVICE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
(Get-Service -Name 'LanmanServer').Status.ToString()
"#;

/// Starts the SMB server service.
pub const START_SERVICE_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
Start-Service -Name 'LanmanServer'
"#;

/// The Windows SMB server, driven through PowerShell and `icacls`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SmbShareBackend;

impl SmbShareBackend {
    /// The backend for this Windows host.
    pub fn new() -> Self {
        Self
    }
}

/// The command line for one PowerShell script.
fn shell_args(script: &str) -> Vec<String> {
    let mut args: Vec<String> = SHELL_FLAGS.iter().map(|flag| (*flag).to_owned()).collect();
    args.push(script.to_owned());
    args
}

/// The environment one share's script reads its values out of.
///
/// Returned as owned pairs so the borrow of the [`DesiredShare`] is explicit and
/// so a caller cannot accidentally build a command whose name and path came from
/// different shares.
fn script_env(share: &DesiredShare) -> Vec<(&'static str, std::ffi::OsString)> {
    vec![
        (NAME_VAR, OsStr::new(share.name().as_str()).to_owned()),
        (PATH_VAR, share.root().as_os_str().to_owned()),
        (ENCRYPT_VAR, OsStr::new(if share.encrypt() { "1" } else { "0" }).to_owned()),
        (READ_ONLY_VAR, OsStr::new(if share.read_only() { "1" } else { "0" }).to_owned()),
    ]
}

/// The environment a removal script reads its one value out of.
fn removal_env(name: &SmbName) -> Vec<(&'static str, std::ffi::OsString)> {
    vec![(NAME_VAR, OsStr::new(name.as_str()).to_owned())]
}

/// Borrows an owned environment list into the shape [`run`] takes.
fn borrow_env<'a>(env: &'a [(&'static str, std::ffi::OsString)]) -> Vec<(&'a str, &'a OsStr)> {
    env.iter().map(|(key, value)| (*key, value.as_os_str())).collect()
}

/// The `icacls` arguments that grant the Administrators group access to the
/// exported directory.
///
/// Grant only. This backend never writes a **deny** entry and never removes an
/// existing one: the directory is the operator's, it may already carry access
/// somebody depends on, and `icacls /remove` on the wrong entry is the kind of
/// mistake that is discovered weeks later. A read-only export is granted `RX`
/// (read and execute — execute is what lets a client traverse subdirectories, so
/// omitting it makes the share look empty below the top level); a writable one is
/// granted `F`.
///
/// The SID is passed in `icacls`'s `*S-1-…` form, which bypasses name resolution
/// and so works identically on a localised install and on one with no domain
/// controller reachable.
pub fn icacls_args(share: &DesiredShare) -> Vec<String> {
    let right = if share.read_only() { "RX" } else { "F" };
    vec![
        share.root_text().to_owned(),
        "/grant".to_owned(),
        format!("*{ADMINISTRATORS_SID}:{INHERIT}{right}"),
    ]
}

/// Reads the JSON emitted by [`LIST_SCRIPT`].
///
/// Accepts both shapes PowerShell produces: `ConvertTo-Json` renders a
/// single-element pipeline as one object rather than as an array of one, which is
/// a long-standing behaviour of Windows PowerShell 5.1 and not something a
/// caller can switch off. A host with exactly one share is therefore the case a
/// naive parser gets wrong, and it is the case tested below.
pub fn parse_listing(text: &str) -> Result<Vec<LiveShare>, SmbError> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let value = selfhost_json::parse(text).map_err(|error| SmbError::Unreadable {
        program: POWERSHELL.to_owned(),
        detail: error.to_string(),
    })?;
    let rows: Vec<&Json> = match &value {
        Json::Array(items) => items.iter().collect(),
        Json::Object(_) => vec![&value],
        Json::Null => Vec::new(),
        _ => {
            return Err(SmbError::Unreadable {
                program: POWERSHELL.to_owned(),
                detail: "expected an object or an array of share objects".to_owned(),
            })
        }
    };

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let name = row.get("Name")?.as_str()?.to_owned();
            Some(LiveShare {
                name,
                // Windows has one name per share point, so there is nothing for
                // an alias to hold.
                aliases: Vec::new(),
                path: row.get("Path").and_then(Json::as_str).unwrap_or_default().to_owned(),
                guest_access: row.get("Guest").and_then(Json::as_bool).unwrap_or(false),
                read_only: !row.get("Writable").and_then(Json::as_bool).unwrap_or(false),
                encrypted: row.get("Encrypted").and_then(Json::as_bool).unwrap_or(false),
                // A share point that exists on Windows is exported; there is no
                // separate "declared but not shared" state as there is on macOS.
                shared: true,
            })
        })
        .collect())
}

impl SmbShareBackend {
    /// Creates one share point and sets the NTFS access list behind it.
    ///
    /// Both, in that order, because a share without the NTFS grant is visible
    /// and unusable — the failure that looks like a bug in this project and is
    /// really a missing second access list.
    async fn create(&self, share: &DesiredShare) -> Result<(), SmbError> {
        let env = script_env(share);
        run(POWERSHELL, &shell_args(CREATE_SCRIPT), &borrow_env(&env), COMMAND_TIMEOUT)
            .await?
            .ok_or_error(POWERSHELL, PRIVILEGE)?;
        run(ICACLS, &icacls_args(share), &[], COMMAND_TIMEOUT)
            .await?
            .ok_or_error(ICACLS, PRIVILEGE)?;
        Ok(())
    }

    /// Removes one share point.
    async fn remove(&self, name: &SmbName) -> Result<(), SmbError> {
        let env = removal_env(name);
        run(POWERSHELL, &shell_args(REMOVE_SCRIPT), &borrow_env(&env), COMMAND_TIMEOUT)
            .await?
            .ok_or_error(POWERSHELL, PRIVILEGE)?;
        Ok(())
    }
}

impl SmbBackend for SmbShareBackend {
    async fn snapshot(&self) -> Result<Vec<LiveShare>, SmbError> {
        let ran = run(POWERSHELL, &shell_args(LIST_SCRIPT), &[], COMMAND_TIMEOUT).await?;
        let ran = ran.ok_or_error(POWERSHELL, PRIVILEGE)?;
        parse_listing(&ran.stdout)
    }

    async fn service_running(&self) -> Result<Option<bool>, SmbError> {
        let ran = run(POWERSHELL, &shell_args(SERVICE_SCRIPT), &[], COMMAND_TIMEOUT).await?;
        if !ran.succeeded() {
            return Ok(None);
        }
        Ok(Some(ran.stdout.trim().eq_ignore_ascii_case("Running")))
    }

    async fn start_service(&self, apply: Apply) -> Result<bool, SmbError> {
        let already = self.service_running().await?.unwrap_or(false);
        if already || !apply.writes() {
            return Ok(already);
        }
        run(POWERSHELL, &shell_args(START_SERVICE_SCRIPT), &[], COMMAND_TIMEOUT)
            .await?
            .ok_or_error(POWERSHELL, PRIVILEGE)?;
        Ok(self.service_running().await?.unwrap_or(false))
    }

    async fn reconcile(
        &self,
        plan: &Reconciliation,
        apply: Apply,
    ) -> Result<Vec<Performed>, SmbError> {
        let mut performed = Vec::new();

        for name in &plan.remove {
            if apply.writes() {
                self.remove(name).await?;
            }
            performed.push(Performed {
                action: Action::Remove,
                name: name.clone(),
                applied: apply.writes(),
            });
        }

        // An update is a removal and a creation, always: see the module
        // documentation for why patching an access list in place is worse.
        for update in &plan.update {
            if apply.writes() {
                self.remove(update.desired.name()).await?;
                self.create(&update.desired).await?;
            }
            performed.push(Performed {
                action: Action::Update,
                name: update.desired.name().clone(),
                applied: apply.writes(),
            });
        }

        for share in &plan.create {
            if apply.writes() {
                self.create(share).await?;
            }
            performed.push(Performed {
                action: Action::Create,
                name: share.name().clone(),
                applied: apply.writes(),
            });
        }

        for name in &plan.forget {
            performed.push(Performed {
                action: Action::Forget,
                name: name.clone(),
                applied: apply.writes(),
            });
        }

        Ok(performed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{Reserved, Share, SmbExport, Shares};
    use crate::smb::plan::{desired_exports, diff, Owned};
    use std::path::PathBuf;

    /// Builds one export. The paths are unix-shaped even though this backend is
    /// the Windows one, because `Share::new` asks the *running* platform whether
    /// a root is absolute and these tests must pass on the machine this project
    /// is developed on. What is being asserted here is the shape of a command
    /// line, which does not depend on the spelling of the path.
    fn export(name: &str, root: &str, encrypt: bool, read_only: bool) -> DesiredShare {
        let reserved = Reserved::new(PathBuf::from("/selfhost/data"), None).expect("legal");
        let share = Share::new(&reserved, "vault", PathBuf::from(root), false, false, None)
            .expect("a legal share")
            .with_smb(SmbExport {
                name: SmbName::parse(name).expect("a legal share name"),
                encrypt,
                read_only,
            });
        let shares = Shares::new(vec![share]).expect("a legal set");
        desired_exports(&shares).expect("no refusal").pop().expect("one export")
    }

    #[test]
    fn no_script_in_this_file_interpolates_anything() {
        // The property that makes the Windows path injection-proof by
        // construction: every script is a constant, so there is no syntactic
        // position an operator-supplied string could occupy.
        for script in [LIST_SCRIPT, CREATE_SCRIPT, REMOVE_SCRIPT, SERVICE_SCRIPT, START_SERVICE_SCRIPT]
        {
            assert!(!script.contains("{}"), "a format placeholder means a built string: {script}");
        }
        let share = export("Vault", "/Shares/Vault", true, false);
        let env = script_env(&share);
        assert!(!CREATE_SCRIPT.contains("Vault"), "the name travels in the environment, not the text");
        assert_eq!(env[0].1, OsStr::new("Vault"));
        assert_eq!(env[1].1, PathBuf::from("/Shares/Vault").as_os_str());
    }

    #[test]
    fn creation_always_names_a_principal_because_omitting_one_grants_everyone() {
        // The single most important assertion in this file. `New-SmbShare` with
        // no access parameter grants `Everyone: Read`; both branches of the
        // script must therefore carry one.
        assert!(CREATE_SCRIPT.contains("-ReadAccess $admins"), "{CREATE_SCRIPT}");
        assert!(CREATE_SCRIPT.contains("-FullAccess $admins"), "{CREATE_SCRIPT}");
        assert_eq!(
            CREATE_SCRIPT.matches("New-SmbShare").count(),
            CREATE_SCRIPT.matches("Access $admins").count(),
            "every New-SmbShare must carry an explicit principal"
        );
        assert!(!CREATE_SCRIPT.contains("Everyone"), "the principal is never Everyone");
    }

    #[test]
    fn the_principal_is_a_sid_rather_than_a_localised_group_name() {
        assert!(CREATE_SCRIPT.contains(ADMINISTRATORS_SID), "{CREATE_SCRIPT}");
        assert!(!CREATE_SCRIPT.contains("'Administrators'"), "a localised name would fail abroad");
    }

    #[test]
    fn guest_exposure_is_detected_by_sid_so_a_localised_install_is_not_missed() {
        for sid in ["S-1-1-0", "S-1-5-7", "S-1-5-32-546"] {
            assert!(LIST_SCRIPT.contains(sid), "{sid} missing from the reading script");
        }
    }

    #[test]
    fn the_ntfs_grant_is_a_grant_and_inherits_into_the_tree() {
        let writable = icacls_args(&export("Vault", "/Shares/Vault", true, false));
        assert_eq!(writable[0], "/Shares/Vault");
        assert_eq!(writable[1], "/grant");
        assert_eq!(writable[2], format!("*{ADMINISTRATORS_SID}:(OI)(CI)F"));

        let read_only = icacls_args(&export("Vault", "/Shares/Vault", true, true));
        assert_eq!(read_only[2], format!("*{ADMINISTRATORS_SID}:(OI)(CI)RX"));

        for args in [&writable, &read_only] {
            assert!(!args.iter().any(|arg| arg.contains("/deny")), "no deny entries, ever");
            assert!(!args.iter().any(|arg| arg.contains("/remove")), "no removals, ever");
        }
    }

    #[test]
    fn a_single_share_arrives_as_one_object_and_is_still_a_list() {
        // Windows PowerShell 5.1 renders a one-element pipeline as an object,
        // not an array of one. A parser that only handles the array shape
        // reports a one-share host as empty and then plans to create a share
        // that already exists.
        let one = r#"{"Name":"Vault","Path":"D:\\Shares\\Vault","Encrypted":true,"Guest":false,"Writable":true}"#;
        let live = parse_listing(one).expect("valid");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].name, "Vault");
        assert_eq!(live[0].path, "D:\\Shares\\Vault");
        assert!(live[0].encrypted);
        assert!(!live[0].read_only, "Writable true means not read-only");
        assert!(live[0].shared);
    }

    #[test]
    fn several_shares_arrive_as_an_array() {
        let many = r#"[{"Name":"Vault","Path":"D:\\V","Guest":false,"Writable":false},
                       {"Name":"IPC$","Path":"","Guest":true,"Writable":false}]"#;
        let live = parse_listing(many).expect("valid");
        assert_eq!(live.len(), 2);
        assert!(live[0].read_only, "no write right means read-only");
        assert!(live[1].guest_access);
    }

    #[test]
    fn the_administrative_shares_are_reported_and_can_never_be_removed() {
        // `IPC$`, `C$` and `ADMIN$` are Windows' own. They appear in the reading,
        // they land in `untouched`, and `$` is not in SmbName's character set —
        // so no plan can ever name one in a removal.
        let many = r#"[{"Name":"C$","Path":"C:\\","Guest":false,"Writable":true},
                       {"Name":"ADMIN$","Path":"C:\\Windows","Guest":false,"Writable":true}]"#;
        let live = parse_listing(many).expect("valid");
        let plan = diff(&[], &live, &Owned::empty());
        assert_eq!(plan.untouched.len(), 2);
        assert!(plan.remove.is_empty());
        for share in &live {
            assert!(SmbName::parse(&share.name).is_err(), "{} must not be nameable", share.name);
        }
    }

    #[test]
    fn output_that_is_not_json_is_unreadable_rather_than_a_command_failure() {
        let error = parse_listing("Get-SmbShare : The term is not recognized")
            .expect_err("not json");
        assert!(matches!(error, SmbError::Unreadable { .. }), "{error}");
    }

    #[test]
    fn an_empty_share_table_reads_as_no_shares() {
        assert!(parse_listing("[]").expect("valid").is_empty());
        assert!(parse_listing("null").expect("valid").is_empty());
        assert!(parse_listing("").expect("no output").is_empty());
    }

    #[test]
    fn the_shell_is_told_not_to_load_a_profile_or_ask_a_question() {
        let args = shell_args(LIST_SCRIPT);
        assert_eq!(&args[..3], &["-NoProfile", "-NonInteractive", "-Command"]);
        assert_eq!(args.len(), 4, "the script is one argument, never several");
    }

    #[tokio::test]
    async fn a_dry_run_runs_nothing_even_on_a_host_with_no_powershell() {
        // The dry run must be safe to call anywhere: it is what the console shows
        // before the operator commits, including from a Mac reviewing a Windows
        // peer's plan.
        let plan = diff(&[export("Vault", "/Shares/Vault", true, false)], &[], &Owned::empty());
        let performed = SmbShareBackend::new()
            .reconcile(&plan, Apply::DryRun)
            .await
            .expect("a dry run spawns no process");
        assert_eq!(performed.len(), 1);
        assert!(!performed[0].applied);
    }
}
