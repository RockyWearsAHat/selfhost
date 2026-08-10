//! Driving macOS File Sharing through `/usr/sbin/sharing` and `launchctl`.
//!
//! macOS keeps its SMB exports as *share points* in the local directory service,
//! and `sharing` is the supported command-line front end to them — the same
//! records the Sharing pane of System Settings writes. Every flag used here was
//! read off this host's own `sharing` usage output rather than guessed:
//!
//! ```text
//! sharing -a <path> -S <name> -n <name> -s 001 -g 000 -R <0|1> -E <0|1>
//! sharing -e <name> -S <name>           -s 001 -g 000 -R <0|1> -E <0|1>
//! sharing -r <name>
//! sharing -l -f json
//! ```
//!
//! `-s`, `-g` and `-i` take a three-digit mask over *AFP, FTP, SMB* in that
//! order, and the first two protocols are no longer supported by the operating
//! system — so `-s 001` means "share over SMB and nothing else" and **`-g 000`
//! means guest access off for every protocol**. That second constant is the one
//! that matters: it is written here as a literal, it is never derived from
//! configuration, and [`create_args`] and [`edit_args`] are asserted to contain
//! it. There is no code path in this backend that emits any other guest mask.
//!
//! # What it needs, and what happens without it
//!
//! Reading needs nothing: `sharing -l -f json` runs as any user, which is how
//! [`SharingBackend::snapshot`] can populate the console on an unprivileged
//! daemon. Changing anything needs **root** — this host answers
//! `sharing: must be run as root` — and that string is what
//! `crate::smb::run`'s denial table turns into [`SmbError::Denied`]. Nothing is
//! attempted and nothing is silently skipped.
//!
//! # Why an update is sometimes a remove and a create
//!
//! `sharing -e` edits a share point's flags but cannot move it: the path is
//! fixed at `-a` time. So when [`Update::path_moved`] is true this backend
//! removes the share point and creates it again, which is visible to a connected
//! client as a disconnect rather than as a silent redirection to a different
//! directory — the honest of the two.
//!
//! # The service
//!
//! `smbd` is a launchd system daemon that ships disabled on a Mac that has never
//! shared a folder. `launchctl print system/com.apple.smbd` answers without
//! privilege and is how [`SharingBackend::service_running`] tells whether it is
//! loaded at all; enabling and bootstrapping it needs root, and it is what makes
//! the machine answer on [`crate::smb::SMB_PORT`].

use crate::share::SmbName;
use crate::smb::plan::{Action, Apply, LiveShare, Performed, Reconciliation, Update};
use crate::smb::run::{run, Ran, COMMAND_TIMEOUT};
use crate::smb::{DesiredShare, SmbBackend, SmbError};
use selfhost_json::Json;

/// The share-point tool, by absolute path.
///
/// Absolute rather than `"sharing"` on `PATH`, because this runs in a daemon
/// whose `PATH` is whatever launchd handed it, and there is exactly one correct
/// binary.
pub const SHARING: &str = "/usr/sbin/sharing";

/// The launchd control tool.
pub const LAUNCHCTL: &str = "/bin/launchctl";

/// The launchd label of the SMB server.
pub const SMBD_SERVICE: &str = "system/com.apple.smbd";

/// The property list launchd bootstraps `smbd` from.
pub const SMBD_PLIST: &str = "/System/Library/LaunchDaemons/com.apple.smbd.plist";

/// The privilege every mutating `sharing` and `launchctl` call needs.
const PRIVILEGE: &str = "root";

/// The protocol mask meaning "share over SMB, and over nothing else".
///
/// The digits are AFP, FTP, SMB; the first two are no longer supported by the
/// operating system, and enabling them would be asking for a protocol nobody has
/// a client for.
const SHARE_SMB_ONLY: &str = "001";

/// The guest mask meaning "no guest access over any protocol".
///
/// A literal, never a variable. See the module documentation: this is one of the
/// two rules the whole SMB module exists to hold.
const GUEST_NONE: &str = "000";

/// macOS File Sharing, driven through `sharing`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SharingBackend;

impl SharingBackend {
    /// The backend for this Mac.
    pub fn new() -> Self {
        Self
    }
}

/// The `sharing` flag for a boolean, in the `0`/`1` spelling it wants.
fn flag(value: bool) -> &'static str {
    if value {
        "1"
    } else {
        "0"
    }
}

/// The arguments that create a share point for one export.
///
/// Pure, so the shape of the command is asserted rather than observed. `-S` and
/// `-n` are given the same name deliberately: macOS lets a share point's record
/// name and its SMB name differ, and keeping ours equal means the name in the
/// ledger, the name in Finder, and the name `sharing -r` takes are one name.
pub fn create_args(share: &DesiredShare) -> Vec<String> {
    vec![
        "-a".into(),
        share.root_text().into(),
        "-S".into(),
        share.name().as_str().into(),
        "-n".into(),
        share.name().as_str().into(),
        "-s".into(),
        SHARE_SMB_ONLY.into(),
        "-g".into(),
        GUEST_NONE.into(),
        "-R".into(),
        flag(share.read_only()).into(),
        "-E".into(),
        flag(share.encrypt()).into(),
    ]
}

/// The arguments that correct an existing share point's flags.
///
/// Cannot move it — `sharing -e` has no path argument — which is why
/// [`Update::path_moved`] exists and why this backend removes and recreates
/// instead when it is true.
pub fn edit_args(share: &DesiredShare) -> Vec<String> {
    vec![
        "-e".into(),
        share.name().as_str().into(),
        "-S".into(),
        share.name().as_str().into(),
        "-s".into(),
        SHARE_SMB_ONLY.into(),
        "-g".into(),
        GUEST_NONE.into(),
        "-R".into(),
        flag(share.read_only()).into(),
        "-E".into(),
        flag(share.encrypt()).into(),
    ]
}

/// The arguments that remove a share point.
///
/// Takes an [`SmbName`] and nothing else can be passed, which is the type-level
/// half of "never remove a share point we did not create": the only `SmbName`s
/// in a plan came from configuration or from the ownership ledger.
pub fn remove_args(name: &SmbName) -> Vec<String> {
    vec!["-r".into(), name.as_str().into()]
}

/// Reads `sharing -l -f json` into the module's own model.
///
/// The output is a JSON **object keyed by record name**, each value carrying
/// `path`, `smb_name`, and the `smb_*` flags as `0`/`1` numbers. Verified against
/// this host, whose one share point reads:
///
/// ```json
/// { "Alex Waldmann’s Public Folder": { "path": "/Users/alexwaldmann/Public",
///   "smb_guest_access": 1, "smb_name": "Alex Waldmann’s Public Folder",
///   "smb_read_only": 0, "smb_sealed": 0, "smb_shared": 1 } }
/// ```
///
/// Note the typographic apostrophe: a live share point's name is whatever the
/// operator typed, which is why [`LiveShare::name`] is a `String` and not an
/// [`SmbName`]. A record whose value is not an object is skipped rather than
/// failing the whole read, because one unreadable entry must not blind the
/// console to the rest of the table — but a body that is not JSON at all is
/// [`SmbError::Unreadable`], since that means the tool's output format changed
/// and every conclusion drawn from it would be wrong.
pub fn parse_listing(text: &str) -> Result<Vec<LiveShare>, SmbError> {
    if text.trim().is_empty() {
        return Ok(Vec::new());
    }
    let value = selfhost_json::parse(text).map_err(|error| SmbError::Unreadable {
        program: SHARING.to_owned(),
        detail: error.to_string(),
    })?;
    let Json::Object(points) = value else {
        return Err(SmbError::Unreadable {
            program: SHARING.to_owned(),
            detail: "expected an object of share points".to_owned(),
        });
    };

    Ok(points
        .iter()
        .filter(|(_, body)| matches!(body, Json::Object(_)))
        .map(|(record_name, body)| {
            let smb_name = body.get("smb_name").and_then(Json::as_str).unwrap_or(record_name);
            LiveShare {
                name: record_name.clone(),
                aliases: if smb_name == record_name {
                    Vec::new()
                } else {
                    vec![smb_name.to_owned()]
                },
                path: body.get("path").and_then(Json::as_str).unwrap_or_default().to_owned(),
                guest_access: truthy(body, "smb_guest_access"),
                read_only: truthy(body, "smb_read_only"),
                encrypted: truthy(body, "smb_sealed"),
                shared: truthy(body, "smb_shared"),
            }
        })
        .collect())
}

/// Reads one of `sharing`'s `0`/`1` flags.
///
/// Accepts a JSON boolean as well as a number, because a flag absent from the
/// output means "off" and a future release spelling it `true` should not make
/// this backend report a guest-accessible share point as private.
fn truthy(body: &Json, key: &str) -> bool {
    match body.get(key) {
        Some(Json::Bool(value)) => *value,
        Some(Json::Number(value)) => *value != 0.0,
        _ => false,
    }
}

/// Whether `launchctl print` found the service in the system domain.
///
/// `launchctl print system/com.apple.smbd` answers without privilege and exits
/// non-zero with *"Could not find service … in domain for system"* on a Mac that
/// has never shared a folder — verified on this host. It reports whether the job
/// is **loaded**, which is the strongest thing launchd will say to an
/// unprivileged caller; a loaded job that has not yet been triggered still counts
/// as the service being available, which is exactly what a client connecting to
/// port 445 will find.
fn service_is_loaded(ran: &Ran) -> bool {
    ran.succeeded()
}

impl SmbBackend for SharingBackend {
    async fn snapshot(&self) -> Result<Vec<LiveShare>, SmbError> {
        let ran = run(SHARING, &["-l", "-f", "json"], &[], COMMAND_TIMEOUT).await?;
        let ran = ran.ok_or_error(SHARING, PRIVILEGE)?;
        parse_listing(&ran.stdout)
    }

    async fn service_running(&self) -> Result<Option<bool>, SmbError> {
        let ran = run(LAUNCHCTL, &["print", SMBD_SERVICE], &[], COMMAND_TIMEOUT).await?;
        Ok(Some(service_is_loaded(&ran)))
    }

    async fn start_service(&self, apply: Apply) -> Result<bool, SmbError> {
        let already = self.service_running().await?.unwrap_or(false);
        if already || !apply.writes() {
            return Ok(already);
        }
        // `enable` clears the persistent disable flag a never-shared Mac ships
        // with; `bootstrap` then loads the job. Both need root, and both are run
        // rather than one, because either alone leaves the service down.
        run(LAUNCHCTL, &["enable", SMBD_SERVICE], &[], COMMAND_TIMEOUT)
            .await?
            .ok_or_error(LAUNCHCTL, PRIVILEGE)?;
        run(LAUNCHCTL, &["bootstrap", "system", SMBD_PLIST], &[], COMMAND_TIMEOUT)
            .await?
            .ok_or_error(LAUNCHCTL, PRIVILEGE)?;
        Ok(self.service_running().await?.unwrap_or(false))
    }

    async fn reconcile(
        &self,
        plan: &Reconciliation,
        apply: Apply,
    ) -> Result<Vec<Performed>, SmbError> {
        let mut performed = Vec::new();

        // Removals first, so a name being withdrawn cannot collide with a name
        // being created in the same run.
        for name in &plan.remove {
            if apply.writes() {
                run(SHARING, &remove_args(name), &[], COMMAND_TIMEOUT)
                    .await?
                    .ok_or_error(SHARING, PRIVILEGE)?;
            }
            performed.push(Performed {
                action: Action::Remove,
                name: name.clone(),
                applied: apply.writes(),
            });
        }

        for update in &plan.update {
            if apply.writes() {
                self.correct(update).await?;
            }
            performed.push(Performed {
                action: Action::Update,
                name: update.desired.name().clone(),
                applied: apply.writes(),
            });
        }

        for share in &plan.create {
            if apply.writes() {
                run(SHARING, &create_args(share), &[], COMMAND_TIMEOUT)
                    .await?
                    .ok_or_error(SHARING, PRIVILEGE)?;
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

impl SharingBackend {
    /// Brings one share point back in line, moving it if the root changed.
    async fn correct(&self, update: &Update) -> Result<(), SmbError> {
        if update.path_moved() {
            run(SHARING, &remove_args(update.desired.name()), &[], COMMAND_TIMEOUT)
                .await?
                .ok_or_error(SHARING, PRIVILEGE)?;
            run(SHARING, &create_args(&update.desired), &[], COMMAND_TIMEOUT)
                .await?
                .ok_or_error(SHARING, PRIVILEGE)?;
        } else {
            run(SHARING, &edit_args(&update.desired), &[], COMMAND_TIMEOUT)
                .await?
                .ok_or_error(SHARING, PRIVILEGE)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{Reserved, Share, SmbExport, Shares};
    use crate::smb::plan::{desired_exports, diff, Owned};
    use std::path::PathBuf;

    /// This host's real `sharing -l -f json`, captured verbatim.
    const THIS_HOST: &str = r#"{
  "Alex Waldmann’s Public Folder" : {
    "path" : "/Users/alexwaldmann/Public",
    "smb_guest_access" : 1,
    "smb_name" : "Alex Waldmann’s Public Folder",
    "smb_read_only" : 0,
    "smb_sealed" : 0,
    "smb_shared" : 1
  }
}"#;

    fn export(name: &str, root: &str, encrypt: bool, read_only: bool) -> DesiredShare {
        let reserved = Reserved::new(PathBuf::from("/var/selfhost/data"), None).expect("legal");
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
    fn this_hosts_own_listing_parses_and_reports_its_guest_access_honestly() {
        let live = parse_listing(THIS_HOST).expect("this host's own output");
        assert_eq!(live.len(), 1);
        assert_eq!(live[0].name, "Alex Waldmann\u{2019}s Public Folder");
        assert_eq!(live[0].path, "/Users/alexwaldmann/Public");
        assert!(live[0].guest_access, "the box really does export this to guests");
        assert!(!live[0].read_only);
        assert!(!live[0].encrypted);
        assert!(live[0].shared);
        assert!(live[0].aliases.is_empty(), "record name and smb name agree here");
    }

    #[test]
    fn a_live_name_this_crate_could_never_choose_still_reads() {
        // The typographic apostrophe is not in SmbName's character set. Reading
        // must still work; acting on it must still be impossible.
        let live = parse_listing(THIS_HOST).expect("valid");
        assert!(SmbName::parse(&live[0].name).is_err(), "and so it can never be removed");
    }

    #[test]
    fn a_share_point_whose_smb_name_differs_keeps_the_other_name_as_an_alias() {
        let text = r#"{"public-folder":{"path":"/tmp/p","smb_name":"Public","smb_shared":1}}"#;
        let live = parse_listing(text).expect("valid");
        assert_eq!(live[0].name, "public-folder");
        assert_eq!(live[0].aliases, vec!["Public".to_owned()]);
        assert!(live[0].answers_to("Public"), "conflict detection must see both");
    }

    #[test]
    fn an_empty_table_is_an_empty_list_rather_than_an_error() {
        assert!(parse_listing("{}").expect("valid").is_empty());
        assert!(parse_listing("   ").expect("no output at all").is_empty());
    }

    #[test]
    fn output_that_is_not_json_is_unreadable_rather_than_a_command_failure() {
        let error = parse_listing("usage: sharing -a <path>").expect_err("not json");
        assert!(matches!(error, SmbError::Unreadable { .. }), "{error}");
    }

    #[test]
    fn a_creation_always_turns_guest_access_off_and_shares_only_over_smb() {
        let args = create_args(&export("Vault", "/srv/vault", true, false));
        let pair = |flag: &str| {
            args.windows(2).find(|window| window[0] == flag).map(|window| window[1].clone())
        };
        assert_eq!(pair("-g").as_deref(), Some(GUEST_NONE), "{args:?}");
        assert_eq!(pair("-s").as_deref(), Some(SHARE_SMB_ONLY), "{args:?}");
        assert_eq!(args.first().map(String::as_str), Some("-a"));
        assert_eq!(args.get(1).map(String::as_str), Some("/srv/vault"));
        assert_eq!(pair("-S").as_deref(), Some("Vault"));
        assert_eq!(pair("-n").as_deref(), Some("Vault"), "record and SMB name are kept equal");
        assert_eq!(pair("-E").as_deref(), Some("1"), "encryption was asked for");
        assert_eq!(pair("-R").as_deref(), Some("0"));
    }

    #[test]
    fn an_edit_also_always_turns_guest_access_off() {
        // The repair path must be as strict as the creation path: an owned share
        // point found with guest access on is corrected, not merely re-flagged.
        let args = edit_args(&export("Vault", "/srv/vault", false, true));
        assert!(args.windows(2).any(|w| w[0] == "-g" && w[1] == GUEST_NONE), "{args:?}");
        assert!(args.windows(2).any(|w| w[0] == "-R" && w[1] == "1"), "{args:?}");
        assert!(args.windows(2).any(|w| w[0] == "-E" && w[1] == "0"), "{args:?}");
    }

    #[test]
    fn no_argument_builder_can_ever_emit_a_guest_mask_that_is_not_zero() {
        // Exhaustive over the four flag combinations, because the guest mask is
        // the one constant nothing in configuration may reach.
        for encrypt in [false, true] {
            for read_only in [false, true] {
                let share = export("Vault", "/srv/vault", encrypt, read_only);
                for args in [create_args(&share), edit_args(&share)] {
                    let masks: Vec<&String> = args
                        .windows(2)
                        .filter(|window| window[0] == "-g")
                        .map(|window| &window[1])
                        .collect();
                    assert_eq!(masks, vec![&GUEST_NONE.to_owned()], "{args:?}");
                }
            }
        }
    }

    #[test]
    fn a_removal_names_exactly_one_share_point_and_takes_a_checked_name() {
        let name = SmbName::parse("Vault").expect("legal");
        assert_eq!(remove_args(&name), vec!["-r".to_owned(), "Vault".to_owned()]);
    }

    #[tokio::test]
    async fn a_dry_run_against_this_host_plans_without_touching_the_public_folder() {
        // The acceptance test, end to end through the backend rather than only
        // through the diff: the live table is this Mac's real one, and the plan
        // that comes out removes nothing and reports the public folder as
        // somebody else's.
        let live = parse_listing(THIS_HOST).expect("this host's own output");
        let desired = vec![export("Vault", "/srv/vault", true, false)];
        let plan = diff(&desired, &live, &Owned::empty());

        let performed = SharingBackend::new()
            .reconcile(&plan, Apply::DryRun)
            .await
            .expect("a dry run runs nothing and so cannot fail");
        assert!(performed.iter().all(|step| !step.applied), "{performed:?}");
        assert_eq!(performed.len(), 1, "one creation planned: {performed:?}");
        assert_eq!(performed[0].action, Action::Create);
        assert_eq!(plan.untouched, vec!["Alex Waldmann\u{2019}s Public Folder".to_owned()]);
        assert!(plan.remove.is_empty());
    }

    #[tokio::test]
    async fn the_listing_this_host_actually_prints_is_the_one_this_backend_reads() {
        // Runs the real tool. Read-only — `sharing -l` needs no privilege — and
        // it is the only way to notice the day macOS changes the format out from
        // under this backend. A host without `sharing` is not a failure.
        match SharingBackend::new().snapshot().await {
            Ok(live) => {
                for share in &live {
                    assert!(!share.name.is_empty(), "a share point with no name: {share:?}");
                }
            }
            Err(SmbError::ToolMissing { .. }) => {}
            Err(other) => panic!("sharing -l should not fail on a Mac: {other}"),
        }
    }
}
