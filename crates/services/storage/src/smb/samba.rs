//! Driving Samba through a generated include file.
//!
//! Samba's configuration is one file that an operator has usually already
//! written, holding a `[global]` section they tuned and share stanzas their
//! colleagues depend on. This backend **never edits it**. It writes a file of its
//! own — [`INCLUDE_FILE`], containing nothing but the stanzas this deployment
//! declares — and asks the operator, once, to pull that file in with a single
//! `include =` line.
//!
//! That is not a stylistic preference: it is how "never touch a share point we
//! did not create" is made structural on this platform. On macOS and Windows the
//! guarantee rests on the ownership ledger, because the share table is one shared
//! namespace those tools edit in place. Here it rests on a **file boundary**. The
//! backend regenerates the whole of its own file on every reconcile, so a removal
//! is a stanza that is no longer emitted rather than a delete issued against
//! somebody else's configuration — and there is no code in this file that opens
//! `smb.conf` for writing at all.
//!
//! # The one thing the operator has to do
//!
//! Add this to the `[global]` section of `smb.conf`:
//!
//! ```text
//! include = /etc/samba/selfhost.conf
//! ```
//!
//! Until then, writing [`INCLUDE_FILE`] changes nothing on the running server,
//! and a reconcile that appeared to succeed would be a lie. So the backend checks
//! for the line before it writes and reports [`SmbError::IncludeMissing`] — which
//! names the file and the exact line — rather than writing into a void. Offering
//! to insert the line automatically was considered and refused: it is an edit to
//! the operator's `smb.conf`, and that is the door this module keeps shut.
//!
//! # What it needs, and what happens without it
//!
//! Reading is `testparm -s`, which needs no privilege — it parses the live
//! configuration and prints the merged result, so it sees every share the server
//! actually serves, including the ones in other included files. Writing needs
//! **write access to the Samba configuration directory**, in practice root, and
//! so does `smbcontrol all reload-config`. Neither is attempted silently: a
//! refusal comes back as [`SmbError::Denied`] naming the access that is missing.
//!
//! # The honest limit of a per-share `guest ok = no`
//!
//! Every stanza this backend emits carries `guest ok = no`, which refuses an
//! unauthenticated session on *that* share whatever the `[global]` section says.
//! What it cannot do is change the `[global]` section — so a server configured
//! with `map to guest = Bad User` still maps a failed login to the guest account
//! for *other* shares, and this backend will report those shares' guest access in
//! its snapshot without changing them. Reporting somebody's configuration is
//! this module's job; rewriting it is not.

use crate::share::SmbName;
use crate::smb::plan::{Action, Apply, LiveShare, Performed, Reconciliation};
use crate::smb::run::{run, COMMAND_TIMEOUT};
use crate::smb::{DesiredShare, SmbBackend, SmbError};
use std::path::{Path, PathBuf};

/// The file this backend owns, writes in full, and is the only writer of.
pub const INCLUDE_FILE: &str = "/etc/samba/selfhost.conf";

/// The operator's own Samba configuration. Read to check for the `include` line;
/// **never written**.
pub const SMB_CONF: &str = "/etc/samba/smb.conf";

/// The configuration parser and dumper that ships with Samba.
pub const TESTPARM: &str = "testparm";

/// The tool that asks a running `smbd` to re-read its configuration.
pub const SMBCONTROL: &str = "smbcontrol";

/// The privilege writing the include file and reloading the server needs.
const PRIVILEGE: &str = "write access to the Samba configuration directory (root)";

/// The section name that is not a share.
const GLOBAL_SECTION: &str = "global";

/// Samba, driven through a generated include file.
///
/// Holds its two paths rather than reaching for the constants, so a test can
/// point it at a scratch directory and exercise the real rendering, the real
/// include check and the real file write without needing `/etc`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SambaBackend {
    include_file: PathBuf,
    smb_conf: PathBuf,
}

impl Default for SambaBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SambaBackend {
    /// The backend for a stock Samba install.
    pub fn new() -> Self {
        Self { include_file: PathBuf::from(INCLUDE_FILE), smb_conf: PathBuf::from(SMB_CONF) }
    }

    /// The backend pointed at another pair of files, for tests.
    pub fn at(include_file: impl Into<PathBuf>, smb_conf: impl Into<PathBuf>) -> Self {
        Self { include_file: include_file.into(), smb_conf: smb_conf.into() }
    }

    /// The file this backend generates.
    pub fn include_file(&self) -> &Path {
        &self.include_file
    }

    /// Whether the operator's `smb.conf` pulls in the generated file.
    ///
    /// A textual check on a file we only ever read. It looks for an `include`
    /// directive naming our path; a commented-out line does not count, because a
    /// commented include is exactly the state of somebody who tried this once and
    /// backed it out.
    ///
    /// A missing or unreadable `smb.conf` answers `false` rather than erroring:
    /// the actionable message is the same one — "add this line" — and it is more
    /// useful than an I/O error about a path the operator did not name.
    pub async fn include_configured(&self) -> bool {
        let Ok(text) = tokio::fs::read_to_string(&self.smb_conf).await else {
            return false;
        };
        let wanted = self.include_file.to_string_lossy();
        text.lines()
            .map(str::trim)
            .filter(|line| !line.starts_with('#') && !line.starts_with(';'))
            .any(|line| {
                let mut halves = line.splitn(2, '=');
                let key = halves.next().unwrap_or_default().trim();
                let value = halves.next().unwrap_or_default().trim();
                key.eq_ignore_ascii_case("include") && value == wanted
            })
    }
}

/// Renders the whole of the generated include file.
///
/// Pure, and total over anything [`DesiredShare`] can hold — which is the reason
/// that type refuses a root with a control character in it. A newline inside a
/// path would end the `path =` line and begin a new directive, and the directive
/// an attacker would choose is `guest ok = yes`.
///
/// Every stanza carries `guest ok = no` as a literal. There is no branch here
/// that emits anything else.
pub fn render_conf(shares: &[&DesiredShare]) -> String {
    let mut out = String::from(
        "# Generated by selfhost. Every share point below was created by this\n\
         # deployment, and this whole file is rewritten on each reconcile — so an\n\
         # edit made here is lost, and a stanza removed from the configuration\n\
         # simply stops being written. selfhost never edits smb.conf itself.\n\
         #\n\
         # Pull this in with one line in the [global] section of smb.conf:\n\
         #   include = /etc/samba/selfhost.conf\n",
    );
    for share in shares {
        out.push_str(&format!("\n[{}]\n", share.name()));
        out.push_str(&format!("\tpath = {}\n", share.root_text()));
        out.push_str("\tavailable = yes\n");
        out.push_str("\tguest ok = no\n");
        out.push_str(&format!(
            "\tread only = {}\n",
            if share.read_only() { "yes" } else { "no" }
        ));
        if share.encrypt() {
            out.push_str("\tsmb encrypt = required\n");
        }
    }
    out
}

/// Reads `testparm -s` into the module's own model.
///
/// `testparm` prints the *merged* configuration — globals, every share, and
/// everything pulled in by an `include` — with only the parameters that differ
/// from Samba's defaults. That last part is the trap this parser is written
/// around: `read only = Yes` is Samba's default for a share and so is usually
/// absent, and a parser that read an absent flag as "writable" would report every
/// stock share as writable and then plan to "correct" share points it owns that
/// were already right.
///
/// So the defaults are applied explicitly: read-only unless a `writeable`,
/// `writable`, `write ok` or `read only` directive says otherwise; available
/// unless `available = no`; guest access only when a directive grants it.
pub fn parse_testparm(text: &str) -> Vec<LiveShare> {
    let mut shares: Vec<LiveShare> = Vec::new();
    // The share the directives being read belong to. `None` means `[global]`, or
    // the preamble before any section, both of which describe the server rather
    // than a share and so are read and discarded.
    let mut current: Option<LiveShare> = None;

    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(name) = section_header(line) {
            shares.extend(current.take());
            if !name.eq_ignore_ascii_case(GLOBAL_SECTION) {
                current = Some(LiveShare {
                    name: name.to_owned(),
                    aliases: Vec::new(),
                    path: String::new(),
                    guest_access: false,
                    // Samba's own defaults, applied here because testparm omits
                    // any parameter that still holds its default value.
                    read_only: true,
                    encrypted: false,
                    shared: true,
                });
            }
            continue;
        }
        if let (Some(share), Some((key, value))) = (current.as_mut(), directive(line)) {
            apply_directive(share, &key, &value);
        }
    }
    shares.extend(current);
    shares
}

/// The share name in a `[section]` header, if this line is one.
fn section_header(line: &str) -> Option<&str> {
    let inner = line.strip_prefix('[')?.strip_suffix(']')?;
    Some(inner.trim())
}

/// A `key = value` directive, lowercased key and trimmed value.
fn directive(line: &str) -> Option<(String, String)> {
    let (key, value) = line.split_once('=')?;
    Some((key.trim().to_ascii_lowercase(), value.trim().to_owned()))
}

/// Folds one directive into the share it belongs to.
///
/// Handles the synonyms Samba accepts for the same knob, because a configuration
/// written by hand uses whichever one its author learned: `writeable`,
/// `writable` and `write ok` are all the inverse of `read only`, and `public` is
/// a synonym for `guest ok`.
fn apply_directive(share: &mut LiveShare, key: &str, value: &str) {
    let yes = is_yes(value);
    match key {
        "path" | "directory" => share.path = value.to_owned(),
        "read only" => share.read_only = yes,
        "writeable" | "writable" | "write ok" => share.read_only = !yes,
        "guest ok" | "public" => share.guest_access = yes,
        "available" => share.shared = yes,
        // Only `required` is encryption the client cannot decline. `desired`
        // negotiates it and falls back, which is not the guarantee an operator
        // who asked for encryption thinks they bought.
        "smb encrypt" => share.encrypted = value.eq_ignore_ascii_case("required"),
        _ => {}
    }
}

/// Whether a Samba boolean reads as true.
///
/// Samba accepts `yes`/`true`/`1` and their negatives, in any case.
fn is_yes(value: &str) -> bool {
    matches!(value.trim().to_ascii_lowercase().as_str(), "yes" | "true" | "1")
}

impl SmbBackend for SambaBackend {
    async fn snapshot(&self) -> Result<Vec<LiveShare>, SmbError> {
        let ran = run(TESTPARM, &["-s"], &[], COMMAND_TIMEOUT).await?;
        // `testparm` writes its dump to standard output and its commentary to
        // standard error, and exits non-zero only when the configuration is
        // unparseable — which is the operator's problem to hear about verbatim.
        let ran = ran.ok_or_error(TESTPARM, PRIVILEGE)?;
        Ok(parse_testparm(&ran.stdout))
    }

    async fn service_running(&self) -> Result<Option<bool>, SmbError> {
        // Samba runs under half a dozen init systems and this crate drives none
        // of them. Saying "cannot tell" is honest; saying "no" would be a claim
        // about a machine nothing here has looked at.
        Ok(None)
    }

    async fn start_service(&self, _apply: Apply) -> Result<bool, SmbError> {
        Err(SmbError::Command {
            program: "smbd".to_owned(),
            code: None,
            detail: "selfhost does not start Samba: it is managed by this host's init system \
                     (systemctl start smbd, rc-service samba start, or the equivalent)"
                .to_owned(),
        })
    }

    async fn reconcile(
        &self,
        plan: &Reconciliation,
        apply: Apply,
    ) -> Result<Vec<Performed>, SmbError> {
        if plan.changes_the_host() && !self.include_configured().await {
            // Refused rather than written: the file would be correct and the
            // server would not have read it, which is the failure mode that
            // wastes an afternoon.
            return Err(SmbError::IncludeMissing { file: self.include_file.clone() });
        }

        if apply.writes() && plan.changes_the_host() {
            let body = render_conf(&plan.desired_after());
            tokio::fs::write(&self.include_file, body).await.map_err(|error| {
                if error.kind() == std::io::ErrorKind::PermissionDenied {
                    SmbError::Denied { program: "write".to_owned(), privilege: PRIVILEGE }
                } else {
                    SmbError::Io(error)
                }
            })?;
            run(SMBCONTROL, &["all", "reload-config"], &[], COMMAND_TIMEOUT)
                .await?
                .ok_or_error(SMBCONTROL, PRIVILEGE)?;
        }

        Ok(steps(plan, apply))
    }
}

/// The steps a rewrite performs, in the vocabulary every backend reports in.
///
/// Samba does not issue a command per share — one file rewrite carries the whole
/// plan — so the list is derived from the plan rather than accumulated while
/// running. The console then renders a Samba reconcile exactly as it renders a
/// macOS one.
fn steps(plan: &Reconciliation, apply: Apply) -> Vec<Performed> {
    let applied = apply.writes();
    let mut performed = Vec::new();
    let mut push = |action: Action, name: &SmbName| {
        performed.push(Performed { action, name: name.clone(), applied });
    };
    for name in &plan.remove {
        push(Action::Remove, name);
    }
    for update in &plan.update {
        push(Action::Update, update.desired.name());
    }
    for share in &plan.create {
        push(Action::Create, share.name());
    }
    for name in &plan.forget {
        push(Action::Forget, name);
    }
    performed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{Reserved, Share, SmbExport, Shares};
    use crate::smb::plan::{desired_exports, diff, Owned};

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

    /// A merged configuration as `testparm -s` prints one, including a share the
    /// operator wrote by hand and left open to guests.
    const LIVE_CONFIG: &str = "\
[global]
\tworkgroup = WORKGROUP
\tmap to guest = Bad User

[printers]
\tpath = /var/spool/samba
\tguest ok = Yes
\tprintable = Yes

[family]
\tpath = /srv/family
\tpublic = yes
\twriteable = yes

[Vault]
\tpath = /srv/vault
\tguest ok = No
\tsmb encrypt = required
";

    #[test]
    fn a_stanza_always_refuses_guests_whatever_else_it_says() {
        for encrypt in [false, true] {
            for read_only in [false, true] {
                let share = export("Vault", "/srv/vault", encrypt, read_only);
                let text = render_conf(&[&share]);
                assert_eq!(text.matches("guest ok = no").count(), 1, "{text}");
                assert!(!text.contains("guest ok = yes"), "{text}");
                assert!(!text.contains("public = yes"), "{text}");
            }
        }
    }

    #[test]
    fn a_stanza_carries_the_name_the_path_and_the_flags_asked_for() {
        let share = export("Vault", "/srv/vault", true, true);
        let text = render_conf(&[&share]);
        assert!(text.contains("[Vault]"), "{text}");
        assert!(text.contains("\tpath = /srv/vault\n"), "{text}");
        assert!(text.contains("\tread only = yes\n"), "{text}");
        assert!(text.contains("\tsmb encrypt = required\n"), "{text}");

        let writable = render_conf(&[&export("Vault", "/srv/vault", false, false)]);
        assert!(writable.contains("\tread only = no\n"), "{writable}");
        assert!(!writable.contains("smb encrypt"), "encryption was not asked for: {writable}");
    }

    #[test]
    fn a_file_with_no_shares_is_still_written_and_still_explains_itself() {
        let text = render_conf(&[]);
        assert!(text.contains("include = /etc/samba/selfhost.conf"), "{text}");
        assert!(
            !text.lines().any(|line| line.starts_with('[')),
            "no stanzas at all, only the comment that names the include line: {text}"
        );
    }

    #[test]
    fn the_generated_file_is_the_whole_removal_mechanism() {
        // A removal on this platform is a stanza that is no longer emitted. The
        // property worth asserting is that what gets written is exactly the
        // plan's surviving set — never anything read back off the host.
        let keep = export("Vault", "/srv/vault", true, true);
        let plan = diff(
            std::slice::from_ref(&keep),
            &[
                LiveShare {
                    name: "Vault".into(),
                    aliases: Vec::new(),
                    path: "/srv/vault".into(),
                    guest_access: false,
                    read_only: true,
                    encrypted: true,
                    shared: true,
                },
                LiveShare {
                    name: "family".into(),
                    aliases: Vec::new(),
                    path: "/srv/family".into(),
                    guest_access: true,
                    read_only: false,
                    encrypted: false,
                    shared: true,
                },
            ],
            &Owned::parse("Vault").expect("legal"),
        );
        let text = render_conf(&plan.desired_after());
        assert!(text.contains("[Vault]"), "{text}");
        assert!(!text.contains("family"), "somebody else's stanza is never written: {text}");
    }

    #[test]
    fn testparm_defaults_are_applied_rather_than_read_as_absent() {
        let live = parse_testparm(LIVE_CONFIG);
        let names: Vec<&str> = live.iter().map(|share| share.name.as_str()).collect();
        assert_eq!(names, vec!["printers", "family", "Vault"], "global is not a share");

        let vault = live.iter().find(|share| share.name == "Vault").expect("Vault");
        assert!(vault.read_only, "read only = Yes is Samba's default and testparm omits it");
        assert!(vault.encrypted);
        assert!(!vault.guest_access);
        assert_eq!(vault.path, "/srv/vault");
        assert!(vault.shared);
    }

    #[test]
    fn the_synonyms_an_operator_may_have_written_are_all_understood() {
        let family = parse_testparm(LIVE_CONFIG)
            .into_iter()
            .find(|share| share.name == "family")
            .expect("family");
        assert!(family.guest_access, "`public = yes` is `guest ok = yes`");
        assert!(!family.read_only, "`writeable = yes` is `read only = no`");
    }

    #[test]
    fn a_share_marked_unavailable_is_not_an_export() {
        let live = parse_testparm("[archive]\n\tpath = /srv/a\n\tavailable = No\n");
        assert_eq!(live.len(), 1);
        assert!(!live[0].shared);
    }

    #[test]
    fn a_hand_written_guest_share_is_reported_and_left_entirely_alone() {
        // The Linux face of the acceptance test: the operator's open `family`
        // share is seen, named for display, and in no actionable list.
        let live = parse_testparm(LIVE_CONFIG);
        let plan = diff(&[], &live, &Owned::empty());
        assert!(plan.untouched.contains(&"family".to_owned()));
        assert!(plan.untouched.contains(&"printers".to_owned()));
        assert!(plan.remove.is_empty(), "{:?}", plan.remove);
    }

    #[tokio::test]
    async fn a_missing_include_line_is_refused_rather_than_written_into_a_void() {
        let directory =
            std::env::temp_dir().join(format!("selfhost-samba-none-{}", std::process::id()));
        tokio::fs::create_dir_all(&directory).await.expect("a scratch directory");
        let include = directory.join("selfhost.conf");
        let conf = directory.join("smb.conf");
        tokio::fs::write(&conf, "[global]\n\tworkgroup = WORKGROUP\n").await.expect("write");

        let backend = SambaBackend::at(&include, &conf);
        assert!(!backend.include_configured().await);

        let plan = diff(&[export("Vault", "/srv/vault", true, true)], &[], &Owned::empty());
        let error = backend
            .reconcile(&plan, Apply::Write)
            .await
            .expect_err("writing a file nothing reads is not success");
        assert!(matches!(error, SmbError::IncludeMissing { .. }), "{error}");
        assert!(!include.exists(), "and nothing was written");

        tokio::fs::remove_dir_all(&directory).await.expect("cleanup");
    }

    #[tokio::test]
    async fn a_commented_out_include_does_not_count() {
        let directory =
            std::env::temp_dir().join(format!("selfhost-samba-hash-{}", std::process::id()));
        tokio::fs::create_dir_all(&directory).await.expect("a scratch directory");
        let include = directory.join("selfhost.conf");
        let conf = directory.join("smb.conf");
        let body = format!("[global]\n#  include = {}\n", include.display());
        tokio::fs::write(&conf, body).await.expect("write");

        assert!(!SambaBackend::at(&include, &conf).include_configured().await);

        tokio::fs::remove_dir_all(&directory).await.expect("cleanup");
    }

    #[tokio::test]
    async fn a_configured_include_is_recognised_and_a_dry_run_still_writes_nothing() {
        let directory =
            std::env::temp_dir().join(format!("selfhost-samba-ok-{}", std::process::id()));
        tokio::fs::create_dir_all(&directory).await.expect("a scratch directory");
        let include = directory.join("selfhost.conf");
        let conf = directory.join("smb.conf");
        let body = format!("[global]\n\tinclude = {}\n", include.display());
        tokio::fs::write(&conf, body).await.expect("write");

        let backend = SambaBackend::at(&include, &conf);
        assert!(backend.include_configured().await);
        assert_eq!(backend.include_file(), include.as_path());

        let plan = diff(&[export("Vault", "/srv/vault", true, true)], &[], &Owned::empty());
        let performed = backend.reconcile(&plan, Apply::DryRun).await.expect("a dry run");
        assert_eq!(performed.len(), 1);
        assert!(!performed[0].applied);
        assert!(!include.exists(), "a dry run writes no file");

        tokio::fs::remove_dir_all(&directory).await.expect("cleanup");
    }

    #[tokio::test]
    async fn starting_samba_is_refused_with_the_command_the_operator_should_run() {
        let error = SambaBackend::new()
            .start_service(Apply::Write)
            .await
            .expect_err("this crate does not drive init systems");
        assert!(error.to_string().contains("systemctl"), "{error}");
    }

    #[tokio::test]
    async fn samba_declines_to_guess_whether_the_service_is_up() {
        assert_eq!(SambaBackend::new().service_running().await.expect("no error"), None);
    }
}
