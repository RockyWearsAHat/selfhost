//! The shares this deployment serves over the console site, over WebDAV, and —
//! where the operating system will do it for us — over SMB.
//!
//! A share is **declared, never discovered**: the set of shares is exactly the
//! set of `[[shares]]` blocks in `selfhost.config.toml`, so the answer to "what
//! can this box hand out?" is a file an operator can read, diff and revert.
//! There is no runtime registration and no "add a folder" button, for the same
//! reason there is no runtime registration of a site or a mailbox.
//!
//! This module is only the *schema* and the rules that are about the document.
//! The running storage layer is built from these types in `selfhost-storage`,
//! which depends on this crate; this crate never depends on `storage`, exactly
//! as [`crate::mail`] never depends on `mail`. That one-way arrangement is why
//! the id character set and the reserved-word list below are **mirrored** from
//! `storage::share` rather than imported.
//!
//! # Where the rules about a share's *root* live, and why not here
//!
//! Config checks the shape of the document: that an id is a legal URL segment,
//! that a root was written down at all, that two shares do not collide. It does
//! **not** decide whether a root is a safe directory to serve. That judgement —
//! refusing the filesystem root, refusing a root containing `..`, and refusing a
//! root that is, contains, or sits inside `data_dir`, the TLS store or this
//! repository's checkout — lives in `storage::share::Share::new`, which cannot
//! be called without the [`Reserved`](../../selfhost_storage/share/struct.Reserved.html)
//! list naming those directories.
//!
//! It lives there because a type whose entire reason for existing is that it has
//! been checked must not depend on some other crate remembering to check it. A
//! share can reach the daemon by a route that never passed through this file — a
//! test fixture, a hand-built literal, a future API — and the rule that stops
//! `root = "/"` from serving `/etc/passwd` has to hold on every one of those
//! routes, not just the one that starts with TOML. Restating it here would make
//! two places that must agree forever; the failure mode of divergence is an
//! exposure, so there is one place.
//!
//! What *is* here is the cross-entry rule no single share can see: two shares
//! whose roots contain one another make every permission question ambiguous, so
//! the set is refused. `storage` re-checks that too, at construction, for the
//! reason above — this copy exists so `selfhost check` names the offending pair
//! at load rather than leaving the daemon to refuse the whole set at start-up.

use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

use crate::validate::Problem;

/// Longest share id, in characters. Mirrors `storage::share::MAX_ID_LEN`, kept
/// local so `config` stays free of a dependency on the `storage` crate (which
/// depends on *this* one), the same way [`crate::mail`] mirrors the address
/// limits it checks against.
const MAX_ID_LEN: usize = 32;

/// Longest SMB share name, in characters. Mirrors
/// `storage::share::MAX_SMB_NAME_LEN`: Windows caps a share name at 80, and
/// macOS and Samba are looser, so 80 is the only number that works everywhere.
const MAX_SMB_NAME_LEN: usize = 80;

/// Path segments a share id may not take, because the console site already
/// serves something at them. Mirrors `storage::share::RESERVED_IDS`.
///
/// A share whose id is `api` would shadow the admin relay for the whole site,
/// which is a denial of service against the operator's only way in.
const RESERVED_IDS: [&str; 5] = ["api", "dav", "assets", "static", "console"];

/// What a grant lets a person do, ordered from least to most.
///
/// The ordering is the point: a `Write` grant satisfies a read, and an `Admin`
/// grant satisfies both. Spelled lowercase in TOML like every other tag in this
/// crate, so a typo'd mode fails at load with serde naming the accepted words
/// rather than at request time as a silent denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessMode {
    /// List and download.
    Read,
    /// Everything `Read` allows, plus create, overwrite, move and delete.
    Write,
    /// Everything `Write` allows, plus changing the share itself.
    Admin,
}

impl AccessMode {
    /// The TOML and wire spelling of this mode, matching its serde form — so an
    /// error message names the exact word the config must contain. Mirrors
    /// `storage::share::Mode::tag`.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }
}

/// One person's grant on one share.
///
/// Every authenticated caller is the owner today — the console password and the
/// bearer token are root credentials of the deployment, not people — so every
/// grant written here is already satisfied. They are parsed, validated and
/// carried anyway, because a permission model retrofitted onto a shipped route
/// is a model nobody ever tested. When per-person identity lands, turning it on
/// is a config change rather than a code change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessConfig {
    /// The person's name, as it appears in the passkey registry.
    ///
    /// Checked here only for presence. What a *legal* person name is belongs to
    /// `selfhost-identity`'s `PersonName::parse`, which `storage` runs when it
    /// builds the grant, so the refusal an operator reads is that crate's own
    /// sentence rather than a second opinion invented here.
    pub user: String,
    /// What they may do.
    pub mode: AccessMode,
}

/// How a share is exported over SMB, when it is.
///
/// SMB authenticates against **operating-system accounts**. The console password
/// cannot open an SMB session on any platform, and guest access is refused and
/// is not configurable — an anonymous file server on a box with a public IP is
/// the single most reliable way to lose every byte on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SmbConfig {
    /// The share name the operating system advertises.
    ///
    /// Kept short and free of the characters that end an argument, because this
    /// string becomes an argument to `New-SmbShare` on Windows and a stanza
    /// header in `smb.conf` on Linux. `storage::share::SmbName` is the authority;
    /// the length and emptiness checks here catch the obvious cases at load.
    pub name: String,
    /// Require SMBv3 encryption, refusing clients that cannot negotiate it.
    ///
    /// Defaults to `true`. An unencrypted SMB session carries file contents in
    /// the clear across whatever network the client reached us over, and the
    /// trade — an old client stops working — is the one worth making by default.
    #[serde(default = "default_true")]
    pub encrypt: bool,
    /// Export read-only regardless of the share's own flag.
    ///
    /// Defaults to `true`, and the **stricter of the two wins**: a share that is
    /// read-only is read-only over SMB whatever this says. Writing to a share
    /// over SMB is authorised by an OS account this project never sees, so it is
    /// opted into deliberately rather than inherited.
    #[serde(default = "default_true")]
    pub read_only: bool,
}

/// The documented `[[shares]]` example, as live TOML.
///
/// Shipped commented out — through [`crate::commented`] — in
/// `selfhost.config.toml` and in the `selfhost init` template, so that a box
/// gains a share only when somebody writes one.
pub const EXAMPLE: &str = "\
# ─── Network storage ───────────────────────────────────────────────────────────
# A share is reachable only through the console site, which validation already
# forces to carry a non-empty allowed_cidrs. A root may not sit inside data_dir,
# the TLS store, or this repository — the box builds and runs that tree, so a
# share rooted there is a write primitive that becomes code execution on the next
# push. That rule is enforced when the share is constructed, not here.

[[shares]]
id = \"vault\"                       # [a-z0-9-]; this is also the URL segment
root = \"D:/Shares/Vault\"           # absolute, must exist, may not nest with another share
read_only = false                  # omitted means read-only: a share is not writable by accident
browsable = true                   # advertise over DNS-SD where the OS will publish for us
quota_bytes = 500000000000

  # Optional: ask the operating system to export the same root over SMB.
  # SMB authenticates against OS accounts — the console password cannot open an
  # SMB session on any platform. Guest access is refused and is not configurable.
  [shares.smb]
  name = \"Vault\"
  encrypt = true                   # require SMBv3 encryption
  read_only = false

  # Optional: per-person grants. Every current caller is the owner, so these are
  # satisfied today; the enforcement path is live from the first release so that
  # turning on per-user identity later is a config change, not a code change.
  [[shares.access]]
  user = \"alex\"
  mode = \"write\"                   # \"read\" | \"write\" | \"admin\"
";

/// One `[[shares]]` block: a directory this box will serve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareConfig {
    /// The share's identifier, which is also its URL segment.
    ///
    /// `[a-z0-9-]` and nothing else — narrow enough to paste into a URL, a
    /// filename, a DNS-SD instance name and an SMB share name without any of
    /// them needing to escape it.
    pub id: String,

    /// The directory served, as an absolute path.
    ///
    /// Whether this is a *safe* directory to serve is decided by
    /// `storage::share::Share::new`, not here; see the module documentation for
    /// why that check cannot live in config.
    pub root: PathBuf,

    /// Refuse every write to this share.
    ///
    /// **Defaults to `true`.** A share whose block never said it was writable is
    /// not writable: the same default-deny posture that makes `[desktop]`
    /// absent mean "no desktop" and an unmanaged firewall open nothing. Turning
    /// a share writable is one word, and it is a word an operator should have to
    /// type.
    #[serde(default = "default_true")]
    pub read_only: bool,

    /// Advertise this share over DNS-SD where the operating system will publish
    /// for us.
    ///
    /// **Defaults to `false`.** Advertising tells every machine on the segment
    /// that this share exists and what it is called, which is a disclosure even
    /// when the bytes stay protected — so it is opted into, not inherited.
    #[serde(default)]
    pub browsable: bool,

    /// Ceiling on the total bytes stored under `root`, enforced by the upload
    /// path. Absent means the share is bounded only by the filesystem, which on
    /// a box that also holds the mail spool and the TLS store means one upload
    /// can take the deployment down.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,

    /// Ask the operating system to export the same root over SMB. Absent → no
    /// SMB export, which is the default and the posture of a box whose only
    /// intended public surface is the proxy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub smb: Option<SmbConfig>,

    /// Per-person grants. Empty means the share is reachable only by the
    /// deployment's owner credentials, which is every credential that exists
    /// today.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub access: Vec<AccessConfig>,
}

fn default_true() -> bool {
    true
}

impl ShareConfig {
    /// A share of `root` under `id`, in the closed posture: read-only, not
    /// advertised, unbounded by quota only because no quota was named, with no
    /// SMB export and no grants.
    ///
    /// Every field a caller does not set is the field's safe value, so a share
    /// built here and a share parsed from a block that names only `id` and
    /// `root` are the same share.
    pub fn new(id: impl Into<String>, root: impl Into<PathBuf>) -> Self {
        Self {
            id: id.into(),
            root: root.into(),
            read_only: true,
            browsable: false,
            quota_bytes: None,
            smb: None,
            access: Vec::new(),
        }
    }

    /// Collects every structural problem with this one block.
    ///
    /// `at` is the dotted path problems are reported under (`shares[0]`),
    /// matching every other `check` in this crate. Cross-entry rules — duplicate
    /// ids, nested roots — belong to [`check_shares`], which is the only place
    /// that can see more than one block at a time.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if let Some(message) = id_problem(&self.id) {
            problems.push(Problem { field: format!("{at}.id"), message });
        }

        if self.root.as_os_str().is_empty() {
            problems.push(Problem {
                field: format!("{at}.root"),
                message: "say which directory this share serves; a share with no root serves \
                          nothing, and an empty path is not a shorter way of writing the \
                          current directory"
                    .into(),
            });
        }

        if self.quota_bytes == Some(0) {
            problems.push(Problem {
                field: format!("{at}.quota_bytes"),
                message: "is zero, which refuses every upload including the first byte; omit \
                          it to leave the share unbounded, or set read_only = true to say \
                          plainly that nothing may be written"
                    .into(),
            });
        }

        if let Some(smb) = &self.smb {
            if let Some(message) = smb_name_problem(&smb.name) {
                problems.push(Problem { field: format!("{at}.smb.name"), message });
            }
        }

        for (i, grant) in self.access.iter().enumerate() {
            if grant.user.trim().is_empty() {
                problems.push(Problem {
                    field: format!("{at}.access[{i}].user"),
                    message: "name the person this grant belongs to; an empty name is not a \
                              person, and a grant nobody holds is a line that only makes the \
                              access list look considered"
                        .into(),
                });
            }
        }
    }
}

/// Collects every structural problem with the whole `[[shares]]` list.
///
/// Runs each block's own [`ShareConfig::check`] and then the two rules that only
/// exist between blocks: no two shares may share an id, and no share's root may
/// contain another's.
///
/// `at` is the dotted path the list is reported under (`shares`). Public because
/// `selfhost doctor` reports the same judgement on a running deployment rather
/// than re-deriving it — a diagnostic that disagrees with the loader about what
/// is acceptable is worse than no diagnostic.
pub fn check_shares(shares: &[ShareConfig], at: &str, problems: &mut Vec<Problem>) {
    for (i, share) in shares.iter().enumerate() {
        share.check(&format!("{at}[{i}]"), problems);

        // A repeated id is ambiguous: one URL segment would name two
        // directories, with two read-only flags, two quotas and two grant
        // lists, and no defensible answer to which applies.
        if let Some(previous) = shares[..i].iter().position(|earlier| earlier.id == share.id) {
            problems.push(Problem {
                field: format!("{at}[{i}].id"),
                message: format!(
                    "\"{}\" is already the id of {at}[{previous}]; an id is the share's URL \
                     segment, so two shares cannot answer to one",
                    share.id
                ),
            });
        }

        for (j, earlier) in shares[..i].iter().enumerate() {
            if nests(&earlier.root, &share.root) {
                problems.push(Problem {
                    field: format!("{at}[{i}].root"),
                    message: format!(
                        "\"{}\" and {at}[{j}]'s \"{}\" contain one another, so a file \
                         reachable through both inherits two read-only flags, two quotas and \
                         two grant lists. Rather than pick one and document it, the pair is \
                         refused: give each share a root the other does not reach.",
                        share.root.display(),
                        earlier.root.display()
                    ),
                });
            }
        }
    }
}

/// Why this text is not a legal share id, or `None` when it is.
///
/// Mirrors `storage::share::ShareId::parse`, whose refusal is the authoritative
/// one; this copy exists so the message an operator reads at `selfhost check`
/// names the field and the fix.
fn id_problem(id: &str) -> Option<String> {
    if id.is_empty() {
        return Some("must not be empty; the id is the share's URL segment".into());
    }
    if id.chars().count() > MAX_ID_LEN {
        return Some(format!(
            "is {} characters, over the {MAX_ID_LEN}-character limit; an id is read in a URL, \
             a WebDAV collection name and half an SMB share name, so it stays short enough to \
             read in all three",
            id.chars().count()
        ));
    }
    if !id.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Some(format!(
            "\"{id}\" must be lowercase letters, digits and hyphens only. That character set \
             is narrow enough to paste into a URL, a filename, a DNS-SD instance name and an \
             SMB share name without any of them needing to escape it, which is worth more \
             than the expressiveness given up."
        ));
    }
    if RESERVED_IDS.contains(&id) {
        return Some(format!(
            "\"{id}\" is a path the console site already serves; a share there would shadow \
             it for the whole site, which is a denial of service against the operator's only \
             way in. Reserved: {}",
            RESERVED_IDS.join(", ")
        ));
    }
    None
}

/// Why this text is not usable as an SMB share name, or `None` when it is.
///
/// Deliberately thin: `storage::share::SmbName` decides the full character set,
/// because that string becomes an argument to three different commands and the
/// rule has to hold wherever an export is built. What is caught here is what an
/// operator can fix by reading their own config — an empty name, an overlong
/// one, and the whitespace-or-control characters that would end a command line
/// or start a second `smb.conf` line.
fn smb_name_problem(name: &str) -> Option<String> {
    if name.trim().is_empty() {
        return Some(
            "must not be empty; this is the name the operating system advertises the share \
             under"
                .into(),
        );
    }
    if name.chars().count() > MAX_SMB_NAME_LEN {
        return Some(format!(
            "is {} characters, over the {MAX_SMB_NAME_LEN}-character limit Windows imposes on \
             a share name",
            name.chars().count()
        ));
    }
    if name.chars().any(|c| c.is_control() || c == '\\' || c == '/' || c == '"') {
        return Some(format!(
            "\"{name}\" contains a control character, a slash or a quote. This name is an \
             argument to New-SmbShare on Windows and a stanza header in smb.conf on Linux, \
             where a newline is a second line of configuration and a quote ends an argument."
        ));
    }
    None
}

/// Whether either path contains the other, component by component.
///
/// Equal paths nest — the same directory under two ids is the ambiguity this
/// rule exists to refuse, not an edge case around it.
///
/// The comparison is exact and textual, which is sound only because a root
/// containing `..` never reaches a live share: `storage::share::Share::new`
/// refuses one outright, precisely so that `/srv/vault` and
/// `/srv/other/../vault` cannot be provably one directory and pass this check as
/// two. A root carrying `..` is therefore skipped here rather than compared
/// wrongly — the refusal it earns is the constructor's, and reporting a second,
/// weaker complaint about the same characters would only bury it.
///
/// What none of this can see is a symlink: two roots that are the same directory
/// by way of one still pass. That is stated rather than hidden, and it is the
/// filesystem layer's to close when it canonicalises each root at start-up.
fn nests(a: &Path, b: &Path) -> bool {
    // An empty root is nobody's parent. It has already earned its own problem
    // for being empty, and zipping zero components against anything answers
    // "prefix of everything", which would bury that problem under a second one.
    if a.as_os_str().is_empty() || b.as_os_str().is_empty() {
        return false;
    }
    if has_parent_component(a) || has_parent_component(b) {
        return false;
    }
    a.components().zip(b.components()).all(|(x, y)| x == y)
}

/// Whether a path has a `..` component, which makes component-wise comparison
/// meaningless.
fn has_parent_component(path: &Path) -> bool {
    path.components().any(|component| matches!(component, Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems_of(shares: &[ShareConfig]) -> Vec<Problem> {
        let mut problems = Vec::new();
        check_shares(shares, "shares", &mut problems);
        problems
    }

    fn has(problems: &[Problem], field: &str) -> bool {
        problems.iter().any(|p| p.field == field)
    }

    #[test]
    fn a_minimal_share_is_valid_and_closed() {
        // The safety argument in one test: a block naming only an id and a root
        // is read-only, unadvertised, unexported and ungranted.
        let share = ShareConfig::new("vault", "/srv/vault");
        assert!(share.read_only);
        assert!(!share.browsable);
        assert_eq!(share.quota_bytes, None);
        assert!(share.smb.is_none());
        assert!(share.access.is_empty());
        assert!(problems_of(&[share]).is_empty());
    }

    #[test]
    fn an_id_must_be_a_legal_url_segment() {
        for bad in ["", "Vault", "my_vault", "vault.old", "va ult", &"v".repeat(33)] {
            let problems = problems_of(&[ShareConfig::new(bad, "/srv/x")]);
            assert!(has(&problems, "shares[0].id"), "{bad:?}: {problems:?}");
        }
        for good in ["vault", "v", "photos-2026", &"v".repeat(32)] {
            let problems = problems_of(&[ShareConfig::new(good, "/srv/x")]);
            assert!(problems.is_empty(), "{good:?}: {problems:?}");
        }
    }

    #[test]
    fn an_id_may_not_shadow_a_path_the_console_already_serves() {
        for reserved in RESERVED_IDS {
            let problems = problems_of(&[ShareConfig::new(reserved, "/srv/x")]);
            assert!(has(&problems, "shares[0].id"), "{reserved}: {problems:?}");
        }
    }

    #[test]
    fn a_root_must_be_written_down() {
        let problems = problems_of(&[ShareConfig::new("vault", "")]);
        assert!(has(&problems, "shares[0].root"), "{problems:?}");
    }

    #[test]
    fn two_shares_may_not_share_an_id() {
        let problems = problems_of(&[
            ShareConfig::new("vault", "/srv/a"),
            ShareConfig::new("vault", "/srv/b"),
        ]);
        assert!(has(&problems, "shares[1].id"), "{problems:?}");
    }

    #[test]
    fn nested_roots_are_refused_in_both_directions_and_when_equal() {
        // Ambiguity is the defect, and it does not care which block was written
        // first, so all three arrangements must be refused.
        for (first, second) in [
            ("/srv/vault", "/srv/vault/inner"),
            ("/srv/vault/inner", "/srv/vault"),
            ("/srv/vault", "/srv/vault"),
        ] {
            let problems =
                problems_of(&[ShareConfig::new("a", first), ShareConfig::new("b", second)]);
            assert!(has(&problems, "shares[1].root"), "{first} vs {second}: {problems:?}");
        }
    }

    #[test]
    fn sibling_roots_that_merely_share_a_prefix_are_fine() {
        // The bug this guards: a textual `starts_with` would call /srv/vault2 a
        // child of /srv/vault and refuse a config that is perfectly sound.
        let problems = problems_of(&[
            ShareConfig::new("a", "/srv/vault"),
            ShareConfig::new("b", "/srv/vault2"),
        ]);
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn a_root_containing_dot_dot_is_left_to_the_constructor() {
        // config cannot compare through `..`, and storage refuses such a root
        // outright — so this file says nothing rather than saying something
        // wrong about which directory the root names.
        let problems = problems_of(&[
            ShareConfig::new("a", "/srv/vault"),
            ShareConfig::new("b", "/srv/other/../vault"),
        ]);
        assert!(!has(&problems, "shares[1].root"), "{problems:?}");
    }

    #[test]
    fn a_zero_quota_is_refused_because_it_reads_as_unlimited() {
        let mut share = ShareConfig::new("vault", "/srv/vault");
        share.quota_bytes = Some(0);
        assert!(has(&problems_of(&[share]), "shares[0].quota_bytes"));
    }

    #[test]
    fn an_smb_name_must_survive_a_command_line() {
        for bad in ["", "   ", "va\nult", "a/b", "a\\b", "say \"hi\"", &"n".repeat(81)] {
            let mut share = ShareConfig::new("vault", "/srv/vault");
            share.smb = Some(SmbConfig { name: bad.into(), encrypt: true, read_only: true });
            let problems = problems_of(&[share]);
            assert!(has(&problems, "shares[0].smb.name"), "{bad:?}: {problems:?}");
        }
    }

    #[test]
    fn a_grant_needs_a_person() {
        let mut share = ShareConfig::new("vault", "/srv/vault");
        share.access = vec![AccessConfig { user: "  ".into(), mode: AccessMode::Read }];
        assert!(has(&problems_of(&[share]), "shares[0].access[0].user"));
    }

    #[test]
    fn access_modes_are_ordered_from_least_to_most() {
        // The ordering is what makes a grant check a `>=` rather than a match
        // arm somebody will forget to extend.
        assert!(AccessMode::Read < AccessMode::Write);
        assert!(AccessMode::Write < AccessMode::Admin);
    }

    #[test]
    fn a_mode_tag_matches_its_toml_spelling() {
        // tag() feeds error messages; it must equal the serde wire form, or an
        // error would tell the operator to write a word the parser rejects.
        for mode in [AccessMode::Read, AccessMode::Write, AccessMode::Admin] {
            let wire = toml::to_string(&Wrap { mode }).expect("serialises");
            assert!(wire.contains(mode.tag()), "{wire}");
        }
    }

    #[derive(Serialize, Deserialize)]
    struct Wrap {
        mode: AccessMode,
    }

    #[test]
    fn the_section_parses_from_toml_with_its_sub_tables() {
        let config = crate::Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"

[[shares]]
id = "vault"
root = "/srv/vault"
read_only = false
browsable = true
quota_bytes = 500000000

  [shares.smb]
  name = "Vault"
  encrypt = true
  read_only = false

  [[shares.access]]
  user = "alex"
  mode = "write"
"#,
        )
        .expect("valid");

        let share = config.shares.first().expect("one share");
        assert_eq!(share.id, "vault");
        assert!(!share.read_only);
        assert!(share.browsable);
        assert_eq!(share.quota_bytes, Some(500_000_000));
        let smb = share.smb.as_ref().expect("smb table");
        assert_eq!(smb.name, "Vault");
        assert!(smb.encrypt);
        assert!(!smb.read_only);
        assert_eq!(share.access, vec![AccessConfig { user: "alex".into(), mode: AccessMode::Write }]);
    }

    #[test]
    fn omitting_the_flags_leaves_the_share_closed() {
        let config = crate::Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"

[[shares]]
id = "vault"
root = "/srv/vault"

  [shares.smb]
  name = "Vault"
"#,
        )
        .expect("valid");
        let share = &config.shares[0];
        assert!(share.read_only, "an unnamed read_only must not mean writable");
        assert!(!share.browsable, "a share is not advertised unless asked for");
        let smb = share.smb.as_ref().expect("smb table");
        assert!(smb.encrypt, "SMB is encrypted unless the operator opts out");
        assert!(smb.read_only, "an SMB export is read-only unless the operator opts out");
    }

    #[test]
    fn the_documented_example_loads_with_its_sub_tables() {
        let document = format!("{}\n{EXAMPLE}", crate::BASE_DOCUMENT);
        let config = crate::Config::parse(&document).expect("the documented example must load");
        let share = config.shares.first().expect("one share");
        assert_eq!(share.id, "vault");
        assert!(share.smb.is_some(), "the commented sub-tables must be part of the block");
        assert_eq!(share.access.len(), 1);
    }

    #[test]
    fn the_shipped_example_arms_nothing() {
        let document = format!("{}\n{}", crate::BASE_DOCUMENT, crate::commented(EXAMPLE));
        let config = crate::Config::parse(&document).expect("valid");
        assert!(config.shares.is_empty());
    }

    #[test]
    fn the_list_is_optional_and_a_bad_set_fails_at_load() {
        let bare = crate::Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"
"#,
        )
        .expect("valid");
        assert!(bare.shares.is_empty(), "shares are opt-in");

        let outcome = crate::Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"

[[shares]]
id = "vault"
root = "/srv/vault"

[[shares]]
id = "vault"
root = "/srv/vault/inner"
"#,
        );
        match outcome {
            Err(crate::ConfigError::Invalid(problems)) => {
                assert!(has(&problems, "shares[1].id"), "{problems:?}");
                assert!(has(&problems, "shares[1].root"), "{problems:?}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
