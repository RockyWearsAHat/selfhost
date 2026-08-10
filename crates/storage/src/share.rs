//! What a share is, once configuration has been read and believed.
//!
//! A share is **declared, never discovered**. There is no "add a folder" button
//! and no runtime registration: the set of shares is exactly the set of
//! `[[shares]]` blocks in `selfhost.config.toml`, which means the answer to "what
//! can this box serve?" is a file an operator can read, diff, and revert — the
//! same argument [`selfhost_config`](../../selfhost_config/index.html) makes for
//! every other subsystem, and the reason none of them has a mutable registry.
//!
//! # Why this type exists at all, when config already has one
//!
//! Configuration is *text an operator wrote*. A [`Share`] is *a share that has
//! been checked*: its id is a legal URL segment, its root is an absolute
//! directory that is neither the whole filesystem nor anything this box keeps
//! its own credentials, keys or source tree in, its SMB export name is safe to
//! hand to a command line, its grants belong to named people, and the set as a
//! whole has no duplicate ids and no nested roots. Constructing one is the only
//! way to get one, so every layer above this can stop re-asking whether the
//! share it was handed makes sense.
//!
//! [`Shares::new`] re-checks what `crates/config`'s validation also checks, and
//! that is deliberate rather than duplicated by accident. Validation refuses a
//! bad configuration at load; this constructor refuses a bad set at
//! *construction*, so a share that reached the daemon by some other route — a
//! future API, a test fixture, a hand-built literal — cannot skip the rule. The
//! two must agree, and the failure mode if they ever diverge is a refusal rather
//! than an exposure.
//!
//! # Every rule is checked here, including the ones about the root
//!
//! An earlier version of this file said the rules about *where* a share may be
//! rooted — not inside `data_dir`, not inside the TLS store, not inside the
//! repository — were "known to `crates/config`, not here, so that particular
//! check lives there". They did not live there. `crates/config` has no
//! `[[shares]]` section yet, so the check lived nowhere, and
//! `Share::new("vault", "/", …)` returned `Ok`: a share rooted at the whole
//! filesystem, which the resolver in [`crate::path`] then confines every request
//! to, faithfully and correctly, handing back `/etc/passwd` with no rule broken
//! anywhere.
//!
//! That is the shape of the mistake worth remembering: the resolver survived a
//! 38,000-input combinatorial attack without a single escape, and it did not
//! matter, because confinement to a root is only as good as the root. So the
//! rule is now here, in the constructor, and it is not optional —
//! [`Share::new`] cannot be called without a [`Reserved`], which is the list of
//! directories on *this* deployment that a share may neither be, contain, nor
//! sit inside. A type whose entire reason for existing is that it has been
//! checked must not depend on some other crate remembering to check it.
//!
//! # Why nesting is refused, and why a root may not contain `..`
//!
//! Two shares whose roots contain one another make permissions ambiguous: a file
//! reachable through both inherits two read-only flags, two quotas and two grant
//! lists, and no answer to "which one applies" is defensible. Rather than pick
//! one and document it, the set is refused.
//!
//! That refusal is only sound if the comparison can see the ambiguity, and
//! component-wise comparison cannot see through `..`: `/srv/vault` and
//! `/srv/other/../vault` are provably one directory and passed the nesting check
//! as two, so one share's read-only promise could be undone by the other's write
//! grant over the same bytes. A root containing `..` also escapes the directory
//! the operator named — `path::resolve` is pure, so it joins onto the root
//! verbatim and cannot normalise. Both problems have the same one-line answer:
//! a root with a `..` component is refused, so every root this module compares
//! is already in its own shortest form.
//!
//! The same reasoning refuses a root inside `data_dir`, the TLS store, or the
//! repository — that last one because the box rebuilds and restarts itself from
//! its own checkout, so a share rooted there is a write primitive that becomes
//! code execution on the next push, and a *read* of the same tree hands out
//! `data/admin.token` and the private keys under `data/tls`.
//!
//! What none of this can see is a symlink: two roots that are the same directory
//! by way of one still pass. That is stated rather than hidden, and it is the
//! filesystem layer's to close when it canonicalises each root at startup.
//!
//! # Grants, and the seam identity lands in
//!
//! Access is a capability check, not a boolean. Today every authenticated caller
//! is the owner — the console password and the bearer token are both root
//! credentials of the deployment, not people — so every grant is satisfied. The
//! enforcement path is built, exercised and tested anyway, because a permission
//! model retrofitted onto a shipped route is a model nobody ever tested.
//!
//! `crates/identity` has since landed, so [`Grantee`] is no longer a placeholder
//! enum of this crate's own: it is that crate's [`Identity`], and a grant holds
//! its validated
//! [`PersonName`]. That closes a hole in the placeholder — an empty string was a
//! grantee, and matched an empty [`Grant::user`], and could therefore hold
//! `admin` on a share — and it stops the crate inventing a second, weaker answer
//! to "what is a person called".
//!
//! What has *not* moved yet is the decision itself. [`Share::permits`] becomes
//! the `FilesRead(ShareId)` / `FilesWrite(ShareId)` arm of `Policy::decide` when
//! the routes are wired; the mapping is one-to-one on purpose ([`Want::Read`] is
//! `Capability::FilesRead`, and so on down), so nothing about the answer changes
//! — only where the caller's name comes from.

use crate::path::{self, Refusal};
use selfhost_identity::{Identity, InvalidPersonName, PersonName};
use std::fmt;
use std::path::{Component, Path, PathBuf};

/// Longest share id, in characters.
///
/// An id is a URL segment, a WebDAV collection name, and — where SMB is asked
/// for — half of a share name, so it stays short enough to read in all three.
pub const MAX_ID_LEN: usize = 32;

/// Longest SMB share name, in characters.
///
/// Windows caps a share name at 80 characters; macOS and Samba are looser, so 80
/// is the number that works on all three and therefore the only number worth
/// having.
pub const MAX_SMB_NAME_LEN: usize = 80;

/// Path segments a share id may not take, because the console site already
/// serves something at them.
///
/// A share whose id is `api` would shadow the admin relay for the whole site,
/// which is a denial of service against the operator's only way in.
///
/// `well-known` used to be on this list and has been removed: the path the
/// console serves is `/.well-known`, whose first character is a dot, and
/// [`ShareId::parse`] refuses a dot in any position. A reserved word that no
/// legal id can spell is not a defence — it is a line that makes the list look
/// more thorough than it is.
const RESERVED_IDS: [&str; 5] = ["api", "dav", "assets", "static", "console"];

/// Why a share or a set of shares was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShareError {
    /// The id was empty, too long, or held a character outside `[a-z0-9-]`.
    BadId(String),
    /// The id names a path segment the console site already uses.
    ReservedId(String),
    /// Two shares declared the same id, so a URL would name both.
    DuplicateId(String),
    /// The root was not an absolute path. A relative root means "wherever the
    /// daemon happened to be started from", which is a different directory
    /// under launchd, under a Windows service, and in a developer's shell.
    RelativeRoot(String),
    /// The root was a filesystem root — `/`, or a bare drive on Windows.
    ///
    /// Its own variant rather than a [`ShareError::ProtectedRoot`] because no
    /// list of protected directories is involved: a share of the whole volume
    /// contains every one of them, plus the operator's home directory, plus
    /// whatever the next release decides to store. There is no deployment in
    /// which this is what somebody meant.
    FilesystemRoot(String),
    /// The root contained a `..` component, which escapes the directory the
    /// operator named and makes two roots incomparable — see the module
    /// documentation.
    TraversalInRoot(String),
    /// The root is, contains, or sits inside a directory this deployment
    /// protects: `data_dir` and the certificate store under it, or the
    /// repository checkout the box rebuilds and restarts itself from.
    ProtectedRoot {
        /// The share root as configured.
        root: String,
        /// The protected directory it collided with.
        protected: String,
    },
    /// A directory offered to [`Reserved`] could not be compared against
    /// anything: it was relative, or held a `..` component of its own.
    ///
    /// Refused rather than best-effort normalised, because a protection that
    /// silently compares the wrong path is worse than one that will not start.
    UnusableProtectedPath(String),
    /// One root contains another, leaving permissions ambiguous.
    NestedRoots {
        /// The root that contains the other.
        outer: String,
        /// The root that sits inside it.
        inner: String,
    },
    /// The SMB export name is not one this box will hand to `sharing -a`,
    /// `New-SmbShare`, or an `smb.conf` stanza.
    BadSmbName {
        /// The name as configured.
        name: String,
        /// Which rule it broke.
        problem: SmbNameProblem,
    },
    /// A grant named a person whose name is not a legal one.
    BadGrantee {
        /// The name as configured.
        user: String,
        /// The identity crate's reason.
        problem: InvalidPersonName,
    },
}

impl fmt::Display for ShareError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadId(id) => {
                write!(f, "share id {id:?} must be 1-{MAX_ID_LEN} characters of a-z, 0-9 or '-'")
            }
            Self::ReservedId(id) => {
                write!(f, "share id {id:?} is a path the console site already serves")
            }
            Self::DuplicateId(id) => write!(f, "two shares are both called {id:?}"),
            Self::RelativeRoot(root) => {
                write!(f, "share root {root:?} must be an absolute path")
            }
            Self::FilesystemRoot(root) => write!(
                f,
                "share root {root:?} is the whole filesystem; a share must name a directory \
                 inside it"
            ),
            Self::TraversalInRoot(root) => write!(
                f,
                "share root {root:?} contains '..'; write the directory it actually names"
            ),
            Self::ProtectedRoot { root, protected } => write!(
                f,
                "share root {root:?} overlaps {protected:?}, which holds this box's own \
                 credentials, keys or source tree"
            ),
            Self::UnusableProtectedPath(path) => write!(
                f,
                "protected directory {path:?} must be absolute and free of '..' to be compared \
                 against a share root"
            ),
            Self::NestedRoots { outer, inner } => write!(
                f,
                "share root {inner:?} sits inside {outer:?}; nested shares make permissions ambiguous"
            ),
            Self::BadSmbName { name, problem } => {
                write!(f, "SMB share name {name:?} {problem}")
            }
            Self::BadGrantee { user, problem } => {
                write!(f, "grant for {user:?} is not a person's name: {problem}")
            }
        }
    }
}

impl std::error::Error for ShareError {}

/// Which rule an SMB export name broke.
///
/// Typed rather than a message string because one of the five carries the path
/// resolver's own reason, and flattening that into prose here would mean this
/// module holds a second, drifting copy of [`Refusal`]'s vocabulary — the exact
/// duplication [`crate::path`] exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmbNameProblem {
    /// There was no name at all.
    Empty,
    /// Longer than [`MAX_SMB_NAME_LEN`], which is what Windows accepts.
    TooLong,
    /// A character outside the set every platform agrees on.
    ForbiddenCharacter,
    /// The name began or ended with something other than a letter or a digit.
    ///
    /// This is the rule doing the security work: it is why no export name can
    /// ever begin with `-` and be read as an option by `sharing -a` or
    /// `New-SmbShare`.
    EdgeIsNotAlphanumeric,
    /// The name is not one every platform will accept as a *file* name, and
    /// this is the resolver's reason — a reserved device, a trailing dot, a
    /// colon.
    NotAFileName(Refusal),
}

impl fmt::Display for SmbNameProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("must not be empty"),
            Self::TooLong => {
                write!(f, "is longer than the {MAX_SMB_NAME_LEN} characters Windows accepts")
            }
            Self::ForbiddenCharacter => {
                f.write_str("may hold only ASCII letters, digits, '-', '_', '.' and spaces")
            }
            Self::EdgeIsNotAlphanumeric => {
                f.write_str("must begin and end with a letter or a digit")
            }
            Self::NotAFileName(refusal) => {
                write!(f, "is not a name every platform accepts: {refusal}")
            }
        }
    }
}

/// The directories on this deployment that a share may not be, contain, or sit
/// inside.
///
/// # Why this is a parameter and not a constant
///
/// The dangerous directories are not fixed paths. `data_dir` is configuration
/// (`./data` by default, resolved against the project directory by
/// `proxy/src/server.rs:136`), and the repository checkout is wherever the box's
/// source tree happens to live — on the production host it is a clone that the
/// self-updater fetches, builds and restarts from, and on a packaged install
/// there may be none at all. A constant would be wrong on every machine.
///
/// So the deployment states them once, at startup, and every [`Share`] is
/// checked against that statement. It is a value rather than a global because a
/// global would be reachable from a test that forgot it, and unset in exactly
/// the deployment that needed it.
///
/// # What belongs in it
///
/// - **`data_dir`** — the console password hash, `admin.token` (the deployment's
///   root bearer credential), the session store, the passkey registry, and the
///   TLS store at `data_dir/tls` with the private keys in it. The TLS store is
///   not listed separately: it is inside `data_dir`, so `data_dir` already
///   covers it, and a second entry that must stay in step with
///   `proxy/src/tls.rs:74` is a second thing to get wrong. If a future
///   configuration moves the store elsewhere, that path is added with
///   [`Reserved::and`].
/// - **The repository checkout**, when there is one. `[self_update]` makes the
///   daemon fetch, build and restart from that tree unattended, so a writable
///   share over it is remote code execution by file copy, and a readable one
///   hands out whatever secrets the working tree holds.
/// - Anything else a deployment adds later — a backup staging area, a mail
///   store — through [`Reserved::and`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reserved {
    paths: Vec<PathBuf>,
}

impl Reserved {
    /// States what this deployment protects.
    ///
    /// `checkout` is an `Option` rather than a second call so that having no
    /// repository is a decision written at the call site — `None` — instead of a
    /// line somebody forgot to add. On this box it is always `Some`.
    ///
    /// Both paths must be absolute and free of `..`, for the reason
    /// [`ShareError::UnusableProtectedPath`] gives: this type's whole job is
    /// comparison, and a path that cannot be compared soundly must not be
    /// accepted quietly.
    pub fn new(data_dir: impl AsRef<Path>, checkout: Option<&Path>) -> Result<Self, ShareError> {
        let mut reserved = Self { paths: Vec::new() }.and(data_dir)?;
        if let Some(checkout) = checkout {
            reserved = reserved.and(checkout)?;
        }
        Ok(reserved)
    }

    /// Adds one more protected directory.
    pub fn and(mut self, path: impl AsRef<Path>) -> Result<Self, ShareError> {
        let path = path.as_ref();
        if !path.is_absolute() || has_traversal(path) {
            return Err(ShareError::UnusableProtectedPath(display(path)));
        }
        if !self.paths.iter().any(|held| held == path) {
            self.paths.push(path.to_path_buf());
        }
        Ok(self)
    }

    /// The protected directories, in the order they were declared.
    pub fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// Which protected directory a root overlaps, if any.
    ///
    /// Overlap is nesting in either direction: a root *inside* `data_dir` serves
    /// the box's secrets, and a root that *contains* `data_dir` serves them just
    /// as well one directory further down. Both are the same refusal.
    fn conflict(&self, root: &Path) -> Option<ShareError> {
        self.paths.iter().find(|protected| overlaps(root, protected)).map(|protected| {
            ShareError::ProtectedRoot { root: display(root), protected: display(protected) }
        })
    }
}

/// A checked SMB share name.
///
/// # Why a newtype, before the SMB backends exist
///
/// This string is not data — it is an **argument**. The plan has it reaching
/// `sharing -a <path> -S <name>` on macOS, `New-SmbShare -Name <name>` on
/// Windows, and a `[<name>]` stanza in `smb.conf` on Linux. An unchecked
/// `String` in that position is three injection surfaces: a name beginning with
/// `-` is an option rather than a value to every one of those commands, and a
/// name containing a newline is a second line of `smb.conf` — the reviewer built
/// `"-R\nguest ok = yes"`, which is both at once, and this type stored it
/// verbatim.
///
/// Checking it now, while the backends are still unwritten, is the cheap moment:
/// afterwards it is three call sites arguing about whose job it was, and the
/// quoting rules of three different shells.
///
/// # The rules
///
/// One to [`MAX_SMB_NAME_LEN`] characters of ASCII letters, digits, `-`, `_`,
/// `.` and space; first and last character alphanumeric; and the whole name must
/// also pass [`crate::path::validate_segment`], which is what rules out the
/// reserved device names, the trailing dot Windows silently strips, and the
/// colon that opens an alternate data stream. The leading-alphanumeric rule is
/// the one doing the security work: it is why no name can ever be read as an
/// option. Everything else keeps a name that is legal on one platform from being
/// illegal on the next.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SmbName(String);

impl SmbName {
    /// Checks a name, or says which rule it broke.
    pub fn parse(text: &str) -> Result<Self, ShareError> {
        let refuse =
            |problem| Err(ShareError::BadSmbName { name: text.to_string(), problem });

        let characters = text.chars().count();
        if characters == 0 {
            return refuse(SmbNameProblem::Empty);
        }
        if characters > MAX_SMB_NAME_LEN {
            return refuse(SmbNameProblem::TooLong);
        }
        if !text.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ')) {
            return refuse(SmbNameProblem::ForbiddenCharacter);
        }
        let edges_are_names = text.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
            && text.chars().next_back().is_some_and(|c| c.is_ascii_alphanumeric());
        if !edges_are_names {
            return refuse(SmbNameProblem::EdgeIsNotAlphanumeric);
        }
        if let Err(refusal) = path::validate_segment(text) {
            return refuse(SmbNameProblem::NotAFileName(refusal));
        }
        Ok(Self(text.to_string()))
    }

    /// The name as text, for the backend that has to pass it on.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SmbName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A checked share id, which is also the share's URL segment.
///
/// The character set is `[a-z0-9-]` and nothing else — no dots, no underscores,
/// no uppercase. That is narrow enough that an id can be pasted into a URL, a
/// filename, a DNS-SD instance name and an SMB share name without any of them
/// needing to escape it, which is worth more than the expressiveness given up.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShareId(String);

impl ShareId {
    /// Checks an id, or says why it is not one.
    pub fn parse(text: &str) -> Result<Self, ShareError> {
        let legal = !text.is_empty()
            && text.len() <= MAX_ID_LEN
            && text.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !legal {
            return Err(ShareError::BadId(text.to_string()));
        }
        if RESERVED_IDS.contains(&text) {
            return Err(ShareError::ReservedId(text.to_string()));
        }
        Ok(Self(text.to_string()))
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShareId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What a grant lets a person do, ordered from least to most.
///
/// Ordering is the whole point of the type: a `Write` grant satisfies a `Read`
/// want, and an `Admin` grant satisfies both. Deriving `PartialOrd` on a
/// declaration order chosen for exactly that reason means the check is a `>=`
/// rather than a match arm somebody will forget to extend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Mode {
    /// List and download.
    Read,
    /// Everything `Read` allows, plus create, overwrite, move and delete.
    Write,
    /// Everything `Write` allows, plus changing the share itself.
    Admin,
}

impl Mode {
    /// The wire and config spelling.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
        }
    }

    /// Reads a mode back from its spelling, for config and for the JSON API.
    pub fn from_tag(text: &str) -> Option<Self> {
        match text {
            "read" => Some(Self::Read),
            "write" => Some(Self::Write),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// What a caller is asking to do right now.
///
/// Distinct from [`Mode`] even though the variants line up, because a want is a
/// question and a mode is an answer. Collapsing them reads fine until the day a
/// want appears that no grant spells (`Want::Discover`, say), and then the two
/// meanings have to be pulled apart inside every call site that mixed them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    /// List a directory or read a file's bytes.
    Read,
    /// Create, overwrite, move or delete.
    Write,
    /// Change the share itself — its SMB export, its grants.
    Admin,
}

impl Want {
    /// The least grant that satisfies this want.
    fn required(self) -> Mode {
        match self {
            Self::Read => Mode::Read,
            Self::Write => Mode::Write,
            Self::Admin => Mode::Admin,
        }
    }
}

/// Who is asking.
///
/// This is [`selfhost_identity::Identity`] under the name this crate's
/// vocabulary uses for it — `Grantee::Owner` and `Grantee::Person(name)` are
/// that enum's own variants, not copies of them. An alias rather than a mirror
/// because a mirror is a second definition of "who", and the whole point of the
/// identity crate is that there is one: the owner is a variant nobody can spell
/// their way into, and a person's name is a [`PersonName`] that has been
/// checked.
///
/// It was a two-variant enum of this crate's own until `crates/identity` landed,
/// and the difference is not cosmetic. The placeholder's `Person(String)`
/// accepted the empty string, which matched an empty [`Grant::user`] and
/// therefore held whatever mode that grant named — an `admin` grant on a share,
/// belonging to nobody, satisfied by a caller with no name.
///
/// The alias is not permanent. When the routes are wired, [`Share::permits`]
/// takes `identity::Caller` — identity *and* the credential it was proved with,
/// because the policy has to be able to say "this is the owner, and nevertheless
/// this bearer token may not write".
pub type Grantee = Identity;

/// Why a share refused an operation, or that it did not.
///
/// Three outcomes rather than a `bool` because the caller answers each one
/// differently: a missing grant is `403` and worth an audit line, a read-only
/// share is `403` with prose the console can render as "this share is published
/// read-only", and an allowed operation continues. Collapsing them would make
/// the console say "forbidden" to an operator whose own configuration is the
/// reason, which reads as a bug in the product.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantOutcome {
    /// The caller may proceed.
    Allowed,
    /// The share is published read-only, so no caller may write to it — not
    /// even one holding an `admin` grant, and not even the owner. The flag is
    /// the operator's statement about the *data*, not about a person.
    ReadOnly,
    /// The caller holds no grant that reaches this want.
    NotGranted,
}

impl GrantOutcome {
    /// Whether the operation may proceed.
    pub fn allowed(self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// A per-person grant on one share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// The person's name, as it appears in the passkey registry — validated, so
    /// a grant can never belong to the empty string or to a spelling of
    /// `"owner"`.
    pub user: PersonName,
    /// What they may do.
    pub mode: Mode,
}

impl Grant {
    /// Reads a grant out of configuration text.
    ///
    /// The name goes through [`PersonName::parse`], so the refusal an operator
    /// sees for `user = ""` is the identity crate's own sentence rather than a
    /// second opinion invented here.
    pub fn parse(user: &str, mode: Mode) -> Result<Self, ShareError> {
        let user = PersonName::parse(user)
            .map_err(|problem| ShareError::BadGrantee { user: user.to_string(), problem })?;
        Ok(Self { user, mode })
    }
}

/// How a share is exported over SMB, when it is.
///
/// Held here rather than in the SMB backend so that `smb/plan.rs` can diff a
/// desired state against the live one without reading config a second time —
/// the same shape `crates/firewall` uses, where `rule::desired_rules` derives
/// what should exist and `diff` decides what to change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbExport {
    /// The share name the operating system advertises — checked, because it is
    /// an argument to three different commands. See [`SmbName`].
    pub name: SmbName,
    /// Require SMBv3 encryption. Older clients that cannot negotiate it are
    /// refused, which is the intended trade.
    pub encrypt: bool,
    /// Export read-only regardless of the share's own flag. The stricter of the
    /// two wins; see [`Share::smb_read_only`].
    pub read_only: bool,
}

/// A share, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    id: ShareId,
    root: PathBuf,
    read_only: bool,
    browsable: bool,
    quota_bytes: Option<u64>,
    smb: Option<SmbExport>,
    grants: Vec<Grant>,
}

impl Share {
    /// Checks a declared share, including where it is rooted.
    ///
    /// The root must be absolute, must not be a filesystem root, must contain no
    /// `..` component, and must not overlap anything in `reserved`. Those four
    /// rules are the whole of the answer to "what can this share reach", and
    /// they are checked here rather than delegated, because the resolver in
    /// [`crate::path`] confines every request to whatever root it is handed —
    /// perfectly, and to `/etc/passwd` if that is what the root contains. The
    /// module documentation tells that story at length; this is where it is
    /// enforced.
    ///
    /// `reserved` is a parameter rather than a lookup so that no construction
    /// path can miss it: a test fixture, a future API and a hand-built literal
    /// all have to say what this deployment protects before they get a `Share`.
    ///
    /// What is *not* done here is canonicalisation, because this constructor is
    /// pure and canonicalising is a filesystem call. Two roots that are the same
    /// directory by way of a symlink still pass every rule above. The filesystem
    /// layer canonicalises each root once at startup and compares every walk
    /// against the result, which is the check that closes it.
    pub fn new(
        reserved: &Reserved,
        id: &str,
        root: impl Into<PathBuf>,
        read_only: bool,
        browsable: bool,
        quota_bytes: Option<u64>,
    ) -> Result<Self, ShareError> {
        let id = ShareId::parse(id)?;
        let root = root.into();
        if !root.is_absolute() {
            return Err(ShareError::RelativeRoot(display(&root)));
        }
        if has_traversal(&root) {
            return Err(ShareError::TraversalInRoot(display(&root)));
        }
        // A filesystem root is the one path with no parent: `/` on unix, `C:\`
        // or `\\?\C:\` on Windows. Checked by shape rather than by spelling, so
        // no platform's way of writing it is missed.
        if root.parent().is_none() {
            return Err(ShareError::FilesystemRoot(display(&root)));
        }
        if let Some(conflict) = reserved.conflict(&root) {
            return Err(conflict);
        }
        Ok(Self {
            id,
            root,
            read_only,
            browsable,
            quota_bytes,
            smb: None,
            grants: Vec::new(),
        })
    }

    /// Attaches an SMB export, replacing any previous one.
    pub fn with_smb(mut self, smb: SmbExport) -> Self {
        self.smb = Some(smb);
        self
    }

    /// Attaches the per-person grants, replacing any previous list.
    pub fn with_grants(mut self, grants: Vec<Grant>) -> Self {
        self.grants = grants;
        self
    }

    /// The share's id, which is also its URL segment.
    pub fn id(&self) -> &ShareId {
        &self.id
    }

    /// The directory this share exports, exactly as configured.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Whether the share refuses every write.
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Whether the share may be advertised over DNS-SD.
    pub fn browsable(&self) -> bool {
        self.browsable
    }

    /// The configured ceiling on bytes stored, if any.
    pub fn quota_bytes(&self) -> Option<u64> {
        self.quota_bytes
    }

    /// The SMB export, if the operator asked for one.
    pub fn smb(&self) -> Option<&SmbExport> {
        self.smb.as_ref()
    }

    /// The per-person grants, in declaration order.
    pub fn grants(&self) -> &[Grant] {
        &self.grants
    }

    /// Whether the SMB export is read-only.
    ///
    /// The stricter of the two flags wins. An operator who marked the share
    /// read-only and then wrote `read_only = false` under `[shares.smb]` has
    /// contradicted themselves, and the safe reading of a contradiction about
    /// write access is the one that refuses writes.
    pub fn smb_read_only(&self) -> bool {
        self.read_only || self.smb.as_ref().is_none_or(|smb| smb.read_only)
    }

    /// Decides whether a caller may do something on this share.
    ///
    /// The read-only flag is checked **before** grants, so the answer to "may I
    /// write to a read-only share?" is the same for everybody including the
    /// owner. That ordering is the difference between a flag that describes the
    /// data and a flag that describes a permission level, and the operator wrote
    /// it meaning the former.
    ///
    /// A caller with no matching grant is refused, with one exception that is
    /// the current reality of the deployment rather than a policy: the owner
    /// holds every capability, because the owner *is* the credential that
    /// configures the box. Taking that away would mean an operator could lock
    /// themselves out of their own storage by editing a grant list.
    pub fn permits(&self, caller: &Grantee, want: Want) -> GrantOutcome {
        if self.read_only && want != Want::Read {
            return GrantOutcome::ReadOnly;
        }

        let held = match caller {
            Grantee::Owner => Some(Mode::Admin),
            Grantee::Person(name) => self.grant_for(name.as_str()),
        };

        match held {
            Some(mode) if mode >= want.required() => GrantOutcome::Allowed,
            _ => GrantOutcome::NotGranted,
        }
    }

    /// The strongest mode granted to a named person, if any.
    ///
    /// Strongest rather than first, so a duplicated name in configuration cannot
    /// quietly *weaken* an operator's intent depending on the order they typed
    /// the blocks in.
    ///
    /// Takes text rather than a [`PersonName`] because the question is often
    /// asked about a name that arrived from outside — a form field, a header, a
    /// row in a listing. That is safe in exactly one direction: every stored
    /// grant holds a name that has been through [`PersonName::parse`], so a
    /// string that could never be a person's name matches nothing, and the empty
    /// string is one of those.
    pub fn grant_for(&self, user: &str) -> Option<Mode> {
        self.grants.iter().filter(|g| g.user.as_str() == user).map(|g| g.mode).max()
    }
}

/// Every share this box serves, as one checked set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Shares {
    shares: Vec<Share>,
}

impl Shares {
    /// Checks a whole set: no duplicate ids, no nested roots.
    ///
    /// Order is preserved, because it is the order the operator wrote and
    /// therefore the order the console should list them in. An alphabetical sort
    /// here would silently disagree with the config file.
    pub fn new(shares: Vec<Share>) -> Result<Self, ShareError> {
        for (index, share) in shares.iter().enumerate() {
            for other in &shares[index + 1..] {
                if share.id == other.id {
                    return Err(ShareError::DuplicateId(share.id.to_string()));
                }
                if let Some(error) = nesting_error(share.root(), other.root()) {
                    return Err(error);
                }
            }
        }
        Ok(Self { shares })
    }

    /// The shares, in declaration order.
    pub fn all(&self) -> &[Share] {
        &self.shares
    }

    /// Whether any share is declared at all.
    ///
    /// Absent shares mean the subsystem does not exist: no route is served and
    /// nothing is advertised. That is the default and it is not an error.
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    /// How many shares are declared.
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Finds a share by the id in a URL.
    ///
    /// The lookup takes raw text and parses it, so an id that could never be
    /// legal is a miss rather than a scan — and a caller cannot accidentally
    /// look up an unvalidated string.
    pub fn find(&self, id: &str) -> Option<&Share> {
        let id = ShareId::parse(id).ok()?;
        self.shares.iter().find(|share| share.id == id)
    }
}

/// Whether either root contains the other, and which way round.
///
/// Symlinks are not considered, because this is pure. Two roots that are the
/// same directory by way of a symlink are caught at startup, when the filesystem
/// layer canonicalises each root and compares the results.
fn nesting_error(first: &Path, second: &Path) -> Option<ShareError> {
    if !overlaps(first, second) {
        return None;
    }
    let (outer, inner) =
        if second.starts_with(first) { (first, second) } else { (second, first) };
    Some(ShareError::NestedRoots { outer: display(outer), inner: display(inner) })
}

/// Whether two directories are the same one, or one is inside the other.
///
/// Comparison is on whole path components (`Path::starts_with`), not on text, so
/// `/srv/vault-two` is not "inside" `/srv/vault`. A textual `starts_with` gets
/// that wrong, and getting it wrong here refuses a configuration the operator
/// wrote correctly — a bug that looks like the product simply not working.
///
/// **The precondition is that neither path holds a `..`**, and it is not
/// defensive to say so: components do not cancel, so `/srv/vault` and
/// `/srv/other/../vault` compare as unrelated while naming one directory. Both
/// callers guarantee it — [`Share::new`] refuses such a root and
/// [`Reserved::and`] refuses such a protected path — which is why this function
/// can be a comparison rather than a normaliser.
fn overlaps(first: &Path, second: &Path) -> bool {
    first.starts_with(second) || second.starts_with(first)
}

/// Whether a path holds a `..` component, in any position.
///
/// `Components` reports `.` and `..` as `CurDir`/`ParentDir` rather than as
/// names, so this sees the traversal however it was spelled — including
/// `/srv/../srv` and a trailing `/srv/vault/..`. A `.` is not looked for,
/// because `Components` drops it and it changes nothing about what a path names.
fn has_traversal(path: &Path) -> bool {
    path.components().any(|component| component == Component::ParentDir)
}

/// A path as text for an error message.
///
/// Lossy on purpose: this is going into a message an operator reads about their
/// own configuration file, and a non-UTF-8 root is a strange enough thing that
/// showing the replacement character is more useful than refusing to describe it.
fn display(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// Resolves a request path inside a share, in one step.
///
/// A convenience over [`path::resolve`] that exists so no caller has to remember
/// to pass the *share's* root — passing the wrong root is the one mistake this
/// module can make that the path resolver cannot catch, since the resolver
/// confines to whatever root it is given.
pub fn resolve_in(share: &Share, request_path: &str) -> Result<path::Resolved, Refusal> {
    path::resolve(share.root(), request_path)
}


#[cfg(test)]
mod tests {
    use super::*;

    /// What a deployment of this box protects: the daemon's data directory —
    /// which holds `admin.token`, the session store and the TLS keys under
    /// `tls/` — and the checkout the self-updater builds and restarts from.
    fn reserved() -> Reserved {
        Reserved::new("/var/lib/selfhost", Some(Path::new("/opt/self-host")))
            .expect("both fixtures are absolute and free of '..'")
    }

    fn share(id: &str, root: &str) -> Share {
        Share::new(&reserved(), id, root, false, true, None).expect("fixture must be legal")
    }

    fn person(name: &str) -> Grantee {
        Grantee::Person(PersonName::parse(name).expect("fixture must be a legal name"))
    }

    fn grant(user: &str, mode: Mode) -> Grant {
        Grant::parse(user, mode).expect("fixture must be a legal name")
    }

    #[test]
    fn ids_are_url_segments_and_nothing_else() {
        assert!(ShareId::parse("vault").is_ok());
        assert!(ShareId::parse("photos-2026").is_ok());
        assert!(ShareId::parse("a").is_ok());

        for bad in ["", "Vault", "va ult", "va/ult", "va.ult", "va_ult", "vä"] {
            assert_eq!(
                ShareId::parse(bad),
                Err(ShareError::BadId(bad.to_string())),
                "{bad:?} should not be a share id"
            );
        }

        let too_long = "a".repeat(MAX_ID_LEN + 1);
        assert_eq!(ShareId::parse(&too_long), Err(ShareError::BadId(too_long)));
        assert!(ShareId::parse(&"a".repeat(MAX_ID_LEN)).is_ok());
    }

    #[test]
    fn an_id_may_not_shadow_a_path_the_console_serves() {
        for reserved in RESERVED_IDS {
            assert_eq!(
                ShareId::parse(reserved),
                Err(ShareError::ReservedId(reserved.to_string())),
                "{reserved:?} would shadow the console"
            );
        }

        // `well-known` is not on the list any more, and does not need to be: the
        // console serves `/.well-known`, and a leading dot is not a legal id in
        // the first place.
        assert!(ShareId::parse("well-known").is_ok());
        assert_eq!(
            ShareId::parse(".well-known"),
            Err(ShareError::BadId(".well-known".to_string()))
        );
    }

    #[test]
    fn a_root_must_be_absolute() {
        let relative = Share::new(&reserved(), "vault", "shares/vault", false, true, None);
        assert_eq!(relative, Err(ShareError::RelativeRoot("shares/vault".to_string())));
    }

    #[test]
    fn a_set_refuses_duplicates_and_nesting() {
        let ok = Shares::new(vec![share("a", "/srv/a"), share("b", "/srv/b")]);
        assert!(ok.is_ok());

        assert_eq!(
            Shares::new(vec![share("a", "/srv/a"), share("a", "/srv/b")]),
            Err(ShareError::DuplicateId("a".to_string()))
        );

        assert_eq!(
            Shares::new(vec![share("a", "/srv/a"), share("b", "/srv/a/inner")]),
            Err(ShareError::NestedRoots {
                outer: "/srv/a".to_string(),
                inner: "/srv/a/inner".to_string()
            })
        );

        // Order does not matter: the inner root declared first is the same
        // ambiguity.
        assert_eq!(
            Shares::new(vec![share("b", "/srv/a/inner"), share("a", "/srv/a")]),
            Err(ShareError::NestedRoots {
                outer: "/srv/a".to_string(),
                inner: "/srv/a/inner".to_string()
            })
        );

        // Identical roots are nesting in both directions, and refused.
        assert!(Shares::new(vec![share("a", "/srv/a"), share("b", "/srv/a")]).is_err());
    }

    #[test]
    fn a_shared_prefix_is_not_nesting() {
        // Textual `starts_with` says `/srv/vault-two` is inside `/srv/vault`.
        // Component-wise it is not, and refusing it would reject a correct
        // configuration.
        assert!(Shares::new(vec![share("a", "/srv/vault"), share("b", "/srv/vault-two")]).is_ok());
    }

    #[test]
    fn the_owner_holds_everything_except_a_write_to_a_read_only_share() {
        let writable = share("vault", "/srv/vault");
        for want in [Want::Read, Want::Write, Want::Admin] {
            assert_eq!(writable.permits(&Grantee::Owner, want), GrantOutcome::Allowed);
        }

        let published =
            Share::new(&reserved(), "pub", "/srv/pub", true, true, None).expect("legal");
        assert_eq!(published.permits(&Grantee::Owner, Want::Read), GrantOutcome::Allowed);
        assert_eq!(published.permits(&Grantee::Owner, Want::Write), GrantOutcome::ReadOnly);
        assert_eq!(published.permits(&Grantee::Owner, Want::Admin), GrantOutcome::ReadOnly);
    }

    #[test]
    fn a_grant_satisfies_every_want_at_or_below_it() {
        let vault = share("vault", "/srv/vault").with_grants(vec![
            grant("reader", Mode::Read),
            grant("writer", Mode::Write),
            grant("supervisor", Mode::Admin),
        ]);

        let table = [
            ("reader", Want::Read, GrantOutcome::Allowed),
            ("reader", Want::Write, GrantOutcome::NotGranted),
            ("reader", Want::Admin, GrantOutcome::NotGranted),
            ("writer", Want::Read, GrantOutcome::Allowed),
            ("writer", Want::Write, GrantOutcome::Allowed),
            ("writer", Want::Admin, GrantOutcome::NotGranted),
            ("supervisor", Want::Read, GrantOutcome::Allowed),
            ("supervisor", Want::Write, GrantOutcome::Allowed),
            ("supervisor", Want::Admin, GrantOutcome::Allowed),
            ("stranger", Want::Read, GrantOutcome::NotGranted),
            ("stranger", Want::Write, GrantOutcome::NotGranted),
        ];

        for (user, want, expected) in table {
            assert_eq!(vault.permits(&person(user), want), expected, "{user} wanting {want:?}");
        }
    }

    #[test]
    fn a_duplicated_name_takes_the_strongest_grant() {
        let vault = share("vault", "/srv/vault").with_grants(vec![
            grant("alex", Mode::Read),
            grant("alex", Mode::Admin),
            grant("alex", Mode::Read),
        ]);
        assert_eq!(vault.grant_for("alex"), Some(Mode::Admin));
        assert_eq!(vault.grant_for("nobody"), None);
    }

    #[test]
    fn read_only_is_checked_before_the_grant_list() {
        // An `admin` grant does not override the operator's statement that the
        // data is published read-only.
        let published = Share::new(&reserved(), "pub", "/srv/pub", true, true, None)
            .expect("legal")
            .with_grants(vec![grant("alex", Mode::Admin)]);
        assert_eq!(published.permits(&person("alex"), Want::Write), GrantOutcome::ReadOnly);
    }

    #[test]
    fn the_stricter_smb_flag_wins() {
        let export = |read_only| SmbExport {
            name: SmbName::parse("Vault").expect("a legal export name"),
            encrypt: true,
            read_only,
        };

        assert!(!share("vault", "/srv/vault").with_smb(export(false)).smb_read_only());
        assert!(share("vault", "/srv/vault").with_smb(export(true)).smb_read_only());

        let published =
            Share::new(&reserved(), "pub", "/srv/pub", true, true, None).expect("legal");
        assert!(published.clone().with_smb(export(false)).smb_read_only());
        // No export at all reads as read-only, which is the safe answer for a
        // question about a thing that does not exist.
        assert!(published.smb_read_only());
    }

    #[test]
    fn a_lookup_takes_untrusted_text() {
        let shares = Shares::new(vec![share("vault", "/srv/vault")]).expect("legal");
        assert!(shares.find("vault").is_some());
        assert!(shares.find("VAULT").is_none());
        assert!(shares.find("../vault").is_none());
        assert!(shares.find("").is_none());
        assert_eq!(shares.len(), 1);
        assert!(!shares.is_empty());
        assert!(Shares::default().is_empty());
    }

    #[test]
    fn resolution_confines_to_the_shares_own_root() {
        let vault = share("vault", "/srv/vault");
        let resolved = resolve_in(&vault, "/notes/today.txt").expect("a legal name");
        assert_eq!(resolved.textual_path(), Path::new("/srv/vault/notes/today.txt"));
        assert_eq!(resolve_in(&vault, "/../secrets"), Err(Refusal::Traversal));
    }

    #[test]
    fn modes_round_trip_through_their_spelling() {
        for mode in [Mode::Read, Mode::Write, Mode::Admin] {
            assert_eq!(Mode::from_tag(mode.tag()), Some(mode));
            assert_eq!(mode.to_string(), mode.tag());
        }
        assert_eq!(Mode::from_tag("owner"), None);
        assert_eq!(Mode::from_tag(""), None);
    }

    #[test]
    fn errors_explain_themselves() {
        for error in [
            ShareError::BadId("Vault".to_string()),
            ShareError::ReservedId("api".to_string()),
            ShareError::DuplicateId("a".to_string()),
            ShareError::RelativeRoot("x".to_string()),
            ShareError::FilesystemRoot("/".to_string()),
            ShareError::TraversalInRoot("/srv/../..".to_string()),
            ShareError::ProtectedRoot {
                root: "/opt/self-host".to_string(),
                protected: "/opt/self-host".to_string(),
            },
            ShareError::UnusableProtectedPath("data".to_string()),
            ShareError::NestedRoots { outer: "/a".to_string(), inner: "/a/b".to_string() },
            ShareError::BadSmbName {
                name: "-R".to_string(),
                problem: SmbNameProblem::EdgeIsNotAlphanumeric,
            },
            ShareError::BadSmbName {
                name: "CON".to_string(),
                problem: SmbNameProblem::NotAFileName(Refusal::ReservedDeviceName),
            },
            ShareError::BadGrantee {
                user: String::new(),
                problem: InvalidPersonName::Empty,
            },
        ] {
            assert!(!error.to_string().is_empty());
        }
        assert!(GrantOutcome::Allowed.allowed());
        assert!(!GrantOutcome::ReadOnly.allowed());
        assert!(!GrantOutcome::NotGranted.allowed());
    }

    // -----------------------------------------------------------------------
    // Adversarial review, 2026-08-10, and its answers.
    //
    // `path.rs` confines a request to whatever root it is handed, and a
    // combinatorial sweep in that module's tests shows it does so without
    // exception. So the way to read `/etc/passwd` through this NAS was never to
    // defeat the resolver. It was to be handed a root that already contains the
    // answer — and nothing checked the root.
    //
    // The four tests below were the reviewer's proof that each hole was live.
    // They now assert the refusal, which is the same proof read the other way
    // round: if any of them starts failing, the hole is open again.
    // -----------------------------------------------------------------------

    /// A share may not be rooted at the filesystem root.
    ///
    /// `Share::new("vault", "/", …)` used to return `Ok`, because the only rule
    /// about a root was that it be absolute and `/` is absolute. Every rule in
    /// `path.rs` then worked exactly as designed and handed back `/etc/passwd`,
    /// with no traversal involved and no refusal anywhere: the confinement was
    /// working, and the thing it confined to was the whole disk.
    #[test]
    fn a_share_may_not_be_rooted_at_the_entire_filesystem() {
        assert_eq!(
            Share::new(&reserved(), "vault", "/", false, true, None),
            Err(ShareError::FilesystemRoot("/".to_string()))
        );

        // The rule is on the *shape* of the path, so a root with no parent is
        // refused however the platform spells it, and a directory one level
        // down is fine.
        assert!(Share::new(&reserved(), "vault", "/srv", false, true, None).is_ok());
    }

    /// A share may not be rooted at the checkout the box rebuilds itself from,
    /// nor anywhere that would expose the key store or the bearer token.
    ///
    /// The module documentation always said a root inside the repository "is a
    /// write primitive that becomes code execution on the next push". It was
    /// right, and nothing enforced it: the same root also exposed `data/tls`,
    /// which on this checkout holds the certificate store, and
    /// `data/admin.token`, the deployment's root bearer credential — readable
    /// through an ordinary `GET` with no refusal anywhere in the stack.
    #[test]
    fn a_share_may_not_be_rooted_at_the_self_updating_checkout_or_its_key_store() {
        let reserved = reserved();

        for root in [
            "/opt/self-host",           // the checkout itself
            "/opt/self-host/data/tls",  // the private keys
            "/opt/self-host/sites",     // any directory inside it
            "/var/lib/selfhost",        // data_dir itself
            "/var/lib/selfhost/tls",    // the store inside data_dir
            "/opt",                     // a root that *contains* the checkout
            "/var",                     // a root that contains data_dir
        ] {
            let refused = Share::new(&reserved, "vault", root, false, true, None);
            assert!(
                matches!(refused, Err(ShareError::ProtectedRoot { .. })),
                "{root} must be refused, got {refused:?}"
            );
        }

        // A neighbour of a protected directory is not inside it, and is fine —
        // the check is component-wise, so `/var/lib/selfhost-backups` is not
        // `/var/lib/selfhost`.
        assert!(Share::new(&reserved, "vault", "/srv/vault", false, true, None).is_ok());
        assert!(Share::new(&reserved, "vault", "/var/lib/selfhost-backups", false, true, None)
            .is_ok());
    }

    /// A root may not contain `..`, which escaped the directory the operator
    /// named and simultaneously defeated the nesting check.
    ///
    /// `is_absolute()` is true for `/srv/vault/../..`, so the constructor used
    /// to accept it, and `path::resolve` joins onto it verbatim — it is pure, so
    /// it cannot normalise and does not try. The result was a `textual_path`
    /// that the operating system resolves to `/etc/passwd`.
    ///
    /// The second half was worse, because it broke an invariant this module
    /// *states* rather than merely failing to add one: components do not cancel,
    /// so two roots that are provably the same directory passed the nesting
    /// check, and one share could be read-only with no grants while the other
    /// was writable with an admin grant over the same bytes.
    #[test]
    fn a_root_containing_dot_dot_is_refused_so_the_nesting_check_can_be_trusted() {
        for escaping in ["/srv/vault/../..", "/srv/other/../vault", "/srv/vault/.."] {
            assert_eq!(
                Share::new(&reserved(), "vault", escaping, false, true, None),
                Err(ShareError::TraversalInRoot(escaping.to_string())),
                "{escaping} must be refused"
            );
        }

        // The pair that used to name one directory and pass as two cannot be
        // built at all now, so the ambiguity has nowhere to appear.
        assert!(Share::new(&reserved(), "priv", "/srv/other/../vault", false, true, None).is_err());

        // And the same two roots written honestly are caught by the nesting
        // rule, which is the guarantee that was being undermined.
        let published =
            Share::new(&reserved(), "pub", "/srv/vault", true, true, None).expect("legal");
        let writable =
            Share::new(&reserved(), "priv", "/srv/vault", false, true, None).expect("legal");
        assert!(matches!(
            Shares::new(vec![published, writable]),
            Err(ShareError::NestedRoots { .. })
        ));

        // A protected directory has the same rule, for the same reason: it is
        // one side of the same comparison.
        assert_eq!(
            Reserved::new("/var/lib/../var/lib/selfhost", None),
            Err(ShareError::UnusableProtectedPath("/var/lib/../var/lib/selfhost".to_string()))
        );
        assert_eq!(
            Reserved::new("data", None),
            Err(ShareError::UnusableProtectedPath("data".to_string()))
        );
    }

    /// An SMB export name is never an argument, and a grant never belongs to
    /// nobody.
    ///
    /// The reviewer built a share whose SMB name was `"-R\nguest ok = yes"` —
    /// an option to `sharing -a` and a second line of `smb.conf` at once — and
    /// this type stored it verbatim, inside a value whose whole claim is that it
    /// has been checked. The grant list had the mirror-image gap: the empty
    /// string was a grantee, and `permits` answered `Allowed` for an `admin`
    /// want by a caller with no name.
    ///
    /// Both are closed at the type, before the SMB backends exist to consume
    /// them, because afterwards it is three call sites arguing about whose job
    /// it was.
    #[test]
    fn an_smb_name_is_never_an_argument_and_a_grant_never_belongs_to_nobody() {
        let hostile = [
            // The reviewer's name: an option to two of the three commands and a
            // second line of `smb.conf` at the same time.
            ("-R\nguest ok = yes", SmbNameProblem::ForbiddenCharacter),
            ("vault\nguest ok = yes", SmbNameProblem::ForbiddenCharacter),
            ("vault; rm -rf /", SmbNameProblem::ForbiddenCharacter),
            ("vault$(whoami)", SmbNameProblem::ForbiddenCharacter),
            ("[global]", SmbNameProblem::ForbiddenCharacter),
            ("va:ult", SmbNameProblem::ForbiddenCharacter),
            ("vault\u{7f}", SmbNameProblem::ForbiddenCharacter),
            // Nothing that could be read as an option survives the edge rule.
            ("-R", SmbNameProblem::EdgeIsNotAlphanumeric),
            ("--recursive", SmbNameProblem::EdgeIsNotAlphanumeric),
            (" vault", SmbNameProblem::EdgeIsNotAlphanumeric),
            ("vault ", SmbNameProblem::EdgeIsNotAlphanumeric),
            ("vault.", SmbNameProblem::EdgeIsNotAlphanumeric),
            ("", SmbNameProblem::Empty),
            // And a name that is legal by every rule above but is still a device
            // on Windows is caught by the resolver, whose reason is carried
            // through rather than restated.
            ("CON", SmbNameProblem::NotAFileName(Refusal::ReservedDeviceName)),
        ];
        for (name, expected) in hostile {
            assert_eq!(
                SmbName::parse(name),
                Err(ShareError::BadSmbName { name: name.to_string(), problem: expected }),
                "{name:?} must be refused as an export name"
            );
        }

        let over_long = "a".repeat(MAX_SMB_NAME_LEN + 1);
        assert_eq!(
            SmbName::parse(&over_long),
            Err(ShareError::BadSmbName {
                name: over_long,
                problem: SmbNameProblem::TooLong
            })
        );

        for legal in ["Vault", "Family Photos", "vault-2026", "a", &"a".repeat(MAX_SMB_NAME_LEN)] {
            let name = SmbName::parse(legal).unwrap_or_else(|e| panic!("{legal:?}: {e}"));
            assert_eq!(name.as_str(), legal);
            assert_eq!(name.to_string(), legal);
        }

        // A grantee is a person or it is nothing. The empty string is refused
        // where it is written, so it can never reach a grant list.
        assert!(matches!(
            Grant::parse("", Mode::Admin),
            Err(ShareError::BadGrantee { problem: InvalidPersonName::Empty, .. })
        ));
        assert!(matches!(
            Grant::parse("owner", Mode::Admin),
            Err(ShareError::BadGrantee { problem: InvalidPersonName::ReservedOwnerName, .. })
        ));

        // And the lookup that used to match it answers for nobody.
        let vault = share("vault", "/srv/vault").with_grants(vec![grant("alex", Mode::Admin)]);
        assert_eq!(vault.grant_for(""), None);
        assert_eq!(vault.grant_for("alex"), Some(Mode::Admin));
    }

    /// A deployment says what it protects once, and every share is measured
    /// against that statement.
    #[test]
    fn what_is_protected_is_stated_by_the_deployment_not_guessed_here() {
        let reserved = reserved();
        assert_eq!(
            reserved.paths(),
            [PathBuf::from("/var/lib/selfhost"), PathBuf::from("/opt/self-host")]
        );

        // A deployment with no checkout says so, and still protects its data.
        let packaged = Reserved::new("/var/lib/selfhost", None).expect("legal");
        assert_eq!(packaged.paths(), [PathBuf::from("/var/lib/selfhost")]);
        assert!(Share::new(&packaged, "vault", "/opt/self-host", false, true, None).is_ok());
        assert!(Share::new(&packaged, "vault", "/var/lib/selfhost", false, true, None).is_err());

        // Anything else a deployment wants covered is added, and adding the same
        // directory twice is not an error — it is the same statement.
        let extended = packaged.clone().and("/var/backups").expect("legal").and("/var/backups");
        assert_eq!(
            extended.expect("legal").paths(),
            [PathBuf::from("/var/lib/selfhost"), PathBuf::from("/var/backups")]
        );
    }
}
