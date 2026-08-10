//! What the operating system's SMB server should export, and how that differs
//! from what it exports now.
//!
//! **Pure.** Nothing here spawns a process, reads a file, or touches a share
//! point. It is the half of the SMB driver that holds the rules, and it holds
//! them so that a backend cannot break them by accident — the same division
//! [`selfhost_firewall::rule`](../../../selfhost_firewall/rule/index.html) draws
//! against its backends, for the same reason: the interesting decisions are the
//! ones worth asserting, and a decision that can only be observed by running
//! `sharing` on a Mac is a decision nobody asserts twice.
//!
//! # The three rules, and where each is actually enforced
//!
//! The module documentation on [`crate::smb`] states the rules. This is where
//! they stop being prose:
//!
//! 1. **Guest access is refused and is not configurable.** There is no guest
//!    field on [`DesiredShare`], and [`DesiredShare`] is the *only* thing a
//!    backend is handed — so "export this to anyone who asks" is not a sentence
//!    this crate's types can say. A live share point the deployment owns which
//!    somehow has guest access on is put in [`Reconciliation::update`], so a
//!    reconcile repairs it rather than tolerating it.
//! 2. **Never touch a share point we did not create.** [`Reconciliation::remove`]
//!    is a `Vec<SmbName>` built by intersecting [`Owned`] — the names this
//!    deployment recorded creating — with what the host actually exports. A
//!    [`LiveShare`] read back from the host carries its name as a plain `String`
//!    and there is no route from that `String` into a removal, because
//!    [`crate::smb::SmbBackend::reconcile`] only ever removes an [`SmbName`] and
//!    the only `SmbName`s in a plan came from configuration or from the ledger.
//!    A pre-existing share point is reported in [`Reconciliation::untouched`]
//!    for display and appears in no actionable list at all.
//! 3. **Nothing reaches a command line unchecked.** [`DesiredShare`] can only be
//!    built by [`desired_exports`], which refuses a root that is not absolute,
//!    not UTF-8, or holds a control character — the three ways a directory path
//!    could become an option to `sharing`, a second line of `smb.conf`, or an
//!    unquotable argument. The name arrived as an [`SmbName`] and was checked
//!    when the share was constructed.
//!
//! # Why ownership is recorded rather than inferred
//!
//! A firewall backend can recognise its own rules because it puts them in its
//! own table, anchor, or name prefix. An SMB share point cannot be marked that
//! way: its name is the name the operator chose and the name their colleagues
//! will see in Finder, so it cannot carry a prefix, and macOS's `sharing` has no
//! comment field to hide a marker in. Ownership is therefore *remembered*: the
//! set of names this deployment created is written down (see
//! [`crate::smb::OwnershipLedger`]) and read back before every diff.
//!
//! The failure modes of that choice both fall the safe way. A lost ledger means
//! we forget we own a share and stop removing it — the share stays up, which is
//! visible and fixable. A ledger naming something we did not create cannot be
//! produced by this code, and even if hand-written it names a share the operator
//! themselves wrote into the ledger file.

use crate::share::{Share, SmbName, Shares};
use selfhost_json::Json;
use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;

/// The port the SMB service listens on, on every platform this drives.
///
/// Stated here because it is the number that matters most to a reader of this
/// module and appears nowhere else in the project: enabling an SMB export means
/// the operating system listens on `445` across every interface it is bound to.
/// This crate never binds it — see [`crate::smb`] for what that does and does
/// not mean for a box with a public IP.
pub const SMB_PORT: u16 = 445;

/// The sentence the console must show beside any SMB pane.
///
/// Shipped as data rather than left to each front end to phrase, and carried in
/// [`SmbState::to_json`], so a plate cannot render the SMB state without also
/// having the one caveat that turns a bug report into an expectation. The web
/// SPA and the native console are separate implementations by design; a
/// sentence duplicated in two languages is a sentence that drifts.
pub const AUTHENTICATION_NOTICE: &str = "SMB authenticates against operating-system \
    accounts (NTLM, Kerberos, smbpasswd). The console password cannot open an SMB \
    session on any platform. Guest access is refused and is not configurable.";

/// Why a desired export could not be derived from configuration.
///
/// Every variant is a refusal to build a command line out of something that
/// would not survive being on one. None of them can be reached from a
/// configuration file that `selfhost-config` accepted — they are the second
/// opinion that makes the guarantee true for a `Share` built by any other route,
/// which is the same argument [`crate::share::Shares::new`] makes for re-checking
/// what validation already checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlanError {
    /// A share root is not an absolute path, so it could be read as an option.
    RelativeRoot {
        /// The export whose root was refused.
        name: String,
        /// The root, as text.
        root: String,
    },
    /// A share root is not valid UTF-8 and so cannot be checked or quoted.
    NonUtf8Root {
        /// The export whose root was refused.
        name: String,
    },
    /// A share root holds a control character — a newline would be a second line
    /// of `smb.conf`, and the rest are unrepresentable in a command line.
    ControlCharacterInRoot {
        /// The export whose root was refused.
        name: String,
        /// The root, as text.
        root: String,
    },
    /// A line in the ownership ledger is not a legal share name, so this
    /// deployment cannot have written it and cannot act on it.
    BadLedgerLine {
        /// The line, verbatim.
        line: String,
    },
}

impl fmt::Display for PlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelativeRoot { name, root } => write!(
                formatter,
                "the SMB export {name} is rooted at {root}, which is not an absolute path; \
                 a relative root cannot be handed to sharing, New-SmbShare or smb.conf"
            ),
            Self::NonUtf8Root { name } => write!(
                formatter,
                "the SMB export {name} is rooted at a path that is not valid UTF-8; \
                 rename the directory, or drop the [shares.smb] block"
            ),
            Self::ControlCharacterInRoot { name, root } => write!(
                formatter,
                "the SMB export {name} is rooted at {root:?}, which holds a control \
                 character; a newline in a path is a second line of smb.conf"
            ),
            Self::BadLedgerLine { line } => write!(
                formatter,
                "the SMB ownership ledger holds {line:?}, which is not a legal share name; \
                 this deployment cannot have created it, so the ledger is not trusted and \
                 nothing will be removed until the line is corrected or deleted"
            ),
        }
    }
}

impl std::error::Error for PlanError {}

/// One share this deployment wants the operating system to export.
///
/// The only value a backend is ever handed, and deliberately so. Its fields are
/// private and its only constructor is [`desired_exports`], which means three
/// things hold for every `DesiredShare` in existence:
///
/// - the name is an [`SmbName`], checked when the share was built;
/// - the root is absolute, UTF-8, and free of control characters;
/// - **there is no way to ask for guest access**, because there is no field for
///   it. That is the enforcement; the prose about it is only the explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredShare {
    name: SmbName,
    root: String,
    encrypt: bool,
    read_only: bool,
}

impl DesiredShare {
    /// The share name the operating system will advertise.
    pub fn name(&self) -> &SmbName {
        &self.name
    }

    /// The directory exported, as a path.
    pub fn root(&self) -> &Path {
        Path::new(&self.root)
    }

    /// The directory exported, as text a configuration file can hold.
    ///
    /// Safe to interpolate into an `smb.conf` stanza *because of where this
    /// value came from*: [`desired_exports`] refused it if it held a control
    /// character. There is no other constructor, so there is no other case.
    pub fn root_text(&self) -> &str {
        &self.root
    }

    /// Whether SMBv3 encryption is required, refusing clients that cannot
    /// negotiate it.
    pub fn encrypt(&self) -> bool {
        self.encrypt
    }

    /// Whether the export refuses writes.
    ///
    /// Already the stricter of the share's own flag and the export's — see
    /// [`Share::smb_read_only`] — so a backend does not get to re-decide it.
    pub fn read_only(&self) -> bool {
        self.read_only
    }
}

/// One share point the operating system currently exports, as a backend read it.
///
/// The name is a plain `String` and that is the point: a host exports whatever
/// names it was given, and this very Mac exports *"Alex Waldmann's Public
/// Folder"* — a name with a typographic apostrophe that [`SmbName::parse`]
/// refuses. Modelling a live name as an `SmbName` would mean either dropping
/// such a share from the reading (and then reporting a host state that is not
/// the host's state) or widening `SmbName` until it stopped being a guarantee.
///
/// A `String` cannot become a command argument anywhere in this module, because
/// no backend method accepts one. Reading is therefore total, and acting is
/// still typed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveShare {
    /// The share point's name, exactly as the host spells it.
    pub name: String,
    /// Other names the same share point answers to. macOS keeps a *record* name
    /// and an *SMB* name that an operator can set independently; this crate
    /// always sets them equal, so a divergence means the share point is somebody
    /// else's and the alias must still be seen by conflict detection.
    pub aliases: Vec<String>,
    /// The directory it exports, as the host reports it.
    pub path: String,
    /// Whether it is reachable without credentials.
    pub guest_access: bool,
    /// Whether it refuses writes.
    pub read_only: bool,
    /// Whether SMBv3 encryption is required on it.
    pub encrypted: bool,
    /// Whether SMB sharing is actually enabled for it — a macOS share point can
    /// exist with sharing switched off, which is not an export.
    pub shared: bool,
}

impl LiveShare {
    /// Whether this share point answers to `name` under any of its spellings.
    pub fn answers_to(&self, name: &str) -> bool {
        self.name == name || self.aliases.iter().any(|alias| alias == name)
    }

    /// Whether the host's state already matches what was asked for.
    ///
    /// Guest access is compared against `false` rather than against a desired
    /// value, because there is no desired value: an owned share point found with
    /// guest access on is out of date whatever else about it is right.
    fn satisfies(&self, desired: &DesiredShare) -> bool {
        self.shared
            && !self.guest_access
            && self.path == desired.root
            && self.read_only == desired.read_only
            && self.encrypted == desired.encrypt
    }
}

/// The share names this deployment created, and the only names it may remove.
///
/// Constructed from the ledger or from a previous plan, never from a reading of
/// the host — which is what makes "never touch a share point we did not create"
/// a property of the code rather than a promise about it. See the module
/// documentation for why ownership is remembered rather than recognised.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Owned {
    names: BTreeSet<SmbName>,
}

impl Owned {
    /// A deployment that has created nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Reads the ledger: one share name per line, blanks and `#` comments
    /// ignored.
    ///
    /// A line that is not a legal [`SmbName`] fails the whole read rather than
    /// being skipped. Skipping would silently narrow the set of things this
    /// deployment believes it owns, and the visible consequence of that is a
    /// share the operator asked to be removed staying up with no explanation. A
    /// refusal, by contrast, names the line.
    pub fn parse(text: &str) -> Result<Self, PlanError> {
        let mut names = BTreeSet::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let name = SmbName::parse(line)
                .map_err(|_| PlanError::BadLedgerLine { line: line.to_owned() })?;
            names.insert(name);
        }
        Ok(Self { names })
    }

    /// Renders the ledger, sorted, with the header that explains what it is.
    ///
    /// Sorted because the set is a `BTreeSet` and a file that reorders itself
    /// between writes is a file nobody can diff.
    pub fn to_text(&self) -> String {
        let mut out = String::from(
            "# Share points selfhost created, and the only ones it will ever remove.\n\
             # One name per line. Deleting a line makes selfhost forget it owns that\n\
             # share point, which means it will be left alone rather than removed.\n",
        );
        for name in &self.names {
            out.push_str(name.as_str());
            out.push('\n');
        }
        out
    }

    /// Whether this deployment created a share point of that name.
    pub fn contains(&self, name: &SmbName) -> bool {
        self.names.contains(name)
    }

    /// Every name owned, in sorted order.
    pub fn names(&self) -> impl Iterator<Item = &SmbName> {
        self.names.iter()
    }

    /// How many share points this deployment believes it created.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether this deployment believes it created nothing.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// The ledger with every name a plan is about to create claimed in advance.
    ///
    /// Written **before** the backend runs, which looks like the wrong order and
    /// is the right one. The failure this exists for is a reconcile that creates
    /// two share points and dies after the first: with the ledger written only at
    /// the end, this deployment would have made a share point and forgotten it,
    /// and the *next* run would find that name live, not owned, and report it as
    /// a [`Conflict`] — refusing to touch its own work until somebody edited the
    /// ledger by hand.
    ///
    /// Claiming early cannot claim somebody else's share point, and that is not a
    /// hope but a property of what is being claimed: [`Reconciliation::create`]
    /// holds only names the host was just observed *not* to have, because a name
    /// that was live and unowned went to `conflicts` instead. The worst case is a
    /// name claimed and never created, which the next diff puts in
    /// [`Reconciliation::forget`] and cleans up on its own.
    pub fn claiming(&self, plan: &Reconciliation) -> Self {
        let mut names = self.names.clone();
        for share in &plan.create {
            names.insert(share.name.clone());
        }
        // Every name in `update` is already owned — the diff cannot produce an
        // update for a share point this deployment did not create — so this loop
        // adds nothing today. It is here so that the claim stays complete if the
        // diff ever learns to adopt.
        for update in &plan.update {
            names.insert(update.desired.name.clone());
        }
        Self { names }
    }

    /// The ledger after a set of changes actually happened.
    ///
    /// Only [`Performed`] entries whose `applied` flag is set change anything, so
    /// a dry run leaves the ledger exactly as it was — which is what makes a dry
    /// run safe to do on a schedule.
    pub fn after(&self, performed: &[Performed]) -> Self {
        let mut names = self.names.clone();
        for step in performed.iter().filter(|step| step.applied) {
            match step.action {
                Action::Create | Action::Update => {
                    names.insert(step.name.clone());
                }
                Action::Remove | Action::Forget => {
                    names.remove(&step.name);
                }
            }
        }
        Self { names }
    }
}

/// A live share point that carries a configured export's name but was not
/// created by this deployment.
///
/// Neither adopted nor deleted. Adopting would mean silently taking over
/// somebody's existing sharing configuration and rewriting its flags; deleting
/// would mean destroying it to satisfy a config file that never mentioned it.
/// The operator is told, and picks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conflict {
    /// The configured export whose name is already taken.
    pub name: SmbName,
    /// Where the existing share point points, so the operator can tell at a
    /// glance whether it is the same directory.
    pub existing_path: String,
    /// Whether the existing share point is reachable without credentials. Worth
    /// surfacing on its own: a guest-accessible share point wearing the name of
    /// a share the operator meant to protect is the worst version of this.
    pub existing_guest_access: bool,
}

/// One share point that needs its flags or its directory corrected.
///
/// Carries the live path beside the desired one because the platforms differ on
/// whether that is an edit or a recreate: macOS's `sharing -e` cannot move a
/// share point and Windows's `Set-SmbShare` cannot change `-Path`, so both
/// backends need to see the old path to know which they are doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    /// What the export should be.
    pub desired: DesiredShare,
    /// Where the share point currently points.
    pub live_path: String,
    /// Whether it is currently reachable without credentials — the one
    /// difference that makes an update urgent rather than cosmetic.
    pub live_guest_access: bool,
}

impl Update {
    /// Whether correcting this means moving the share point to another
    /// directory, which every backend does by removing and recreating.
    pub fn path_moved(&self) -> bool {
        self.live_path != self.desired.root
    }
}

/// The per-share plan for converging the host's exports onto the configured set.
///
/// Read the fields as three groups: things to do ([`create`](Self::create),
/// [`update`](Self::update), [`remove`](Self::remove), [`forget`](Self::forget)),
/// things already right ([`keep`](Self::keep)), and things the operator must
/// decide about or simply be told ([`conflicts`](Self::conflicts),
/// [`untouched`](Self::untouched)).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Reconciliation {
    /// Configured exports the host does not have: create these.
    pub create: Vec<DesiredShare>,
    /// Owned share points whose flags or directory are wrong: correct these.
    pub update: Vec<Update>,
    /// Owned share points that already match: leave these alone.
    pub keep: Vec<DesiredShare>,
    /// Owned share points no longer configured: remove these.
    ///
    /// The only removable thing in the whole module, and it is an [`SmbName`]
    /// drawn from [`Owned`] — never from a reading of the host.
    pub remove: Vec<SmbName>,
    /// Names in the ledger that the host does not have and configuration does
    /// not want: drop them from the ledger. No host command is run for these;
    /// somebody removed the share point by hand and the ledger is catching up.
    pub forget: Vec<SmbName>,
    /// Configured exports whose name is already taken by a share point this
    /// deployment did not create.
    pub conflicts: Vec<Conflict>,
    /// Every other share point on the host, named for display only.
    ///
    /// These are `String`s and stay `String`s. No backend method in this module
    /// accepts a `String`, so there is no call that could act on one — the list
    /// exists so the console can say "four other share points, left alone"
    /// instead of leaving the operator to wonder whether we ate them.
    pub untouched: Vec<String>,
}

impl Reconciliation {
    /// Whether anything at all would change on the host.
    ///
    /// [`forget`](Self::forget) does not count: it changes only this
    /// deployment's own bookkeeping.
    pub fn changes_the_host(&self) -> bool {
        !self.create.is_empty() || !self.update.is_empty() || !self.remove.is_empty()
    }

    /// Whether the plan is entirely satisfied and there is nothing to do.
    pub fn is_settled(&self) -> bool {
        !self.changes_the_host() && self.forget.is_empty()
    }

    /// Every export that should exist once this plan has been performed.
    ///
    /// The union of [`keep`](Self::keep), [`create`](Self::create) and the
    /// desired half of [`update`](Self::update) — and deliberately **not**
    /// [`conflicts`](Self::conflicts), whose names belong to share points
    /// somebody else made.
    ///
    /// This is what a backend that rewrites a whole configuration file needs,
    /// rather than the deltas a backend that issues per-share commands needs.
    /// Samba is the former: it regenerates the file it owns, which is also why
    /// it cannot delete a stanza it did not write — a removal there is simply a
    /// stanza that is no longer emitted.
    pub fn desired_after(&self) -> Vec<&DesiredShare> {
        self.keep
            .iter()
            .chain(self.update.iter().map(|update| &update.desired))
            .chain(self.create.iter())
            .collect()
    }
}

/// Whether a reconcile writes to the host or only reports what it would write.
///
/// Dry run is the default everywhere it is offered, matching `selfhost dns sync`:
/// the operator sees the plan, then asks for it. A subsystem that changes the
/// machine on the strength of being invoked is a subsystem people stop invoking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Apply {
    /// Report the plan; run nothing.
    #[default]
    DryRun,
    /// Perform the plan.
    Write,
}

impl Apply {
    /// Whether this run is permitted to change the host.
    pub fn writes(self) -> bool {
        matches!(self, Self::Write)
    }
}

/// What one step of a plan does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Create a share point that does not exist.
    Create,
    /// Correct an owned share point's flags or directory.
    Update,
    /// Remove an owned share point.
    Remove,
    /// Drop a name from the ownership ledger. Touches no share point.
    Forget,
}

impl Action {
    /// The wire and log spelling.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Remove => "remove",
            Self::Forget => "forget",
        }
    }

    /// Reads an action back from its spelling.
    pub fn from_tag(text: &str) -> Option<Self> {
        match text {
            "create" => Some(Self::Create),
            "update" => Some(Self::Update),
            "remove" => Some(Self::Remove),
            "forget" => Some(Self::Forget),
            _ => None,
        }
    }
}

/// One step of a plan, and whether it actually happened.
///
/// A dry run returns the same list with every `applied` false, so the console
/// renders one thing whichever mode it asked for and the operator compares like
/// with like before saying yes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Performed {
    /// What the step does.
    pub action: Action,
    /// Which share point it does it to.
    pub name: SmbName,
    /// Whether the host was actually changed. False for every step of a dry run.
    pub applied: bool,
}

impl Performed {
    /// The step as it goes over the wire.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("action", Json::string(self.action.tag())),
            ("name", Json::string(self.name.as_str())),
            ("applied", Json::Bool(self.applied)),
        ])
    }

    /// Reads a step back from the wire, dropping one that is not well formed.
    pub fn from_json(value: &Json) -> Option<Self> {
        Some(Self {
            action: Action::from_tag(value.get("action")?.as_str()?)?,
            name: SmbName::parse(value.get("name")?.as_str()?).ok()?,
            applied: value.get("applied").and_then(Json::as_bool).unwrap_or(false),
        })
    }
}

/// Derives the export set from the checked shares.
///
/// The only constructor of [`DesiredShare`], which is what makes the guarantees
/// on that type total. A share with no `[shares.smb]` block contributes nothing —
/// SMB is opt-in per share, and a box with no `[shares.smb]` anywhere never
/// speaks to its SMB server at all.
///
/// Refuses, rather than sanitising, a root that could not survive a command line
/// or a configuration stanza. Sanitising would mean exporting a directory the
/// operator did not name.
pub fn desired_exports(shares: &Shares) -> Result<Vec<DesiredShare>, PlanError> {
    shares.all().iter().filter_map(desired_export).collect()
}

/// The export one share asks for, if it asks for one.
fn desired_export(share: &Share) -> Option<Result<DesiredShare, PlanError>> {
    let export = share.smb()?;
    let name = export.name.clone();
    let root = match share.root().to_str() {
        Some(root) => root,
        None => return Some(Err(PlanError::NonUtf8Root { name: name.to_string() })),
    };
    if !share.root().is_absolute() {
        return Some(Err(PlanError::RelativeRoot {
            name: name.to_string(),
            root: root.to_owned(),
        }));
    }
    if root.chars().any(char::is_control) {
        return Some(Err(PlanError::ControlCharacterInRoot {
            name: name.to_string(),
            root: root.to_owned(),
        }));
    }
    Some(Ok(DesiredShare {
        name,
        root: root.to_owned(),
        encrypt: export.encrypt,
        // The stricter of the share's flag and the export's, decided once in
        // `share.rs` so no backend re-reads the contradiction its own way.
        read_only: share.smb_read_only(),
    }))
}

/// Decides what to create, correct, remove, and leave entirely alone.
///
/// The load-bearing function of the module. Its shape is the safety property:
/// `remove` and `forget` are filled *only* from `owned`, and `untouched` is
/// filled from `live` but into a field whose element type no backend method
/// accepts. There is no code path from a share point the host reported to a
/// command that changes it, unless its name is in `owned`.
///
/// `live` is what the host says it exports; `owned` is what this deployment
/// recorded creating. Passing an empty `owned` is the honest state of a fresh
/// deployment and produces a plan that creates and never removes.
pub fn diff(desired: &[DesiredShare], live: &[LiveShare], owned: &Owned) -> Reconciliation {
    let mut plan = Reconciliation::default();

    for want in desired {
        let name = want.name.as_str();
        match live.iter().find(|share| share.answers_to(name)) {
            None => plan.create.push(want.clone()),
            Some(found) if !owned.contains(&want.name) => plan.conflicts.push(Conflict {
                name: want.name.clone(),
                existing_path: found.path.clone(),
                existing_guest_access: found.guest_access,
            }),
            Some(found) if found.satisfies(want) => plan.keep.push(want.clone()),
            Some(found) => plan.update.push(Update {
                desired: want.clone(),
                live_path: found.path.clone(),
                live_guest_access: found.guest_access,
            }),
        }
    }

    for name in owned.names() {
        if desired.iter().any(|want| &want.name == name) {
            continue;
        }
        if live.iter().any(|share| share.answers_to(name.as_str())) {
            plan.remove.push(name.clone());
        } else {
            plan.forget.push(name.clone());
        }
    }

    plan.untouched = live
        .iter()
        .filter(|share| {
            !owned.names().any(|name| share.answers_to(name.as_str()))
                && !desired.iter().any(|want| share.answers_to(want.name.as_str()))
        })
        .map(|share| share.name.clone())
        .collect();

    plan
}

/// Which SMB driver this host is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    /// macOS, driven through `/usr/sbin/sharing` and `launchctl`.
    Sharing,
    /// Windows, driven through the `SmbShare` PowerShell cmdlets and `icacls`.
    SmbShare,
    /// Linux, driven through a generated Samba include file.
    Samba,
    /// No driver for this operating system.
    Unsupported,
}

impl BackendKind {
    /// The wire spelling.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Sharing => "sharing",
            Self::SmbShare => "smbshare",
            Self::Samba => "samba",
            Self::Unsupported => "unsupported",
        }
    }

    /// A label a person reads, naming the thing actually being driven.
    pub fn label(self) -> &'static str {
        match self {
            Self::Sharing => "macOS File Sharing",
            Self::SmbShare => "Windows Server Message Block",
            Self::Samba => "Samba",
            Self::Unsupported => "unsupported",
        }
    }

    /// Reads a driver back from its wire spelling.
    pub fn from_tag(text: &str) -> Option<Self> {
        match text {
            "sharing" => Some(Self::Sharing),
            "smbshare" => Some(Self::SmbShare),
            "samba" => Some(Self::Samba),
            "unsupported" => Some(Self::Unsupported),
            _ => None,
        }
    }
}

/// One share point as the console shows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareState {
    /// Its name on the host.
    pub name: String,
    /// The directory it exports.
    pub path: String,
    /// Whether this deployment created it — and therefore whether a reconcile
    /// would ever change or remove it.
    pub managed: bool,
    /// Whether it is reachable without credentials.
    pub guest_access: bool,
    /// Whether it refuses writes.
    pub read_only: bool,
    /// Whether SMBv3 encryption is required on it.
    pub encrypted: bool,
}

impl ShareState {
    /// The share point as it goes over the wire.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("name", Json::string(&self.name)),
            ("path", Json::string(&self.path)),
            ("managed", Json::Bool(self.managed)),
            ("guestAccess", Json::Bool(self.guest_access)),
            ("readOnly", Json::Bool(self.read_only)),
            ("encrypted", Json::Bool(self.encrypted)),
        ])
    }

    /// Reads a share point back from the wire.
    pub fn from_json(value: &Json) -> Option<Self> {
        Some(Self {
            name: value.get("name")?.as_str()?.to_owned(),
            path: value.get("path").and_then(Json::as_str).unwrap_or_default().to_owned(),
            managed: value.get("managed").and_then(Json::as_bool).unwrap_or(false),
            guest_access: value.get("guestAccess").and_then(Json::as_bool).unwrap_or(false),
            read_only: value.get("readOnly").and_then(Json::as_bool).unwrap_or(true),
            encrypted: value.get("encrypted").and_then(Json::as_bool).unwrap_or(false),
        })
    }
}

/// The host's SMB exports as the backend last observed them, in the form the
/// console reads.
///
/// Hand-written camelCase JSON, the contract-with-the-console idiom
/// [`selfhost_firewall::state`](../../../selfhost_firewall/state/index.html) uses.
/// It carries [`AUTHENTICATION_NOTICE`] so that no front end can display SMB
/// state without having the caveat to hand.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbState {
    /// The driver for this host.
    pub backend: BackendKind,
    /// Whether the platform's SMB service is running, where the platform will
    /// say. `None` means the backend cannot tell, which is not the same as "no".
    pub service_running: Option<bool>,
    /// Every share point the host exports, ours and everybody else's.
    pub shares: Vec<ShareState>,
}

impl SmbState {
    /// Builds the console's view from a host reading and the ownership ledger.
    pub fn observed(
        backend: BackendKind,
        service_running: Option<bool>,
        live: &[LiveShare],
        owned: &Owned,
    ) -> Self {
        Self {
            backend,
            service_running,
            shares: live
                .iter()
                .map(|share| ShareState {
                    name: share.name.clone(),
                    path: share.path.clone(),
                    managed: owned.names().any(|name| share.answers_to(name.as_str())),
                    guest_access: share.guest_access,
                    read_only: share.read_only,
                    encrypted: share.encrypted,
                })
                .collect(),
        }
    }

    /// A label a person reads, naming the SMB server being driven.
    pub fn backend_label(&self) -> &'static str {
        self.backend.label()
    }

    /// The state as it goes over the wire, caveat included.
    pub fn to_json(&self) -> Json {
        let mut fields = vec![
            ("backend", Json::string(self.backend.tag())),
            ("notice", Json::string(AUTHENTICATION_NOTICE)),
            ("port", Json::Number(f64::from(SMB_PORT))),
            ("shares", Json::array(self.shares.iter().map(ShareState::to_json))),
        ];
        fields.push((
            "serviceRunning",
            match self.service_running {
                Some(running) => Json::Bool(running),
                None => Json::Null,
            },
        ));
        Json::object(fields)
    }

    /// Reads a state back from the wire, for the console.
    pub fn from_json(value: &Json) -> Option<Self> {
        Some(Self {
            backend: BackendKind::from_tag(value.get("backend")?.as_str()?)?,
            service_running: value.get("serviceRunning").and_then(Json::as_bool),
            shares: value
                .get("shares")
                .and_then(Json::as_array)
                .map(|items| items.iter().filter_map(ShareState::from_json).collect())
                .unwrap_or_default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::{Reserved, Share, SmbExport};
    use std::path::PathBuf;

    fn reserved() -> Reserved {
        Reserved::new(PathBuf::from("/var/selfhost/data"), None).expect("legal data dir")
    }

    fn share(id: &str, root: &str, read_only: bool, smb: Option<(&str, bool, bool)>) -> Share {
        let share = Share::new(&reserved(), id, PathBuf::from(root), read_only, false, None)
            .expect("a legal share");
        match smb {
            None => share,
            Some((name, encrypt, export_read_only)) => share.with_smb(SmbExport {
                name: SmbName::parse(name).expect("a legal share name"),
                encrypt,
                read_only: export_read_only,
            }),
        }
    }

    fn shares(list: Vec<Share>) -> Shares {
        Shares::new(list).expect("a legal share set")
    }

    fn want(name: &str, root: &str) -> DesiredShare {
        DesiredShare {
            name: SmbName::parse(name).expect("a legal share name"),
            root: root.to_owned(),
            encrypt: true,
            read_only: true,
        }
    }

    fn live(name: &str, path: &str) -> LiveShare {
        LiveShare {
            name: name.to_owned(),
            aliases: Vec::new(),
            path: path.to_owned(),
            guest_access: false,
            read_only: true,
            encrypted: true,
            shared: true,
        }
    }

    fn owning(names: &[&str]) -> Owned {
        Owned {
            names: names.iter().map(|n| SmbName::parse(n).expect("legal")).collect(),
        }
    }

    /// The public folder this very Mac exports, as `sharing -l -f json` reports
    /// it. The apostrophe is the typographic one macOS actually uses, and it is
    /// deliberately a name `SmbName::parse` refuses.
    fn the_mac_s_public_folder() -> LiveShare {
        LiveShare {
            name: "Alex Waldmann\u{2019}s Public Folder".to_owned(),
            aliases: Vec::new(),
            path: "/Users/alexwaldmann/Public".to_owned(),
            guest_access: true,
            read_only: false,
            encrypted: false,
            shared: true,
        }
    }

    #[test]
    fn a_share_with_no_smb_block_asks_for_no_export() {
        let set = shares(vec![share("vault", "/srv/vault", false, None)]);
        assert!(desired_exports(&set).expect("no refusal").is_empty());
    }

    #[test]
    fn an_export_carries_the_stricter_of_the_two_read_only_flags() {
        // The share is read-only; the export says it is not. The share wins,
        // because the safe reading of a contradiction about writes refuses them.
        let set = shares(vec![share("vault", "/srv/vault", true, Some(("Vault", true, false)))]);
        let exports = desired_exports(&set).expect("no refusal");
        assert_eq!(exports.len(), 1);
        assert!(exports[0].read_only(), "a read-only share is read-only over SMB");
        assert_eq!(exports[0].name().as_str(), "Vault");
        assert_eq!(exports[0].root_text(), "/srv/vault");
    }

    #[test]
    fn a_root_holding_a_newline_is_refused_rather_than_written_into_smb_conf() {
        let set = shares(vec![share(
            "vault",
            "/srv/vault\nguest ok = yes",
            false,
            Some(("Vault", true, true)),
        )]);
        let error = desired_exports(&set).expect_err("a newline must not reach a stanza");
        assert!(matches!(error, PlanError::ControlCharacterInRoot { .. }), "{error}");
    }

    #[test]
    fn an_empty_host_creates_every_configured_export_and_removes_nothing() {
        let plan = diff(&[want("Vault", "/srv/vault")], &[], &Owned::empty());
        assert_eq!(plan.create.len(), 1);
        assert!(plan.remove.is_empty());
        assert!(plan.conflicts.is_empty());
        assert!(plan.untouched.is_empty());
    }

    #[test]
    fn the_macs_pre_existing_guest_share_is_untouched_and_appears_in_no_action_list() {
        // The acceptance test of the whole module, stated as a property: a share
        // point selfhost did not create is in `untouched` and in nothing else,
        // whatever else the plan does.
        let plan = diff(
            &[want("Vault", "/srv/vault")],
            &[the_mac_s_public_folder()],
            &owning(&["Vault"]),
        );
        assert_eq!(plan.untouched, vec![the_mac_s_public_folder().name]);
        assert!(plan.remove.is_empty(), "{:?}", plan.remove);
        assert!(plan.forget.is_empty(), "{:?}", plan.forget);
        assert!(plan.update.is_empty(), "{:?}", plan.update);
        assert_eq!(plan.create.len(), 1, "the configured export is still created");
    }

    #[test]
    fn a_foreign_share_point_wearing_a_configured_name_is_a_conflict_not_an_adoption() {
        let plan = diff(&[want("Public", "/srv/vault")], &[live("Public", "/elsewhere")], &Owned::empty());
        assert!(plan.create.is_empty(), "adopting somebody else's share point is not ours to do");
        assert!(plan.remove.is_empty(), "nor is deleting it");
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].existing_path, "/elsewhere");
    }

    #[test]
    fn a_macos_alias_is_seen_by_conflict_detection() {
        // A share point whose record name and SMB name differ is somebody else's
        // configuration; matching only the record name would let us "create" a
        // second share point under a name already in use.
        let mut existing = live("public-folder", "/elsewhere");
        existing.aliases = vec!["Public".to_owned()];
        let plan = diff(&[want("Public", "/srv/vault")], &[existing], &Owned::empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert!(plan.create.is_empty());
    }

    #[test]
    fn an_owned_share_point_no_longer_configured_is_removed() {
        let plan = diff(&[], &[live("Vault", "/srv/vault")], &owning(&["Vault"]));
        assert_eq!(plan.remove, vec![SmbName::parse("Vault").expect("legal")]);
        assert!(plan.untouched.is_empty(), "an owned share point is not somebody else's");
    }

    #[test]
    fn an_owned_name_the_host_no_longer_has_is_forgotten_without_a_command() {
        let plan = diff(&[], &[], &owning(&["Vault"]));
        assert!(plan.remove.is_empty(), "there is nothing on the host to remove");
        assert_eq!(plan.forget, vec![SmbName::parse("Vault").expect("legal")]);
        assert!(!plan.changes_the_host(), "forgetting is bookkeeping, not a host change");
    }

    #[test]
    fn an_owned_share_point_found_with_guest_access_on_is_repaired() {
        let mut drifted = live("Vault", "/srv/vault");
        drifted.guest_access = true;
        let plan = diff(&[want("Vault", "/srv/vault")], &[drifted], &owning(&["Vault"]));
        assert_eq!(plan.update.len(), 1);
        assert!(plan.update[0].live_guest_access);
        assert!(!plan.update[0].path_moved());
        assert!(plan.keep.is_empty());
    }

    #[test]
    fn a_moved_root_is_an_update_that_reports_the_move() {
        let plan = diff(
            &[want("Vault", "/srv/vault")],
            &[live("Vault", "/srv/old")],
            &owning(&["Vault"]),
        );
        assert_eq!(plan.update.len(), 1);
        assert!(plan.update[0].path_moved(), "a backend must recreate rather than edit");
    }

    #[test]
    fn a_share_point_that_exists_but_is_not_shared_is_not_satisfied() {
        let mut idle = live("Vault", "/srv/vault");
        idle.shared = false;
        let plan = diff(&[want("Vault", "/srv/vault")], &[idle], &owning(&["Vault"]));
        assert_eq!(plan.update.len(), 1, "a share point with sharing off is not an export");
    }

    #[test]
    fn a_converged_host_is_settled_and_changes_nothing() {
        let plan = diff(
            &[want("Vault", "/srv/vault")],
            &[live("Vault", "/srv/vault")],
            &owning(&["Vault"]),
        );
        assert!(plan.is_settled(), "{plan:?}");
        assert_eq!(plan.keep.len(), 1);
    }

    #[test]
    fn a_dry_run_leaves_the_ledger_exactly_as_it_was() {
        let owned = owning(&["Vault"]);
        let steps = vec![
            Performed {
                action: Action::Remove,
                name: SmbName::parse("Vault").expect("legal"),
                applied: false,
            },
            Performed {
                action: Action::Create,
                name: SmbName::parse("Photos").expect("legal"),
                applied: false,
            },
        ];
        assert_eq!(owned.after(&steps), owned);
    }

    #[test]
    fn the_ledger_records_creations_and_drops_removals_that_happened() {
        let owned = owning(&["Vault"]);
        let steps = vec![
            Performed {
                action: Action::Remove,
                name: SmbName::parse("Vault").expect("legal"),
                applied: true,
            },
            Performed {
                action: Action::Create,
                name: SmbName::parse("Photos").expect("legal"),
                applied: true,
            },
        ];
        assert_eq!(owned.after(&steps), owning(&["Photos"]));
    }

    #[test]
    fn a_name_about_to_be_created_is_claimed_before_the_backend_runs() {
        // The claim is what keeps a reconcile that dies half way through from
        // reporting its own share point as somebody else's on the next run.
        let plan = diff(&[want("Vault", "/srv/vault")], &[], &Owned::empty());
        let claimed = Owned::empty().claiming(&plan);
        assert_eq!(claimed, owning(&["Vault"]));

        // And what it can never claim is a share point that was already there:
        // such a name went to `conflicts`, so `create` never held it.
        let taken = diff(&[want("Public", "/srv/vault")], &[live("Public", "/elsewhere")], &Owned::empty());
        assert!(taken.conflicts.len() == 1 && taken.create.is_empty());
        assert_eq!(Owned::empty().claiming(&taken), Owned::empty());
    }

    #[test]
    fn a_claimed_name_that_was_never_created_is_forgotten_by_the_next_diff() {
        // The cost of claiming early, and its own cleanup: the ledger names a
        // share point the host does not have, so the next plan drops the line
        // without running a command.
        let plan = diff(&[], &[], &owning(&["Vault"]));
        assert_eq!(plan.forget, vec![SmbName::parse("Vault").expect("legal")]);
    }

    #[test]
    fn the_ledger_round_trips_through_its_own_text() {
        let owned = owning(&["Photos", "Vault"]);
        assert_eq!(Owned::parse(&owned.to_text()).expect("our own text"), owned);
    }

    #[test]
    fn a_ledger_line_that_could_never_be_a_share_name_fails_the_whole_read() {
        // Refusing is the safe direction: skipping the line would silently shrink
        // what this deployment thinks it owns, and the visible symptom of that is
        // a share the operator asked to be removed quietly staying up.
        let error = Owned::parse("Vault\n-R\nguest ok = yes\n").expect_err("not a share name");
        assert!(matches!(error, PlanError::BadLedgerLine { .. }), "{error}");
        assert!(error.to_string().contains("nothing will be removed"), "{error}");
    }

    #[test]
    fn an_administrative_share_can_never_enter_the_ledger() {
        // `C$`, `ADMIN$` and `IPC$` are Windows's own share points. They can
        // never be owned, because `$` is not in SmbName's character set — so
        // they can never be removed, without any backend having to know that.
        for admin in ["C$", "ADMIN$", "IPC$"] {
            assert!(SmbName::parse(admin).is_err(), "{admin} must not be nameable");
            assert!(Owned::parse(admin).is_err(), "{admin} must not be ownable");
        }
    }

    #[test]
    fn the_state_round_trips_whole_and_carries_the_caveat() {
        let state = SmbState::observed(
            BackendKind::Sharing,
            Some(true),
            &[live("Vault", "/srv/vault"), the_mac_s_public_folder()],
            &owning(&["Vault"]),
        );
        let text = state.to_json().to_text();
        assert!(text.contains("operating-system"), "the caveat travels with the state: {text}");
        let parsed = selfhost_json::parse(&text).expect("valid json");
        assert_eq!(SmbState::from_json(&parsed), Some(state.clone()));
        assert!(state.shares[0].managed, "we created Vault");
        assert!(!state.shares[1].managed, "we did not create the public folder");
    }

    #[test]
    fn a_backend_that_cannot_tell_whether_the_service_runs_says_so_rather_than_no() {
        let state = SmbState::observed(BackendKind::Samba, None, &[], &Owned::empty());
        let text = state.to_json().to_text();
        assert!(text.contains(r#""serviceRunning":null"#), "{text}");
        let parsed = selfhost_json::parse(&text).expect("valid json");
        assert_eq!(SmbState::from_json(&parsed).expect("a state").service_running, None);
    }

    #[test]
    fn every_backend_kind_and_action_survives_its_own_spelling() {
        for kind in [
            BackendKind::Sharing,
            BackendKind::SmbShare,
            BackendKind::Samba,
            BackendKind::Unsupported,
        ] {
            assert_eq!(BackendKind::from_tag(kind.tag()), Some(kind));
        }
        assert_eq!(BackendKind::from_tag("netbios"), None);
        for action in [Action::Create, Action::Update, Action::Remove, Action::Forget] {
            assert_eq!(Action::from_tag(action.tag()), Some(action));
        }
        assert_eq!(Action::from_tag("adopt"), None);
    }

    #[test]
    fn a_performed_step_round_trips_over_the_wire() {
        let step = Performed {
            action: Action::Create,
            name: SmbName::parse("Vault").expect("legal"),
            applied: true,
        };
        let parsed = selfhost_json::parse(&step.to_json().to_text()).expect("valid json");
        assert_eq!(Performed::from_json(&parsed), Some(step));
    }

    #[test]
    fn a_dry_run_is_the_default_mode() {
        assert!(!Apply::default().writes());
        assert!(Apply::Write.writes());
    }
}
