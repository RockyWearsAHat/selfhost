//! What a caller may be permitted to do: a closed vocabulary of powers.
//!
//! # Why the enum is closed, and small
//!
//! Every route in this deployment answers one question today — *does this
//! request carry a valid credential?* — and that question has one answer for
//! restarting a service, reading a firewall's state, and (once the rest of this
//! branch lands) watching the screen and typing on it. Those are not the same
//! power, and a boolean cannot say so.
//!
//! A closed enum, rather than a string or a bitmask, is what makes the
//! difference checkable by the compiler. Adding a new power means adding a
//! variant, which breaks [`Capability::name`]'s match, which breaks the build
//! until the new power has been given a wire word, a place in the grant
//! implications, and a row in the policy's test table. A string-keyed
//! permission model has none of that: a typo is a silent denial, and a
//! forgotten capability is a silent allow.
//!
//! # Viewing is not driving, and the clipboard is neither
//!
//! Three of these variants describe the remote desktop, and the split between
//! them is the most load-bearing decision in the file. [`Capability::DesktopView`]
//! renders the machine's screen. [`Capability::DesktopControl`] moves its
//! pointer and types on its keyboard — the only capability in this repository
//! that *drives* the machine rather than serving data from it, and therefore the
//! one that can type a password, write an SSH key, or push a commit the box will
//! build and run unattended. [`Capability::ClipboardRead`] is neither: it
//! exfiltrates whatever the person at the machine last copied, which is
//! routinely a password or a token, and it does so without any of the visible
//! evidence that watching a screen leaves. Granting somebody a look at a
//! monitor must not silently grant them the other two, so they are three
//! capabilities and not one with flags.
//!
//! # Targets are validated, because they end up in a log line
//!
//! [`ShareId`] and [`NodeName`] are newtypes over a strict token grammar for
//! the same reason [`PersonName`](crate::PersonName) is: a capability is written
//! into an append-only audit line and into a JSON registry, and a target that
//! could contain a space, an equals sign or a newline would be a way for the
//! thing being named to rewrite the record of it being named. The grammar is
//! narrower than what `[[nodes]]` and `[[shares]]` accept in config today, and
//! that is deliberate: a config entry whose name cannot be expressed as a
//! capability target must fail closed at the boundary rather than be quietly
//! coerced into some neighbouring name.

use std::fmt;

/// The longest share id accepted, in characters.
///
/// A share id is also a URL path segment on the console site, so it is short by
/// nature; the cap exists so a registry file cannot be inflated by a name.
pub const MAX_SHARE_ID_CHARS: usize = 32;

/// The longest node name accepted, in characters.
///
/// Larger than a share id because a node name is a machine's name and people
/// give machines long ones, but still bounded for the same reason.
pub const MAX_NODE_NAME_CHARS: usize = 64;

/// Separators permitted inside a token, between alphanumerics.
const TOKEN_SEPARATORS: [char; 3] = ['-', '_', '.'];

/// Why a string is not a usable capability target.
///
/// One error type for both [`ShareId`] and [`NodeName`], because both wear the
/// same grammar; the `subject` field says which one was being parsed so the
/// message an operator sees names the thing they were configuring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidToken {
    /// The token was empty.
    Empty,
    /// The token was longer than its kind allows.
    TooLong {
        /// How many characters were offered.
        chars: usize,
        /// The cap for this kind of token.
        limit: usize,
    },
    /// The token did not begin and end with a lowercase letter or a digit.
    Edge,
    /// The token contained a character outside `a-z`, `0-9`, `-`, `_` and `.`.
    Forbidden {
        /// The first offending character.
        character: char,
    },
    /// Two separators sat next to each other.
    AdjacentSeparators,
}

impl fmt::Display for InvalidToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "may not be empty"),
            Self::TooLong { chars, limit } => {
                write!(f, "may be at most {limit} characters ({chars} given)")
            }
            Self::Edge => write!(f, "must begin and end with a lowercase letter or a digit"),
            Self::Forbidden { character } => write!(
                f,
                "may not contain {character:?}; lowercase letters, digits and {TOKEN_SEPARATORS:?} are allowed"
            ),
            Self::AdjacentSeparators => {
                write!(f, "may not put two of {TOKEN_SEPARATORS:?} side by side")
            }
        }
    }
}

impl std::error::Error for InvalidToken {}

/// Validates a lowercase token: the shared grammar behind both target types.
///
/// Kept private and shared rather than written twice, so the two targets cannot
/// drift into having different ideas about what a safe name is.
fn parse_token(text: &str, limit: usize) -> Result<String, InvalidToken> {
    if text.is_empty() {
        return Err(InvalidToken::Empty);
    }
    let chars = text.chars().count();
    if chars > limit {
        return Err(InvalidToken::TooLong { chars, limit });
    }
    let mut previous_was_separator = false;
    let mut last_was_separator = false;
    for (index, character) in text.chars().enumerate() {
        let separator = TOKEN_SEPARATORS.contains(&character);
        let alphanumeric = character.is_ascii_lowercase() || character.is_ascii_digit();
        if !separator && !alphanumeric {
            return Err(InvalidToken::Forbidden { character });
        }
        if index == 0 && separator {
            return Err(InvalidToken::Edge);
        }
        if separator && previous_was_separator {
            return Err(InvalidToken::AdjacentSeparators);
        }
        previous_was_separator = separator;
        last_was_separator = separator;
    }
    if last_was_separator {
        return Err(InvalidToken::Edge);
    }
    Ok(text.to_owned())
}

/// The id of a declared share: its config key and its URL segment.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ShareId(String);

impl ShareId {
    /// Validates `text` as a share id.
    pub fn parse(text: &str) -> Result<Self, InvalidToken> {
        parse_token(text, MAX_SHARE_ID_CHARS).map(Self)
    }

    /// The id as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ShareId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of a machine in the mesh, as declared in `[[nodes]]`.
///
/// The pseudo-peer `self` — this machine, reached through the same code path as
/// any other — is an ordinary value of this type, which is what keeps
/// "control the box I am logged into" and "control another box" one
/// authorisation check rather than two.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeName(String);

impl NodeName {
    /// Validates `text` as a node name.
    pub fn parse(text: &str) -> Result<Self, InvalidToken> {
        parse_token(text, MAX_NODE_NAME_CHARS).map(Self)
    }

    /// The name as written.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// One power a caller may hold.
///
/// The variants carrying a target are per-object: a person granted
/// `FilesRead("photos")` holds nothing at all over the share `vault`, and a
/// person granted `DesktopView("alex-desktop")` cannot see this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    /// Read the console: the service list, a service's state and logs, the
    /// firewall's state. Everything the console *shows* and nothing it does.
    ConsoleRead,
    /// Start, stop, restart, install, uninstall and deploy services.
    ServiceControl,
    /// List and download from one share.
    FilesRead(ShareId),
    /// Upload to, rename in and delete from one share.
    ///
    /// Implies [`Capability::FilesRead`] on the same share — see
    /// [`crate::Grants::holds`], and the `mode = "read" | "write" | "admin"`
    /// ladder the share config already exposes.
    FilesWrite(ShareId),
    /// Administer the storage subsystem: every share, plus the SMB export
    /// state and its reconcile action.
    FilesAdmin,
    /// Watch one node's screen.
    DesktopView(NodeName),
    /// Move one node's pointer and type on its keyboard.
    ///
    /// The only capability in this repository that drives a machine rather than
    /// serving data from it. Implies [`Capability::DesktopView`] on the same
    /// node — you cannot aim at what you cannot see — but is never implied *by*
    /// it, and is re-checked per input message rather than inferred once from a
    /// handshake, so a person can be downgraded mid-session.
    DesktopControl(NodeName),
    /// Read one node's clipboard.
    ///
    /// Its own capability, implied by nothing: the last thing copied on a
    /// machine is routinely a password or a token, and reading it leaves none
    /// of the visible trace that watching a screen does.
    ClipboardRead(NodeName),
    /// Administer the peer mesh: invite a node, revoke a node, see the peer
    /// registry. Deliberately implies no power *over* those nodes' desktops —
    /// managing a list of machines and driving one of them are different jobs.
    NodeAdmin,
    /// Create, change and remove **websites**: their hostnames, where the files
    /// are, which instances serve them, and which networks may reach them.
    ///
    /// The most consequential capability in this list and the one to read
    /// carefully. Every other power here acts *within* what this deployment
    /// already exposes; this one changes what it exposes. Someone holding it can
    /// point a hostname this box answers for at a directory or at a port, and can
    /// widen a site's `allowed_cidrs`. It is therefore never implied by anything,
    /// and the console it is administered from is itself a site.
    SiteAdmin,
    /// Create, change and remove **DNS records** in the zones this deployment
    /// serves, and push them to the registrar.
    ///
    /// Separate from [`Capability::SiteAdmin`] because the two fail differently:
    /// a wrong site is a page nobody can reach, and a wrong DNS record is a
    /// domain pointed somewhere else entirely — including, if the record is the
    /// one ACME validates against, somewhere that can be issued a certificate for
    /// it. Delegating the ability to add a subdomain is not delegating the
    /// ability to move the apex, but the grammar cannot express that, so the
    /// whole zone travels with the grant and the audit line is how it is watched.
    DnsAdmin,
    /// Create, change and remove **mailboxes and aliases**.
    ///
    /// Its own capability rather than a corner of the others because mail is the
    /// one surface where creating an account creates an *identity elsewhere*: a
    /// mailbox that can receive a password reset is a way into every service that
    /// trusts the address. Granting it hands over that, and nothing else.
    MailAdmin,
}

impl Capability {
    /// The wire word for this capability, without its target.
    ///
    /// This match is the crate's compile-time guard: a new variant cannot be
    /// added without being named here, and everything else that must be updated
    /// alongside it ([`Capability::target`], [`crate::Grants::holds`], the
    /// policy's table) is named in this method's own documentation so the
    /// author of the new variant finds the list at the point they are stopped.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ConsoleRead => "console.read",
            Self::ServiceControl => "service.control",
            Self::FilesRead(_) => "files.read",
            Self::FilesWrite(_) => "files.write",
            Self::FilesAdmin => "files.admin",
            Self::DesktopView(_) => "desktop.view",
            Self::DesktopControl(_) => "desktop.control",
            Self::ClipboardRead(_) => "clipboard.read",
            Self::NodeAdmin => "node.admin",
            Self::SiteAdmin => "site.admin",
            Self::DnsAdmin => "dns.admin",
            Self::MailAdmin => "mail.admin",
        }
    }

    /// The object this capability is about, for the variants that have one.
    ///
    /// Always a validated token, so a caller rendering it into a log line or a
    /// JSON string needs no escaping and no length check of its own.
    pub fn target(&self) -> Option<&str> {
        match self {
            Self::ConsoleRead
            | Self::ServiceControl
            | Self::FilesAdmin
            | Self::NodeAdmin
            | Self::SiteAdmin
            | Self::DnsAdmin
            | Self::MailAdmin => None,
            Self::FilesRead(share) | Self::FilesWrite(share) => Some(share.as_str()),
            Self::DesktopView(node) | Self::DesktopControl(node) | Self::ClipboardRead(node) => {
                Some(node.as_str())
            }
        }
    }

    /// Parses the wire form: `"console.read"`, `"files.write:vault"`.
    ///
    /// Strict in both directions. A word with a target it does not take, a word
    /// missing the target it does take, an unknown word, and a target that
    /// fails its own grammar are all `None` — one uniform refusal, because the
    /// caller of this function is reading a stored registry or a console
    /// request, and in both cases the safe reading of "I do not understand this
    /// grant" is to hold no grant at all.
    pub fn parse(text: &str) -> Option<Self> {
        let (word, target) = match text.split_once(':') {
            Some((word, target)) => (word, Some(target)),
            None => (text, None),
        };
        let share = |target: Option<&str>| ShareId::parse(target?).ok();
        let node = |target: Option<&str>| NodeName::parse(target?).ok();
        match (word, target) {
            ("console.read", None) => Some(Self::ConsoleRead),
            ("service.control", None) => Some(Self::ServiceControl),
            ("files.admin", None) => Some(Self::FilesAdmin),
            ("node.admin", None) => Some(Self::NodeAdmin),
            ("site.admin", None) => Some(Self::SiteAdmin),
            ("dns.admin", None) => Some(Self::DnsAdmin),
            ("mail.admin", None) => Some(Self::MailAdmin),
            ("files.read", target) => share(target).map(Self::FilesRead),
            ("files.write", target) => share(target).map(Self::FilesWrite),
            ("desktop.view", target) => node(target).map(Self::DesktopView),
            ("desktop.control", target) => node(target).map(Self::DesktopControl),
            ("clipboard.read", target) => node(target).map(Self::ClipboardRead),
            _ => None,
        }
    }

    /// Whether holding this capability lets a caller drive a machine.
    ///
    /// The predicate the policy's first asymmetry keys on: an unattended token
    /// may read anything the owner can read, and may not do these.
    pub fn drives_a_machine(&self) -> bool {
        matches!(self, Self::DesktopControl(_) | Self::ClipboardRead(_))
    }

    /// One capability of every shape, for exhaustive tables.
    ///
    /// Takes the targets rather than inventing them so a test can sweep the
    /// same share and node it granted. The length assertion in this module's
    /// tests is the reminder to extend this list when a variant is added;
    /// [`Capability::name`] is what stops the build first.
    pub fn every_shape(share: &ShareId, node: &NodeName) -> Vec<Capability> {
        vec![
            Self::ConsoleRead,
            Self::ServiceControl,
            Self::FilesRead(share.clone()),
            Self::FilesWrite(share.clone()),
            Self::FilesAdmin,
            Self::DesktopView(node.clone()),
            Self::DesktopControl(node.clone()),
            Self::ClipboardRead(node.clone()),
            Self::NodeAdmin,
            Self::SiteAdmin,
            Self::DnsAdmin,
            Self::MailAdmin,
        ]
    }

    /// Whether holding this capability lets a caller change what this deployment
    /// *is*, as against what it currently reports.
    ///
    /// The three configuration capabilities, as one predicate, because they share
    /// a property none of the others have: they edit `selfhost.config.toml`, and
    /// the file they edit is the description the whole deployment is derived
    /// from. Callers use this to demand a fresh credential and to write the
    /// louder audit line — a grant that can rewrite the deployment should not
    /// ride silently in a cookie that was minted twelve hours ago.
    pub fn edits_the_deployment(&self) -> bool {
        matches!(self, Self::SiteAdmin | Self::DnsAdmin | Self::MailAdmin)
    }
}

impl fmt::Display for Capability {
    /// The wire form, which is also what the audit log and the registry store.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.target() {
            Some(target) => write!(f, "{}:{target}", self.name()),
            None => f.write_str(self.name()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn share() -> ShareId {
        ShareId::parse("vault").expect("a valid share id")
    }

    fn node() -> NodeName {
        NodeName::parse("alex-desktop").expect("a valid node name")
    }

    #[test]
    fn ordinary_tokens_parse_and_odd_ones_do_not() {
        for good in ["vault", "a", "a1", "photos-2024", "alex_desktop", "a.b", "self", "home"] {
            assert!(ShareId::parse(good).is_ok(), "{good:?} should be a share id");
            assert!(NodeName::parse(good).is_ok(), "{good:?} should be a node name");
        }
        let bad = [
            ("", InvalidToken::Empty),
            ("-vault", InvalidToken::Edge),
            ("vault-", InvalidToken::Edge),
            (".vault", InvalidToken::Edge),
            ("va--ult", InvalidToken::AdjacentSeparators),
            ("va-_ult", InvalidToken::AdjacentSeparators),
        ];
        for (text, expected) in bad {
            assert_eq!(ShareId::parse(text), Err(expected), "{text:?}");
        }
        for text in ["Vault", "va ult", "va/ult", "va:ult", "va=ult", "va\nult", "vaült", "va%20"] {
            assert!(
                matches!(ShareId::parse(text), Err(InvalidToken::Forbidden { .. })),
                "{text:?} must be refused as a forbidden character"
            );
        }
    }

    #[test]
    fn a_token_is_bounded_by_characters() {
        assert!(ShareId::parse(&"a".repeat(MAX_SHARE_ID_CHARS)).is_ok());
        assert_eq!(
            ShareId::parse(&"a".repeat(MAX_SHARE_ID_CHARS + 1)),
            Err(InvalidToken::TooLong { chars: MAX_SHARE_ID_CHARS + 1, limit: MAX_SHARE_ID_CHARS })
        );
        assert!(NodeName::parse(&"a".repeat(MAX_NODE_NAME_CHARS)).is_ok());
        assert!(NodeName::parse(&"a".repeat(MAX_NODE_NAME_CHARS + 1)).is_err());
    }

    #[test]
    fn every_capability_round_trips_through_its_wire_form() {
        let shapes = Capability::every_shape(&share(), &node());
        assert_eq!(shapes.len(), 12, "extend every_shape when a variant is added");
        for capability in &shapes {
            let text = capability.to_string();
            assert_eq!(
                Capability::parse(&text).as_ref(),
                Some(capability),
                "{text} must round-trip"
            );
        }
        // The rendered words are what a registry file and an audit line carry;
        // they are fixed, and a rename is a file-format change.
        assert_eq!(Capability::FilesWrite(share()).to_string(), "files.write:vault");
        assert_eq!(Capability::DesktopControl(node()).to_string(), "desktop.control:alex-desktop");
        assert_eq!(Capability::NodeAdmin.to_string(), "node.admin");
        assert_eq!(Capability::SiteAdmin.to_string(), "site.admin");
        assert_eq!(Capability::DnsAdmin.to_string(), "dns.admin");
        assert_eq!(Capability::MailAdmin.to_string(), "mail.admin");
    }

    #[test]
    fn the_three_configuration_capabilities_are_the_ones_that_edit_the_deployment() {
        // The predicate exists so a caller does not have to remember the list,
        // and the negative half is the point: none of the powers that merely act
        // within what the deployment already exposes may be mistaken for one that
        // changes what it exposes.
        for editing in [Capability::SiteAdmin, Capability::DnsAdmin, Capability::MailAdmin] {
            assert!(editing.edits_the_deployment(), "{editing} edits selfhost.config.toml");
        }
        for acting in [
            Capability::ConsoleRead,
            Capability::ServiceControl,
            Capability::FilesAdmin,
            Capability::NodeAdmin,
            Capability::FilesWrite(share()),
            Capability::DesktopControl(node()),
            Capability::ClipboardRead(node()),
        ] {
            assert!(!acting.edits_the_deployment(), "{acting} does not rewrite the config");
        }
    }

    #[test]
    fn administering_the_configuration_is_not_driving_a_machine() {
        // Two independent asymmetries. An unattended token is refused the powers
        // that drive a machine; that refusal must not quietly extend to editing
        // config, nor must editing config quietly acquire a keyboard.
        for editing in [Capability::SiteAdmin, Capability::DnsAdmin, Capability::MailAdmin] {
            assert!(!editing.drives_a_machine(), "{editing} is not a keyboard");
        }
    }

    #[test]
    fn a_configuration_capability_takes_no_target() {
        // `site.admin:example` would read as "may administer only this site" and
        // grant something this grammar cannot enforce, so it is refused outright
        // rather than silently reduced to the whole-deployment grant.
        for text in ["site.admin:example", "dns.admin:rockywearsahat.com", "mail.admin:alex"] {
            assert_eq!(Capability::parse(text), None, "{text} must not parse");
        }
    }

    #[test]
    fn a_wire_form_that_is_not_understood_grants_nothing() {
        let refused = [
            "",
            "console.write",
            "console.read:vault",   // a target it does not take
            "files.read",           // the target it does take, missing
            "files.read:",          // present but empty
            "files.read:Vault",     // a target that fails its own grammar
            "files.read:a:b",       // the second colon lands inside the target
            "desktop.control",
            "node.admin:self",
            "FILES.READ:vault",
            " console.read",
            "console.read ",
        ];
        for text in refused {
            assert_eq!(Capability::parse(text), None, "{text:?} must grant nothing");
        }
    }

    #[test]
    fn driving_a_machine_is_exactly_control_and_clipboard() {
        for capability in Capability::every_shape(&share(), &node()) {
            let expected = matches!(
                capability,
                Capability::DesktopControl(_) | Capability::ClipboardRead(_)
            );
            assert_eq!(capability.drives_a_machine(), expected, "{capability}");
        }
    }

    #[test]
    fn a_target_is_present_exactly_for_the_variants_that_take_one() {
        assert_eq!(Capability::ConsoleRead.target(), None);
        assert_eq!(Capability::FilesAdmin.target(), None);
        assert_eq!(Capability::NodeAdmin.target(), None);
        assert_eq!(Capability::FilesRead(share()).target(), Some("vault"));
        assert_eq!(Capability::DesktopView(node()).target(), Some("alex-desktop"));
    }
}
