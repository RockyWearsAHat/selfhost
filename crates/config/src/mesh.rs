//! The peer link, which is what makes a worker's daemon dial the owner.
//!
//! Every other way this project connects two machines starts with something
//! listening. This one does not, and that is the entire design: **a worker binds
//! nothing at all**, and the owner binds nothing new — the link arrives at the
//! console site the owner already serves on 443, over the tunnel that site is
//! already reached through. The `[[nodes]]` block on the owner is unchanged and
//! this section is absent there; a worker adds this section and gains an
//! outbound connection, not an inbound port.
//!
//! That inverts the arrangement `mesh_ip` used to describe, where a worker was
//! reached at a bare TCP address with no authentication, so anything at that
//! address could impersonate it. Here the worker proves who it is on the
//! connection it opened, with an HMAC over the WebSocket handshake — see
//! `selfhost-mesh`'s `enroll` module for why binding the proof to
//! `Sec-WebSocket-Key`/`Sec-WebSocket-Accept` means a captured proof is not a
//! credential.
//!
//! # Why `wss://` is a refusal and not a warning
//!
//! The enrolment proof and every frame after it ride this link: application
//! traffic, service control, and — once the desktop routes are wired — a
//! keyboard. `ws://` would carry all of that in the clear across whatever
//! network sits between the worker and the owner, and it would hand the proof
//! itself to anyone on the path, who could then complete the handshake it
//! belongs to.
//!
//! A warning is the wrong shape for that. A deployment that starts and logs a
//! line nobody reads is a deployment running in the clear; a deployment that
//! refuses to start is a deployment somebody fixes. So the scheme is checked at
//! load, and `ws://` is named specifically in the message rather than left to be
//! inferred from "must be wss://".
//!
//! # This crate does not depend on `selfhost-mesh`
//!
//! `mesh` depends on this crate's siblings and must compile without the box's
//! config, so the node-name length limit is mirrored here rather than imported,
//! the same way [`crate::mail`] mirrors the address limits it checks against.
//! Whether the named node *exists* is not a rule this type can check at all —
//! it needs the `[[nodes]]` list — so that one lives in [`crate::validate`],
//! beside the identical check on a site instance's node.

use serde::{Deserialize, Serialize};
use std::path::{Component, PathBuf};

use crate::validate::Problem;

/// Longest a node name may be. Mirrors `mesh::registry::MAX_NAME_LEN`, kept
/// local so `config` stays free of a dependency on the `mesh` crate (which
/// depends on *this* one).
const MAX_NODE_NAME_LEN: usize = 63;

/// The only scheme a peer link may use.
///
/// Named as a constant rather than written into the check, because it appears in
/// the refusal message, in the documented example, and in the check itself — and
/// three copies of the string that carries this section's entire confidentiality
/// argument is three chances for one of them to say `ws`.
pub const REQUIRED_SCHEME: &str = "wss://";

/// The token file a worker reads its shared secret from when the section names
/// none, resolved relative to `server.data_dir`.
pub const DEFAULT_TOKEN_FILE: &str = "peer.token";

/// The documented `[mesh]` example, as live TOML.
///
/// Shipped commented out — through [`crate::commented`] — in
/// `selfhost.config.toml` and in the `selfhost init` template. It carries the
/// worker's own `[[nodes]]` entry as well as the link, because `node` must name
/// a declared entry and a worker's config is the document that declares it; an
/// example that cannot be uncommented as it stands is an example that teaches
/// the wrong thing.
pub const EXAMPLE: &str = "\
# ─── Peer link ─────────────────────────────────────────────────────────────────
# On a worker, this is what makes its daemon dial the owner. The owner needs
# nothing here beyond the existing [[nodes]] block: it binds nothing new, and a
# worker binds nothing at all — the link is an outbound connection to the console
# site the owner already serves, over the tunnel that site is already reached
# through.

[[nodes]]
name = \"alex-desktop\"
role = \"worker\"

[mesh]
node = \"alex-desktop\"                              # must name a declared [[nodes]] entry
owner_url = \"wss://admin.rockywearsahat.com/api/mesh/link\"  # wss:// only; ws:// is refused
token_file = \"peer.token\"                          # relative to data_dir, written 0600
dial = true                                        # false parks the link without removing config
";

/// The `[mesh]` section: how this machine reaches the owner.
///
/// Present on a worker, absent on the owner. See the module documentation for
/// why a worker binds nothing and why the scheme is enforced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mesh {
    /// Which declared `[[nodes]]` entry *this machine* is.
    ///
    /// The name is half of the enrolment proof, so it is not a label: the owner
    /// looks up the token by it, and a proof computed under one name does not
    /// verify under another.
    pub node: String,

    /// The owner's link endpoint, e.g.
    /// `wss://admin.rockywearsahat.com/api/mesh/link`.
    ///
    /// Must be `wss://`. See the module documentation for why a downgrade to
    /// cleartext is a refusal rather than a warning.
    pub owner_url: String,

    /// Where this node's shared secret is read from, relative to
    /// `server.data_dir`, written `0600`.
    ///
    /// Relative rather than absolute so the secret cannot be pointed at a
    /// world-readable path by editing one line, and so a deployment's secrets
    /// stay in the one directory the backup, the permissions and the teardown
    /// story are all written about.
    #[serde(default = "default_token_file")]
    pub token_file: PathBuf,

    /// Whether the daemon actually dials.
    ///
    /// Defaults to `true`, because a `[mesh]` section that does not dial does
    /// nothing at all. `false` parks the link during an incident without the
    /// operator having to delete — and then retype from memory — the URL and the
    /// node name.
    #[serde(default = "default_true")]
    pub dial: bool,
}

fn default_token_file() -> PathBuf {
    PathBuf::from(DEFAULT_TOKEN_FILE)
}

fn default_true() -> bool {
    true
}

impl Mesh {
    /// A link from `node` to `owner_url`, with defaults: the standard token
    /// file, dialling.
    pub fn new(node: impl Into<String>, owner_url: impl Into<String>) -> Self {
        Self {
            node: node.into(),
            owner_url: owner_url.into(),
            token_file: default_token_file(),
            dial: true,
        }
    }

    /// Collects every structural problem with this section that can be judged
    /// without the rest of the document.
    ///
    /// `at` is the dotted path problems are reported under (`mesh`), matching
    /// every other `check` in this crate. Whether [`Mesh::node`] names a
    /// declared `[[nodes]]` entry, and whether that entry is a worker, are
    /// checked by [`Config::check_mesh`](crate::Config) — those need the node
    /// list, and a rule is checked where its inputs are.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if let Some(message) = node_name_problem(&self.node) {
            problems.push(Problem { field: format!("{at}.node"), message });
        }
        if let Some(message) = owner_url_problem(&self.owner_url) {
            problems.push(Problem { field: format!("{at}.owner_url"), message });
        }
        if let Some(message) = token_file_problem(&self.token_file) {
            problems.push(Problem { field: format!("{at}.token_file"), message });
        }
    }
}

/// Why this text is not usable as a node name, or `None` when it is.
///
/// Only shape: emptiness, length, and the whitespace that would make the name in
/// the proof and the name in `[[nodes]]` two different strings that print
/// identically. Whether the name is *declared* is [`crate::Config`]'s to answer.
fn node_name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some(
            "must name this machine's [[nodes]] entry; the name is half of the enrolment \
             proof, not a label"
                .into(),
        );
    }
    if name.chars().count() > MAX_NODE_NAME_LEN {
        return Some(format!(
            "is {} characters, over the {MAX_NODE_NAME_LEN}-character limit the mesh registry \
             enforces on a node name",
            name.chars().count()
        ));
    }
    if name.trim() != name {
        return Some(format!(
            "\"{name}\" has leading or trailing whitespace, so it prints identically to the \
             [[nodes]] entry it is meant to be and matches nothing"
        ));
    }
    None
}

/// Why this text is not a usable owner endpoint, or `None` when it is.
///
/// Deliberately narrow. This is not a URL parser — there is no URL crate here,
/// and inventing one to validate a string the operator typed would be a parser
/// on the load path for no benefit. What it checks is the property the security
/// argument rests on (the scheme) and the two shapes that would fail later with
/// an unhelpful error (no host, embedded whitespace).
fn owner_url_problem(url: &str) -> Option<String> {
    if url.is_empty() {
        return Some(format!(
            "must be the owner's link endpoint, e.g. \
             \"{REQUIRED_SCHEME}admin.example.com/api/mesh/link\""
        ));
    }

    let Some(rest) = url.strip_prefix(REQUIRED_SCHEME) else {
        // "ws://" is named on its own because it is the mistake that actually
        // happens, and because "must start with wss://" does not say what is
        // wrong with the thing that was written.
        let detail = if url.starts_with("ws://") {
            "\"ws://\" is cleartext. The enrolment proof and every frame after it — \
             application traffic, service control, and a keyboard once the desktop routes \
             are wired — ride this link, and anyone on the path could read all of it and \
             replay the proof onto the handshake it belongs to."
        } else {
            "a peer link is a WebSocket over TLS; no other scheme reaches the owner's \
             console site."
        };
        return Some(format!("must start with \"{REQUIRED_SCHEME}\": {detail}"));
    };

    if url.chars().any(char::is_whitespace) {
        return Some(format!("\"{url}\" contains whitespace, which no URL may"));
    }

    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() {
        return Some(format!(
            "\"{url}\" names no host; the part after \"{REQUIRED_SCHEME}\" must be the \
             owner's hostname, e.g. \"{REQUIRED_SCHEME}admin.example.com/api/mesh/link\""
        ));
    }
    if authority.contains('@') {
        return Some(format!(
            "\"{url}\" carries userinfo before the host. Credentials do not belong in this \
             URL: the link authenticates with the node token from token_file, and anything \
             written here would be copied into logs and diagnostics."
        ));
    }

    None
}

/// Why this path is not usable as a token file, or `None` when it is.
fn token_file_problem(path: &std::path::Path) -> Option<String> {
    if path.as_os_str().is_empty() {
        return Some(format!(
            "must name the file holding this node's token, relative to server.data_dir \
             (\"{DEFAULT_TOKEN_FILE}\" is the default); omit the line to use it"
        ));
    }
    if path.is_absolute() {
        return Some(format!(
            "\"{}\" is absolute. The token is resolved inside server.data_dir so that a \
             deployment's secrets stay in the one directory whose permissions, backups and \
             teardown are written about — an absolute path moves a 0600 secret somewhere \
             none of that applies.",
            path.display()
        ));
    }
    if path.components().any(|component| matches!(component, Component::ParentDir)) {
        return Some(format!(
            "\"{}\" must not contain \"..\"; the token file is resolved relative to \
             server.data_dir and may not point outside it",
            path.display()
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems_of(mesh: &Mesh) -> Vec<Problem> {
        let mut problems = Vec::new();
        mesh.check("mesh", &mut problems);
        problems
    }

    fn has(problems: &[Problem], field: &str) -> bool {
        problems.iter().any(|p| p.field == field)
    }

    fn link() -> Mesh {
        Mesh::new("shed", "wss://admin.example.com/api/mesh/link")
    }

    #[test]
    fn a_minimal_link_is_valid_and_dials_the_default_token_file() {
        let mesh = link();
        assert!(mesh.dial);
        assert_eq!(mesh.token_file, PathBuf::from(DEFAULT_TOKEN_FILE));
        assert!(problems_of(&mesh).is_empty(), "{:?}", problems_of(&mesh));
    }

    #[test]
    fn cleartext_is_refused_and_the_message_names_ws() {
        let mut broken = link();
        broken.owner_url = "ws://admin.example.com/api/mesh/link".into();
        let problems = problems_of(&broken);
        assert!(has(&problems, "mesh.owner_url"), "{problems:?}");
        assert!(
            problems[0].message.contains("ws://"),
            "the operator must be told what is wrong with what they wrote: {problems:?}"
        );
    }

    #[test]
    fn every_other_scheme_is_refused_too() {
        for url in [
            "https://admin.example.com/api/mesh/link",
            "http://admin.example.com/api/mesh/link",
            "admin.example.com/api/mesh/link",
            "WSS://admin.example.com/api/mesh/link",
            "",
        ] {
            let mut broken = link();
            broken.owner_url = url.into();
            assert!(has(&problems_of(&broken), "mesh.owner_url"), "{url:?}");
        }
    }

    #[test]
    fn a_url_with_no_host_or_with_credentials_is_refused() {
        for url in [
            "wss://",
            "wss:///api/mesh/link",
            "wss://user:pass@admin.example.com/api/mesh/link",
            "wss://admin.example.com/api/mesh /link",
        ] {
            let mut broken = link();
            broken.owner_url = url.into();
            assert!(has(&problems_of(&broken), "mesh.owner_url"), "{url:?}");
        }
    }

    #[test]
    fn a_host_without_a_path_is_accepted() {
        // The path is the owner's business, not this file's; only the scheme and
        // the presence of a host are load-bearing here.
        let mut mesh = link();
        mesh.owner_url = "wss://admin.example.com".into();
        assert!(problems_of(&mesh).is_empty(), "{:?}", problems_of(&mesh));
    }

    #[test]
    fn a_node_name_must_be_present_short_and_untrimmed() {
        for name in ["", " shed", "shed ", &"n".repeat(64)] {
            let mut broken = link();
            broken.node = name.into();
            assert!(has(&problems_of(&broken), "mesh.node"), "{name:?}");
        }
    }

    #[test]
    fn the_token_file_stays_inside_the_data_directory() {
        for path in ["", "/etc/selfhost/peer.token", "../peer.token", "keys/../../peer.token"] {
            let mut broken = link();
            broken.token_file = PathBuf::from(path);
            assert!(has(&problems_of(&broken), "mesh.token_file"), "{path:?}");
        }

        let mut nested = link();
        nested.token_file = PathBuf::from("keys/peer.token");
        assert!(problems_of(&nested).is_empty(), "{:?}", problems_of(&nested));
    }

    #[test]
    fn the_section_parses_from_toml_and_is_optional() {
        let with = crate::Config::parse(
            r#"
version = 1

[server]
acme_email = "a@b.com"

[[nodes]]
name = "home"
role = "owner"

[[nodes]]
name = "shed"
role = "worker"
mesh_ip = "10.77.0.2"

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"

[mesh]
node = "shed"
owner_url = "wss://admin.example.com/api/mesh/link"
"#,
        )
        .expect("valid");
        let mesh = with.mesh.expect("mesh present");
        assert_eq!(mesh.node, "shed");
        assert!(mesh.dial, "a link that does not dial does nothing, so dialling is the default");
        assert_eq!(mesh.token_file, PathBuf::from(DEFAULT_TOKEN_FILE));

        let without = crate::Config::parse(
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
        assert!(without.mesh.is_none(), "the owner needs nothing here");
    }

    #[test]
    fn the_documented_example_loads_as_it_stands() {
        // It carries its own [[nodes]] entry precisely so this passes: an
        // example whose `node` names nothing would teach an operator to write a
        // config that is refused.
        let document = format!("{}\n{EXAMPLE}", crate::BASE_DOCUMENT);
        let config = crate::Config::parse(&document).expect("the documented example must load");
        let mesh = config.mesh.expect("mesh present");
        assert_eq!(mesh.node, "alex-desktop");
        assert!(mesh.owner_url.starts_with(REQUIRED_SCHEME));
        assert!(mesh.dial);
    }

    #[test]
    fn the_shipped_example_arms_nothing() {
        let document = format!("{}\n{}", crate::BASE_DOCUMENT, crate::commented(EXAMPLE));
        let config = crate::Config::parse(&document).expect("valid");
        assert!(config.mesh.is_none());
        assert_eq!(config.nodes.len(), 1, "the example's worker node stays commented too");
    }

    #[test]
    fn an_undeclared_node_fails_validation_at_load() {
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

[mesh]
node = "ghost"
owner_url = "wss://admin.example.com/api/mesh/link"
"#,
        );
        match outcome {
            Err(crate::ConfigError::Invalid(problems)) => {
                assert!(has(&problems, "mesh.node"), "{problems:?}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn the_owner_may_not_declare_a_link_to_itself() {
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

[mesh]
node = "home"
owner_url = "wss://admin.example.com/api/mesh/link"
"#,
        );
        match outcome {
            Err(crate::ConfigError::Invalid(problems)) => {
                assert!(has(&problems, "mesh.node"), "{problems:?}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }
}
