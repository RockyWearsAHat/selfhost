//! VPN relays: a controlled door in front of one local service.
//!
//! Every other section in this file describes something this deployment serves.
//! This one describes the thing that decides who gets to reach it at all, so what
//! is true about its implementation matters more here than anywhere else — and
//! earlier revisions of this file got it wrong. They said the tunnel was missing
//! and unauditable. **It is neither.** Secure-VPN is the operator's own project,
//! `https://github.com/RockyWearsAHat/Secure-VPN.git`, and every file of it —
//! `server.py` included — is committed there and always was. The claim came from
//! one path: `crates/app/cli/src/service_install.rs` used to name
//! `scripts/securevpn/server.py`, a file *this* repository never had, and four
//! documents concluded from that absence that the code existed nowhere. It was in
//! a different repository of the same author's, which is a two-repositories
//! problem — `docs/principles.dx` files it under `rui` — and not a missing-code
//! one. A snapshot of the client half is vendored at `scripts/securevpn/app/` so
//! the copy a box installs can be diffed against a reviewed one; what a deployment
//! *runs* is always a copy, and that is the part worth checking.
//!
//! This module does not carry the tunnel. It carries the *shape* of a relay. The
//! transport cryptography stays where the workspace
//! dependency policy puts it — in the vetted implementation, run as a program,
//! exactly as `ssh`, `git` and the platform's own SMB server are run
//! (`crates/services/storage/src/smb/`). `docs/labs/vpn-lab.dx` is the design;
//! this file is its schema.
//!
//! # What a relay is
//!
//! One `[[vpn]]` block is one relay: a socket that accepts mutually-authenticated
//! sessions from named peers and hands each one to a **loopback** target on this
//! box. It is not a general network. `forward` is a loopback address and
//! validation refuses anything else, because a relay that can forward off this box
//! is a hole punched through the LAN's perimeter with an ACL nobody reviewed — and
//! because "put controlled access in front of my own app" means *this box's* app.
//!
//! Several relays may be declared, and that is the point: a person who runs a
//! service here can front it with their own door and their own roster instead of
//! being handed the console's. What they cannot do is front the *control plane*
//! by accident — see [`Config::check_vpn`](crate::Config)'s refusal of a relay
//! that forwards to `server.admin_bind`.
//!
//! # What a peer is
//!
//! A Peer is one device, and it exists only because a signed-in account enrolled
//! it: `<key_dir>/roster` lists it, `<key_dir>/<peer>.pub` pins it, and
//! `<data_dir>/vpn.peers` binds it to its Person (`selfhost_vpn::peer_binding`).
//! None of that is config. A `[[vpn.peers]]` block is refused at load.
//!
//! # Why the backend is still an enum with one member
//!
//! [`Backend::SecureVpn`] is the only member. WireGuard was removed on 2026-08-17
//! on the operator's ruling: it has never run on either machine in this
//! deployment, no invocation for it is recorded anywhere here, and a config
//! variant nobody can start is a subsystem that reads as configured and does
//! nothing. It is not a fallback and not a future option.
//!
//! The enum stays an enum rather than collapsing into nothing, for three reasons
//! that are about failure rather than taste. `backend = "secure-vpn"` is written
//! in the shipped example and in whatever a deployment has already saved, and
//! deleting the field would make those documents fail to load. [`Backend::from_tag`]
//! refuses `"wireguard"` and `"openvpn"` **by name**, so a hopeful edit is a
//! refusal at load rather than a silently ignored key. And a `match` over one
//! variant is exhaustive, so the day a second transport is genuinely run here, the
//! compiler names every place that has to decide about it — which is exactly how
//! this removal was carried out.

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Component, PathBuf};
use std::time::Duration;

use crate::validate::Problem;

/// Longest relay name, in characters.
///
/// A relay name is a directory segment under `data_dir`, a log line's subject and
/// a CLI argument, so it stays short enough to read in all three — the same
/// reasoning, and the same number, as a share id.
pub const MAX_RELAY_NAME_LEN: usize = 32;

/// Longest peer name, in characters.
pub const MAX_PEER_NAME_LEN: usize = 32;

/// Roster names that are a role rather than a device, and so are never a Peer.
/// `client` was the single shared key every device once used.
pub const RESERVED_PEER_NAMES: [&str; 2] = ["client", "server"];

/// Default ceiling on concurrent sessions a relay will hold.
///
/// The number is not arbitrary: it is the pre-authentication connection cap
/// already carried by the deployed Secure-VPN server (`docs/VPN.md`, "Pre-auth
/// DoS hardening"), restated here so the config and the program agree.
pub const DEFAULT_MAX_SESSIONS: u32 = 256;

/// Most concurrent sessions that may be asked for.
///
/// Every session in flight is memory held on behalf of a peer who has not yet
/// proved anything, so this is the ceiling on what an unauthenticated caller can
/// make this box allocate. Above it, the cap has stopped being a cap.
pub const MAX_MAX_SESSIONS: u32 = 4096;

/// Default seconds a handshake may take before the session is dropped. The
/// deployed server's own deadline.
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECS: u64 = 30;

/// Longest handshake deadline that still bounds anything: two minutes.
///
/// The deadline exists so an unauthenticated slow-drip cannot hold a session slot
/// open indefinitely. Past this, a caller who sends one byte a minute keeps a
/// slot for as long as they like, which is the attack the deadline was added for.
pub const MAX_HANDSHAKE_TIMEOUT_SECS: u64 = 120;

/// Length, in bytes, of a peer's public key.
///
/// Ed25519 public keys are 32 bytes and `key_manager.py` writes them in base64
/// (`scripts/securevpn/app/key_manager.py`, now in this repository). Checking the
/// decoded length is shape checking, not cryptography: it catches a truncated
/// paste, a fingerprint pasted in place of a key, and a private key pasted in
/// place of a public one only insofar as the length differs — it says nothing
/// about whether the key is any good.
pub const PEER_KEY_BYTES: usize = 32;

/// Who carries the transport cryptography for a relay.
///
/// One member. Kept as a closed enum rather than dropped — see the module
/// documentation for the three failure modes that keeps closed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// The project's own mutually-authenticated TCP forwarder, run as a program.
    ///
    /// The implementation is the operator's own project,
    /// `https://github.com/RockyWearsAHat/Secure-VPN.git`, with a snapshot of its
    /// client half vendored at `scripts/securevpn/app/` for diffing. It is the
    /// only transport this deployment has ever run, which is why it is the only
    /// one this enum offers.
    #[default]
    SecureVpn,
}

impl Backend {
    /// The TOML and wire spelling of this backend.
    ///
    /// One word serves the config, the CLI's output and any diagnostic, so the
    /// three can never disagree about how a backend is spelled.
    pub fn tag(self) -> &'static str {
        match self {
            Self::SecureVpn => "secure-vpn",
        }
    }

    /// Parses a backend from its TOML spelling, or `None` for anything else.
    ///
    /// `"wireguard"` is *not* accepted, and that is the point of keeping this
    /// function: a deployment that writes it gets a refusal naming the word it
    /// wrote, rather than a key serde ignores or a default it did not ask for.
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            "secure-vpn" => Some(Self::SecureVpn),
            _ => None,
        }
    }
}

/// A key this schema no longer has, remembered only so it can be refused by name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Removed(bool);

impl<'de> Deserialize<'de> for Removed {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(Self(true))
    }
}

/// The documented `[[vpn]]` example, as live TOML.
///
/// Shipped commented out — through [`crate::commented`] — so that a box gains a
/// relay only when somebody writes one, exactly as with `[[shares]]` and
/// `[desktop]`.
pub const EXAMPLE: &str = "\
# ─── VPN relays ────────────────────────────────────────────────────────────────
# A relay is one socket in front of ONE local service. Who may come through it is
# not written here: each account enrols its own devices by signing in. `forward` must be a loopback address — a relay forwards to
# this box and nowhere else — and it may not be server.admin_bind: the control
# API answers the bearer token as the owner, so a relay in front of it would be
# the deployment's root credential on a public port.
#
# `public = true` is required before a relay may bind anything but loopback, and
# it is a word an operator types rather than a default: docs/SECURITY.md §1 says
# every wildcard bind needs a written justification, and this is where writing it
# starts. Adding one to a box with a public IP is adding an inbound surface.
#
# Nobody is listed here. A device is on a relay because a signed-in account
# enrolled it, and `selfhost people` shows and removes them.

[[vpn]]
name = \"console\"                    # [a-z0-9-]; names the key directory and the log line
backend = \"secure-vpn\"              # the only transport this deployment runs
enabled = false                     # declared is not running; this is the switch
public = true                       # this relay is reachable from off this machine
listen = \"0.0.0.0:8443\"             # the one inbound socket, sanctioned as VPN-01
forward = \"127.0.0.1:443\"           # where an admitted session lands
key_dir = \"vpn/console\"             # relative to data_dir, 0700; omit for vpn/<name>
max_sessions = 256                  # concurrent, including handshakes not yet proved
handshake_timeout_secs = 30         # a slow drip must not hold a slot for ever

# A second relay, same identity and roster shape, pointed at SSH instead of the
# proxy — SSH-02's sanctioned remote-SSH path (docs/SECURITY.md). Not a second
# VPN product: same vetted implementation, same key model, one more forwarded
# target. Naming it \"ssh\" is what makes its supervised service vpn-ssh,
# matching `scripts/securevpn/install-vpn-service.ps1 -Name ssh`.
[[vpn]]
name = \"ssh\"
backend = \"secure-vpn\"
enabled = false
public = true
listen = \"0.0.0.0:8444\"            # a distinct port from the console relay's 8443
forward = \"127.0.0.1:22\"           # the box's own sshd, loopback-only either way
";

/// One `[[vpn]]` block: a door, and who may come through it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Relay {
    /// The relay's identifier: its key directory's name, and the subject of every
    /// line written about it. `[a-z0-9-]`.
    pub name: String,

    /// Who carries the transport cryptography. See [`Backend`].
    #[serde(default)]
    pub backend: Backend,

    /// Whether the daemon actually starts this relay.
    ///
    /// **Defaults to `false`.** A declared relay is a described relay; starting
    /// it is a second decision, and on this box starting one means binding an
    /// inbound socket. The same posture that makes an absent `[desktop]` block
    /// mean "no desktop" and an unmanaged firewall open nothing.
    #[serde(default)]
    pub enabled: bool,

    /// Acknowledges that `listen` is reachable from off this machine.
    ///
    /// **Defaults to `false`, and validation refuses a non-loopback `listen`
    /// without it.** `docs/SECURITY.md`'s first invariant is loopback-by-default
    /// and its checklist requires a written justification for any wildcard bind;
    /// this field is that requirement expressed as something the loader can check.
    /// It grants nothing on its own — it is an assertion about the address on the
    /// line above it, and validation refuses it on a loopback relay for exactly
    /// that reason.
    #[serde(default)]
    pub public: bool,

    /// The socket this relay accepts sessions on, e.g. `0.0.0.0:8443`.
    pub listen: String,

    /// Where an admitted session is handed, e.g. `127.0.0.1:443`.
    ///
    /// Must be loopback. A relay that can forward elsewhere is an authenticated
    /// tunnel into whatever else the LAN runs, with an access list nobody
    /// reviewed; see the module documentation.
    pub forward: String,

    /// Where this relay's key material lives, relative to `server.data_dir`.
    ///
    /// Absent means `vpn/<name>`. Relative rather than absolute for the reason
    /// [`crate::mesh::Mesh::token_file`] is: a deployment's secrets stay in the
    /// one directory whose permissions, backups and teardown are written about,
    /// and an absolute path moves a private key somewhere none of that applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_dir: Option<PathBuf>,

    /// Ceiling on concurrent sessions, including handshakes that have proved
    /// nothing yet.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: u32,

    /// Seconds a handshake may take before its session is dropped.
    #[serde(default = "default_handshake_timeout_secs")]
    pub handshake_timeout_secs: u64,

    /// Where `[[vpn.peers]]` used to be. Kept only so [`Relay::check`] can refuse
    /// it by name instead of serde ignoring it.
    #[serde(default, skip_serializing)]
    peers: Removed,
}

fn default_max_sessions() -> u32 {
    DEFAULT_MAX_SESSIONS
}

fn default_handshake_timeout_secs() -> u64 {
    DEFAULT_HANDSHAKE_TIMEOUT_SECS
}

impl Relay {
    /// A relay in the closed posture: the default backend, not enabled, not
    /// public, no roster, the documented session and handshake bounds.
    ///
    /// Every field a caller does not set is that field's safe value, so a relay
    /// built here and a relay parsed from a block naming only `name`, `listen`
    /// and `forward` are the same relay.
    pub fn new(
        name: impl Into<String>,
        listen: impl Into<String>,
        forward: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            backend: Backend::default(),
            enabled: false,
            public: false,
            listen: listen.into(),
            forward: forward.into(),
            key_dir: None,
            max_sessions: DEFAULT_MAX_SESSIONS,
            handshake_timeout_secs: DEFAULT_HANDSHAKE_TIMEOUT_SECS,
            peers: Removed::default(),
        }
    }

    /// Where this relay's keys live, relative to `server.data_dir`.
    ///
    /// Derived rather than defaulted through serde, because the default depends
    /// on the relay's own name and a `#[serde(default)]` function cannot see it.
    pub fn key_dir(&self) -> PathBuf {
        self.key_dir.clone().unwrap_or_else(|| PathBuf::from("vpn").join(&self.name))
    }

    /// The listening socket, parsed, or `None` when the text does not parse —
    /// which validation has already reported.
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        self.listen.parse().ok()
    }

    /// The shared forwarding target, parsed, or `None` when the text does not
    /// parse.
    pub fn forward_addr(&self) -> Option<SocketAddr> {
        self.forward.parse().ok()
    }

    /// The handshake deadline as a [`Duration`], converted in one place so a
    /// `from_millis` typo cannot quietly shorten it by a thousand.
    pub fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_secs)
    }


    /// Collects every structural problem with this one block.
    ///
    /// `at` is the dotted path problems are reported under (`vpn[0]`), matching
    /// every other `check` in this crate. Rules that need the rest of the
    /// document — a listen socket colliding with the proxy's, a forward pointed
    /// at the admin API — belong to [`Config::check_vpn`](crate::Config),
    /// because a rule is checked where its inputs are.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if let Some(message) = relay_name_problem(&self.name) {
            problems.push(Problem { field: format!("{at}.name"), message });
        }
        self.check_sockets(at, problems);
        self.check_limits(at, problems);
        self.check_peers(at, problems);
    }

    /// The two addresses, and the one word that has to be typed before this box
    /// listens anywhere but loopback.
    fn check_sockets(&self, at: &str, problems: &mut Vec<Problem>) {
        let listen = match self.listen.parse::<SocketAddr>() {
            Ok(address) => Some(address),
            Err(_) => {
                problems.push(Problem {
                    field: format!("{at}.listen"),
                    message: format!(
                        "\"{}\" is not a bindable address like \"0.0.0.0:8443\" or \
                         \"127.0.0.1:8443\". A relay's listening socket is written in full — \
                         address and port — because the address is the entire difference \
                         between a door onto the internet and a door onto this machine.",
                        self.listen
                    ),
                });
                None
            }
        };

        if let Some(address) = listen {
            if address.port() == 0 {
                problems.push(Problem {
                    field: format!("{at}.listen"),
                    message: "names port 0, which asks the kernel to pick one. A relay's port \
                              has to be forwarded by a router, allowed by a firewall and \
                              written into whatever a peer dials, so a port that changes on \
                              every restart is a relay nobody can reach."
                        .into(),
                });
            }

            let reachable_off_box = !address.ip().is_loopback();
            if reachable_off_box && !self.public {
                problems.push(Problem {
                    field: format!("{at}.listen"),
                    message: format!(
                        "\"{}\" is reachable from off this machine, and {at}.public is not set. \
                         This box has a real public IP and docs/SECURITY.md's second invariant \
                         is loopback-by-default: a bind that anything but this machine can \
                         reach is an inbound surface, and adding one is a decision somebody \
                         makes rather than a line somebody types. Write public = true to say \
                         it was decided, or bind 127.0.0.1 and reach the relay through \
                         something that already faces the world.",
                        self.listen
                    ),
                });
            }
            if !reachable_off_box && self.public {
                problems.push(Problem {
                    field: format!("{at}.public"),
                    message: format!(
                        "is true while {at}.listen is \"{}\", a loopback address nothing off \
                         this machine can reach. The line claims an exposure the relay does \
                         not have, and the next person to edit this file will act on what it \
                         appears to say — the same reason [desktop] refuses allow_input beside \
                         enabled = false.",
                        self.listen
                    ),
                });
            }
        }

        let forward = match self.forward.parse::<SocketAddr>() {
            Ok(address) => Some(address),
            Err(_) => {
                problems.push(Problem {
                    field: format!("{at}.forward"),
                    message: format!(
                        "\"{}\" is not an address like \"127.0.0.1:443\"; a relay hands every \
                         session to one local socket, named in full",
                        self.forward
                    ),
                });
                None
            }
        };

        if let Some(address) = forward {
            if !address.ip().is_loopback() {
                problems.push(Problem {
                    field: format!("{at}.forward"),
                    message: format!(
                        "\"{}\" is not a loopback address. A relay forwards to a service on \
                         this box and nowhere else: one that can reach the LAN or the internet \
                         is an authenticated tunnel into whatever else is on the network, \
                         governed by an access list nobody wrote and nobody reviewed. Front a remote service by running a relay on the machine \
                         that serves it.",
                        self.forward
                    ),
                });
            }
            if address.port() == 0 {
                problems.push(Problem {
                    field: format!("{at}.forward"),
                    message: "names port 0, which is not a service. Name the port the local \
                              service actually listens on."
                        .into(),
                });
            }
        }

        if let (Some(listen), Some(forward)) = (listen, forward) {
            if listen == forward {
                problems.push(Problem {
                    field: format!("{at}.forward"),
                    message: format!(
                        "is the same socket as {at}.listen (\"{}\"), so every admitted session \
                         would be handed back to this relay. That is a loop that consumes the \
                         session cap and serves nothing.",
                        self.listen
                    ),
                });
            }
        }

        if let Some(key_dir) = &self.key_dir {
            if let Some(message) = key_dir_problem(key_dir) {
                problems.push(Problem { field: format!("{at}.key_dir"), message });
            }
        }
    }

    /// The session and handshake bounds.
    fn check_limits(&self, at: &str, problems: &mut Vec<Problem>) {
        if self.max_sessions == 0 || self.max_sessions > MAX_MAX_SESSIONS {
            let why = if self.max_sessions == 0 {
                "admits nobody at all, which is a relay that binds a port and refuses every \
                 peer on it"
            } else {
                "is past the point where the cap caps anything — every session in flight is \
                 memory this box holds on behalf of a caller who has not yet proved who they \
                 are, and that is exactly what the number bounds"
            };
            problems.push(Problem {
                field: format!("{at}.max_sessions"),
                message: format!(
                    "must be between 1 and {MAX_MAX_SESSIONS}; {} {why}",
                    self.max_sessions
                ),
            });
        }

        if self.handshake_timeout_secs == 0
            || self.handshake_timeout_secs > MAX_HANDSHAKE_TIMEOUT_SECS
        {
            let why = if self.handshake_timeout_secs == 0 {
                "expires every handshake before it can complete, so no peer can ever connect"
            } else {
                "lets a caller who sends one byte a minute hold a session slot for as long as \
                 they like, which is the unauthenticated slow drip the deadline exists to stop"
            };
            problems.push(Problem {
                field: format!("{at}.handshake_timeout_secs"),
                message: format!(
                    "must be between 1 and {MAX_HANDSHAKE_TIMEOUT_SECS} seconds; {} {why}",
                    self.handshake_timeout_secs
                ),
            });
        }
    }

    /// Refuses the `[[vpn.peers]]` block this schema used to have.
    fn check_peers(&self, at: &str, problems: &mut Vec<Problem>) {
        if self.peers.0 {
            problems.push(Problem {
                field: format!("{at}.peers"),
                message: "is no longer read: a relay's devices now come from signing in \
                          (each account enrols its own). Delete the [[vpn.peers]] blocks."
                    .into(),
            });
        }
    }
}

/// Collects every structural problem with the whole `[[vpn]]` list.
///
/// Runs each relay's own [`Relay::check`] and then the rules that only exist
/// between blocks: two relays may not share a name or a listening socket, and no
/// relay may forward to another relay's front door.
///
/// `at` is the dotted path the list is reported under (`vpn`). Public so
/// `selfhost doctor` can report the same judgement on a running deployment
/// rather than re-deriving it — a diagnostic that disagrees with the loader about
/// what is acceptable is worse than no diagnostic.
pub fn check_relays(relays: &[Relay], at: &str, problems: &mut Vec<Problem>) {
    for (i, relay) in relays.iter().enumerate() {
        relay.check(&format!("{at}[{i}]"), problems);

        if let Some(previous) =
            relays[..i].iter().position(|earlier| earlier.name == relay.name)
        {
            problems.push(Problem {
                field: format!("{at}[{i}].name"),
                message: format!(
                    "\"{}\" is already the name of {at}[{previous}]. A relay's name is its key \
                     directory under data_dir, so two relays sharing one would share their key \
                     material — including the private key that is the whole perimeter.",
                    relay.name
                ),
            });
        }

        // A relay that failed to parse its own listen address has already earned
        // that problem, and a second one about the same characters would bury
        // it — so only parsed addresses are compared here.
        if let Some(address) = relay.listen_addr() {
            if let Some(previous) = relays[..i]
                .iter()
                .position(|earlier| earlier.listen_addr().is_some_and(|other| collides(other, address)))
            {
                problems.push(Problem {
                    field: format!("{at}[{i}].listen"),
                    message: format!(
                        "\"{}\" is already claimed by {at}[{previous}]. Whichever relay starts \
                         second fails to bind, and which one that is depends on start order — \
                         so the deployment would front a different service on that port \
                         depending on how it was restarted.",
                        relay.listen
                    ),
                });
            }
        }

        check_forward_collisions(relays, i, at, problems);
    }
}

/// Whether relay `i` forwards into an earlier relay's own front door.
///
/// Two relays sharing a `forward` is two doors onto one service, which is what
/// several relays are for. A forward that lands on another relay's `listen` is a
/// session handed to a tunnel expecting a handshake, which fails as a malformed
/// packet.
fn check_forward_collisions(relays: &[Relay], i: usize, at: &str, problems: &mut Vec<Problem>) {
    let Some(forward) = relays[i].forward_addr() else {
        return;
    };
    for (k, earlier) in relays[..i].iter().enumerate() {
        if earlier.listen_addr().is_some_and(|listen| collides(listen, forward)) {
            problems.push(Problem {
                field: format!("{at}[{i}].forward"),
                message: format!(
                    "sends sessions to {forward}, which is {at}[{k}].listen — another relay's own \
                     front door. An admitted session would arrive at a tunnel expecting a \
                     handshake, fail it, and be dropped with a message about a malformed \
                     packet."
                ),
            });
        }
    }
}

/// Whether two listening sockets cannot both be bound on this machine.
///
/// Not equality, deliberately. `0.0.0.0:8443` and `127.0.0.1:8443` are two
/// different [`SocketAddr`]s and exactly one of them can be bound: the wildcard
/// already covers the specific address, and the second `bind` fails with
/// `EADDRINUSE`. An equality test would let that pair through validation and
/// leave it to be discovered as a service that starts on Monday and not on
/// Tuesday, depending on which of the two came up first.
///
/// The families are treated as separate, because on both platforms this project
/// runs on they are: `0.0.0.0:443` and `[::]:443` coexist, and the proxy already
/// relies on that. Public so `selfhost doctor` can ask the same question of a
/// running deployment rather than re-deriving it.
pub fn collides(a: SocketAddr, b: SocketAddr) -> bool {
    if a.port() != b.port() || a.is_ipv4() != b.is_ipv4() {
        return false;
    }
    a.ip() == b.ip() || a.ip().is_unspecified() || b.ip().is_unspecified()
}

/// Why this text is not a legal relay name, or `None` when it is.
fn relay_name_problem(name: &str) -> Option<String> {
    if name.is_empty() {
        return Some(
            "must not be empty; the name is this relay's key directory under data_dir and the \
             subject of every line written about it"
                .into(),
        );
    }
    if name.chars().count() > MAX_RELAY_NAME_LEN {
        return Some(format!(
            "is {} characters, over the {MAX_RELAY_NAME_LEN}-character limit",
            name.chars().count()
        ));
    }
    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Some(format!(
            "\"{name}\" must be lowercase letters, digits and hyphens only. It becomes a \
             directory name holding private key material and an argument to the program that \
             runs the tunnel, and that character set needs no escaping in either."
        ));
    }
    None
}

/// Why this text is not a legal peer name, or `None` when it is.
///
/// The same character set as a relay name and for the same reason: this name is a
/// filename under the key directory *and* the value `--identity` carries on the
/// wire (`scripts/securevpn/join-mac.sh`), so it must be safe in both.
///
/// `pub` so every door a peer name comes through — enrolment, `selfhost people`
/// — is held to this one rule. [`RESERVED_PEER_NAMES`] are refused here, so a
/// role name can never be listed or authorised as a device.
pub fn peer_name_problem(name: &str) -> Option<String> {
    if RESERVED_PEER_NAMES.contains(&name) {
        return Some(format!(
            "\"{name}\" is a shared role name, not a device; a Peer needs its own name"
        ));
    }
    if name.is_empty() {
        return Some(
            "must not be empty; this is the entry the relay looks a peer up under, and it is \
             what --identity carries"
                .into(),
        );
    }
    if name.chars().count() > MAX_PEER_NAME_LEN {
        return Some(format!(
            "is {} characters, over the {MAX_PEER_NAME_LEN}-character limit",
            name.chars().count()
        ));
    }
    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Some(format!(
            "\"{name}\" must be lowercase letters, digits and hyphens only; it is a filename \
             under the relay's key directory as well as a value sent on the wire"
        ));
    }
    None
}

/// Why this text is not usable as a peer's public key, or `None` when it is.
///
/// Shape, not cryptography: the character set and the decoded length. Whether the
/// 32 bytes are a valid point on a curve is the tunnel implementation's to
/// decide, and this crate deliberately does not link one — the workspace
/// dependency policy is that cryptography is not hand-written here, and that
/// includes half-checking a key.
///
/// `pub` for the same reason [`peer_name_problem`] is.
pub fn public_key_problem(key: &str) -> Option<String> {
    if key.is_empty() {
        return Some(
            "must be the peer's public key in base64. It is not a secret — it is what pins \
             this peer"
                .into(),
        );
    }
    if key.chars().any(char::is_whitespace) {
        return Some(format!(
            "\"{key}\" contains whitespace. A key pasted across a line break is a key that \
             matches nothing, and the failure it produces says only that the handshake did not \
             complete."
        ));
    }

    let body = key.strip_suffix('=').unwrap_or(key);
    if !body.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/') {
        return Some(format!(
            "\"{key}\" is not base64. A peer key is 32 bytes written in base64 — that is what \
             scripts/securevpn/app/key_manager.py writes and what join-mac.sh prints — so a hex \
             string, a fingerprint or a file path here is something other than the key."
        ));
    }
    // 32 bytes is 43 base64 characters plus one '=' of padding. Both spellings
    // are accepted because the tools that print keys disagree about padding.
    let unpadded = 4 * PEER_KEY_BYTES / 3 + usize::from(PEER_KEY_BYTES % 3 != 0);
    if body.chars().count() != unpadded {
        return Some(format!(
            "decodes to something other than {PEER_KEY_BYTES} bytes ({} base64 characters, \
             expected {unpadded} with optional \"=\" padding). Ed25519 public keys are \
             {PEER_KEY_BYTES} bytes; a value of another length is a truncated paste or a \
             different kind of value altogether.",
            body.chars().count()
        ));
    }
    None
}

/// Why this path is not usable as a key directory, or `None` when it is.
///
/// The same rule, and the same reasoning, as [`crate::mesh`]'s token file: key
/// material stays inside `server.data_dir`.
fn key_dir_problem(path: &std::path::Path) -> Option<String> {
    if path.as_os_str().is_empty() {
        return Some(
            "must name the directory holding this relay's keys, relative to server.data_dir; \
             omit the line for \"vpn/<name>\""
                .into(),
        );
    }
    if path.is_absolute() {
        return Some(format!(
            "\"{}\" is absolute. Key material is resolved inside server.data_dir so that a \
             deployment's secrets stay in the one directory whose permissions, backups and \
             teardown are written about — an absolute path moves a private key somewhere none \
             of that applies.",
            path.display()
        ));
    }
    if path.components().any(|component| matches!(component, Component::ParentDir)) {
        return Some(format!(
            "\"{}\" must not contain \"..\"; the key directory is resolved relative to \
             server.data_dir and may not point outside it",
            path.display()
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problems_of(relay: &Relay) -> Vec<Problem> {
        let mut problems = Vec::new();
        relay.check("vpn[0]", &mut problems);
        problems
    }

    fn has(problems: &[Problem], field: &str) -> bool {
        problems.iter().any(|p| p.field == field)
    }

    fn relay() -> Relay {
        Relay::new("console", "127.0.0.1:8443", "127.0.0.1:443")
    }


    #[test]
    fn a_minimal_relay_is_valid_and_starts_closed() {
        let relay = relay();
        assert!(!relay.enabled, "a declared relay is not a running one");
        assert!(!relay.public, "loopback-by-default, exactly as SECURITY.md's second invariant");
        assert_eq!(relay.backend, Backend::SecureVpn);
        assert_eq!(relay.max_sessions, DEFAULT_MAX_SESSIONS);
        assert_eq!(relay.handshake_timeout(), Duration::from_secs(30));
        assert_eq!(relay.key_dir(), PathBuf::from("vpn").join("console"));
        assert!(problems_of(&relay).is_empty(), "{:?}", problems_of(&relay));
    }

    #[test]
    fn binding_off_this_machine_needs_the_word_typed() {
        let mut wide = relay();
        wide.listen = "0.0.0.0:8443".into();
        let problems = problems_of(&wide);
        assert!(has(&problems, "vpn[0].listen"), "{problems:?}");
        assert!(
            problems[0].message.contains("public = true"),
            "the refusal must say what to write: {problems:?}"
        );

        wide.public = true;
        assert!(problems_of(&wide).is_empty(), "{:?}", problems_of(&wide));

        // A LAN address is off this machine too — the rule is not about the
        // wildcard, it is about who can reach the socket.
        let mut lan = relay();
        lan.listen = "192.168.1.8:8443".into();
        assert!(has(&problems_of(&lan), "vpn[0].listen"));
    }

    #[test]
    fn claiming_an_exposure_the_relay_does_not_have_is_refused() {
        let mut dishonest = relay();
        dishonest.public = true;
        assert!(has(&problems_of(&dishonest), "vpn[0].public"));
    }

    #[test]
    fn a_relay_may_only_forward_to_loopback() {
        for target in ["192.168.1.50:8080", "10.0.0.9:22", "203.0.113.4:80"] {
            let mut broken = relay();
            broken.forward = target.into();
            assert!(has(&problems_of(&broken), "vpn[0].forward"), "{target}");
        }
        // Both loopback families are fine.
        for target in ["127.0.0.1:443", "[::1]:443"] {
            let mut fine = relay();
            fine.forward = target.into();
            assert!(problems_of(&fine).is_empty(), "{target}: {:?}", problems_of(&fine));
        }
    }

    #[test]
    fn unparsable_ports_and_zero_ports_are_refused() {
        for listen in ["8443", "0.0.0.0", "localhost:8443", "127.0.0.1:0"] {
            let mut broken = relay();
            broken.listen = listen.into();
            assert!(has(&problems_of(&broken), "vpn[0].listen"), "{listen}");
        }
        for forward in ["443", "127.0.0.1:0"] {
            let mut broken = relay();
            broken.forward = forward.into();
            assert!(has(&problems_of(&broken), "vpn[0].forward"), "{forward}");
        }
    }

    #[test]
    fn a_relay_may_not_forward_to_itself() {
        let mut loop_relay = relay();
        loop_relay.forward = loop_relay.listen.clone();
        assert!(has(&problems_of(&loop_relay), "vpn[0].forward"));
    }

    #[test]
    fn the_session_and_handshake_bounds_refuse_both_ends() {
        for sessions in [0, MAX_MAX_SESSIONS + 1] {
            let mut broken = relay();
            broken.max_sessions = sessions;
            assert!(has(&problems_of(&broken), "vpn[0].max_sessions"), "{sessions}");
        }
        for secs in [0, MAX_HANDSHAKE_TIMEOUT_SECS + 1] {
            let mut broken = relay();
            broken.handshake_timeout_secs = secs;
            assert!(has(&problems_of(&broken), "vpn[0].handshake_timeout_secs"), "{secs}");
        }
    }

    #[test]
    fn a_peers_block_is_refused_because_devices_come_from_signing_in() {
        let refused = crate::Config::parse(&format!(
            "{}\n[[vpn]]\nname = \"console\"\nlisten = \"127.0.0.1:8443\"\nforward = \
             \"127.0.0.1:443\"\n[[vpn.peers]]\nname = \"alex-mac\"\nperson = \"Alex\"\n",
            crate::BASE_DOCUMENT
        ))
        .expect_err("a [[vpn.peers]] block must not load");
        assert!(refused.to_string().contains("signing in"), "{refused}");
    }

    #[test]
    fn the_key_is_checked_for_shape_and_length_only() {
        for bad in [
            "",
            "not base64!",
            "deadbeef",                        // hex, and too short
            &"A".repeat(64),                   // a hex-length string of base64 characters
            &format!("{}\n{}", "A".repeat(21), "A".repeat(22)), // pasted across a line break
        ] {
            assert!(public_key_problem(bad).is_some(), "{bad:?}");
        }

        // Padded and unpadded spellings of 32 bytes are both accepted, because
        // the tools that print keys disagree about padding.
        assert_eq!(public_key_problem(&format!("{}=", "A".repeat(43))), None);
        assert_eq!(public_key_problem(&"A".repeat(43)), None);
    }

    #[test]
    fn the_role_names_are_never_a_peer() {
        for name in RESERVED_PEER_NAMES {
            assert!(peer_name_problem(name).is_some(), "{name}");
        }
        assert_eq!(peer_name_problem("alex-mac"), None);
    }

    #[test]
    fn the_key_directory_stays_inside_the_data_directory() {
        for path in ["", "/etc/selfhost/keys", "../keys", "vpn/../../keys"] {
            let mut broken = relay();
            broken.key_dir = Some(PathBuf::from(path));
            assert!(has(&problems_of(&broken), "vpn[0].key_dir"), "{path:?}");
        }
        let mut nested = relay();
        nested.key_dir = Some(PathBuf::from("vpn/console/keys"));
        assert!(problems_of(&nested).is_empty(), "{:?}", problems_of(&nested));
    }

    #[test]
    fn the_backend_is_closed_and_wireguard_is_refused_by_name() {
        // The removal, asserted. A deployment that writes the old word is told
        // it is not a backend rather than having the key ignored or defaulted.
        assert_eq!(Backend::from_tag(Backend::SecureVpn.tag()), Some(Backend::SecureVpn));
        assert_eq!(Backend::from_tag("wireguard"), None);
        assert_eq!(Backend::from_tag("openvpn"), None);

        let wire = toml::to_string(&Wrap { backend: Backend::SecureVpn }).unwrap();
        assert!(wire.contains("secure-vpn"), "{wire}");

        let refused = crate::Config::parse(&format!(
            "{}\n[[vpn]]\nname = \"console\"\nbackend = \"wireguard\"\nlisten = \
             \"127.0.0.1:8443\"\nforward = \"127.0.0.1:443\"\n",
            crate::BASE_DOCUMENT
        ));
        assert!(refused.is_err(), "a wireguard relay must not load");
    }

    #[test]
    fn a_wildcard_and_a_specific_address_on_one_port_collide() {
        // The pair an equality test would miss, and the reason `collides` is not
        // `==`: exactly one of these two can be bound, and which one depends on
        // start order.
        let wildcard: SocketAddr = "0.0.0.0:8443".parse().unwrap();
        let specific: SocketAddr = "127.0.0.1:8443".parse().unwrap();
        assert!(collides(wildcard, specific));
        assert!(collides(specific, wildcard));
        assert!(collides(wildcard, wildcard));
        // Different port, and the two families, are not collisions.
        assert!(!collides(wildcard, "0.0.0.0:8444".parse().unwrap()));
        assert!(!collides(wildcard, "[::]:8443".parse().unwrap()));

        let mut narrow = relay();
        narrow.name = "private".into();
        let mut wide = relay();
        wide.name = "console".into();
        wide.listen = "0.0.0.0:8443".into();
        wide.public = true;
        let mut problems = Vec::new();
        check_relays(&[narrow, wide], "vpn", &mut problems);
        assert!(has(&problems, "vpn[1].listen"), "{problems:?}");
    }

    #[test]
    fn two_relays_may_not_share_a_name_or_a_socket() {
        let mut problems = Vec::new();
        let mut second = relay();
        second.listen = "127.0.0.1:8444".into();
        check_relays(&[relay(), second], "vpn", &mut problems);
        assert!(has(&problems, "vpn[1].name"), "{problems:?}");

        let mut problems = Vec::new();
        let mut renamed = relay();
        renamed.name = "private".into();
        check_relays(&[relay(), renamed], "vpn", &mut problems);
        assert!(has(&problems, "vpn[1].listen"), "{problems:?}");
    }

    #[test]
    fn a_forward_may_not_be_another_relays_front_door() {
        let mut into_a_tunnel = relay();
        into_a_tunnel.name = "private".into();
        into_a_tunnel.listen = "127.0.0.1:8444".into();
        into_a_tunnel.forward = "127.0.0.1:8443".into();
        let mut problems = Vec::new();
        check_relays(&[relay(), into_a_tunnel], "vpn", &mut problems);
        assert!(has(&problems, "vpn[1].forward"), "{problems:?}");

        // Two relays sharing an ordinary `forward` is fine and normal — two
        // doors onto one service is what several relays are for.
        let mut plain = relay();
        plain.name = "private".into();
        plain.listen = "127.0.0.1:8444".into();
        let mut problems = Vec::new();
        check_relays(&[relay(), plain], "vpn", &mut problems);
        assert!(problems.is_empty(), "{problems:?}");
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

[[sites]]
name = "a"
domains = ["example.com"]
static_root = "./public"

[[vpn]]
name = "console"
public = true
listen = "0.0.0.0:8443"
forward = "127.0.0.1:443"
"#,
        )
        .expect("valid");
        let relay = &with.vpn[0];
        assert_eq!(relay.name, "console");
        assert!(!relay.enabled, "a block that does not say enabled does not run");
        assert_eq!(relay.backend, Backend::SecureVpn);

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
        assert!(without.vpn.is_empty(), "no [[vpn]] block means this box runs no relay");
    }

    #[test]
    fn the_documented_example_loads_as_it_stands() {
        let document = format!("{}\n{EXAMPLE}", crate::BASE_DOCUMENT);
        let config = crate::Config::parse(&document).expect("the documented example must load");
        let relay = &config.vpn[0];
        assert_eq!(relay.name, "console");
        assert!(!relay.enabled, "the example must not arm a relay");
        assert!(relay.public, "the example binds 0.0.0.0, so it must say so");
    }

    #[test]
    fn the_shipped_example_arms_nothing() {
        let document = format!("{}\n{}", crate::BASE_DOCUMENT, crate::commented(EXAMPLE));
        let config = crate::Config::parse(&document).expect("valid");
        assert!(config.vpn.is_empty());
    }

    #[derive(Serialize, Deserialize)]
    struct Wrap {
        backend: Backend,
    }
}
