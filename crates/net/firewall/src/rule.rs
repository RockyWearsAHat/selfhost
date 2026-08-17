//! What the firewall should hold, and how a desired set differs from the live one.
//!
//! Pure, so it is all testable: nothing here spawns a process or reads a firewall.
//! [`desired_rules`] derives the allowances from config the way
//! [`selfhost_git::plan`](../../selfhost_git/plan/index.html) builds `git`
//! arguments, and [`diff`] decides add/withdraw/keep the way `plan::decide`
//! reaches a `Step` — asserted directly rather than inferred from a live host.

use selfhost_config::{Mail, Scope, Server};
use std::net::SocketAddr;

/// Transport a rule governs.
///
/// A closed set, not a string, for the reason [`Scope`] is one: only `Tcp` is
/// emitted today, and `Udp` exists so the DNS server (roadmap #4) is a later
/// variant rather than a schema change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Proto {
    /// The wire and command spelling.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }

    /// The uppercase spelling the Windows firewall wants (`protocol=TCP`).
    pub fn upper(self) -> &'static str {
        match self {
            Self::Tcp => "TCP",
            Self::Udp => "UDP",
        }
    }

    /// Reads a transport back from its wire spelling.
    pub fn from_tag(text: &str) -> Option<Self> {
        match text {
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            _ => None,
        }
    }
}

/// One inbound allowance the firewall should hold.
///
/// Derived from a public bind, never written by hand. `tag` is a diagnostic
/// label (`"http"`/`"https"`/`"ssh"`) carried so the console and each backend's
/// own rule name can identify the opening the operator recognises rather than a
/// bare port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowRule {
    /// The port opened.
    pub port: u16,
    /// The transport opened.
    pub proto: Proto,
    /// Who, off this machine, the opening admits.
    pub scope: Scope,
    /// A human label for the opening.
    pub tag: String,
}

impl AllowRule {
    /// Whether two allowances name the same opening — the same transport and port.
    ///
    /// The identity a reconciler diffs on: a rule for `443/tcp` *is* the HTTPS
    /// opening whatever its scope or label, so a scope change re-applies the same
    /// opening rather than counting as a different one to add beside it.
    pub fn same_opening(&self, other: &AllowRule) -> bool {
        self.proto == other.proto && self.port == other.port
    }
}

/// Port OpenSSH listens on, kept open by every managed policy.
pub const SSH_PORT: u16 = 22;

/// The private address ranges that make up [`Scope::Lan`].
///
/// RFC1918, CGNAT (`100.64/10`, which is where Tailscale and a carrier's own
/// NAT live), link-local, and loopback. Each backend formats these into its own
/// source-match syntax; keeping the list in one place keeps the three backends
/// honest about meaning the same thing by "the local network".
pub const LAN_CIDRS: [&str; 6] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "127.0.0.0/8",
];

/// The SSH allowance folded into every managed ruleset.
///
/// Scoped [`Scope::Lan`] rather than `Internet`: it admits the operator's own
/// network (including a CGNAT/Tailscale address) without publishing SSH to the
/// whole internet, and a session opened from anywhere else survives the policy
/// change because every backend preserves established connections. The one thing
/// this guarantees is that enabling default-deny can never sever the operator's
/// way into the machine the daemon runs on.
pub fn ssh_rule() -> AllowRule {
    AllowRule { port: SSH_PORT, proto: Proto::Tcp, scope: Scope::Lan, tag: "ssh".into() }
}

/// Folds [`ssh_rule`] into a desired set unless it is already present.
///
/// Every backend applies `with_ssh(desired)` rather than `desired`, so the SSH
/// opening is always in the "keep" or "add" set and never in "remove" — the
/// mechanism behind "never remove the SSH rule".
pub fn with_ssh(desired: &[AllowRule]) -> Vec<AllowRule> {
    let mut out = desired.to_vec();
    if !out.iter().any(|rule| rule.proto == Proto::Tcp && rule.port == SSH_PORT) {
        out.push(ssh_rule());
    }
    out
}

/// The inbound allowances a deployment's public binds require under its scope.
///
/// Covers the web binds always, and the five mail binds when `[mail]` is
/// configured — a deployment that answers `MX` queries with its own name must
/// keep `:25` open across router and firewall resets exactly as reliably as it
/// keeps `:443`, so the two are derived by the one function.
///
/// - `manage == false` → no rules. Reconcile asserts nothing; the firewall is
///   left exactly as the operator set it.
/// - [`Scope::Loopback`] → no rules. The default inbound block is the whole
///   policy, so a public bind under loopback scope is simply firewalled off.
/// - A bind whose IP is loopback → no rule. Nothing off the machine can reach
///   it, so opening a port would be meaningless.
///
/// `admin_bind` is never considered: it is loopback (refused otherwise by the
/// admin crate), the host firewalls this drives do not filter loopback, and the
/// console reaches it over an SSH tunnel that terminates on loopback. It needs no
/// rule, ever.
pub fn desired_rules(server: &Server, mail: Option<&Mail>) -> Vec<AllowRule> {
    if !server.firewall.manage || server.firewall.scope == Scope::Loopback {
        return Vec::new();
    }
    let scope = server.firewall.scope;
    let mut binds: Vec<(&'static str, SocketAddr)> = [("http", &server.http_bind), ("https", &server.https_bind)]
        .into_iter()
        .filter_map(|(tag, bind)| bind.parse().ok().map(|addr| (tag, addr)))
        .collect();
    if let Some(mail) = mail {
        binds.extend(mail.socket_binds());
    }
    binds
        .into_iter()
        .filter(|(_, addr)| !addr.ip().is_loopback())
        .map(|(tag, addr)| AllowRule { port: addr.port(), proto: Proto::Tcp, scope, tag: tag.into() })
        .collect()
}

/// The per-opening plan for converging a live managed set onto a desired one.
///
/// `present` is only ever the rules a backend *itself* created — it reads its own
/// owned table / anchor / name-prefixed rules and nothing else — so every entry
/// in `remove` is a selfhost-managed rule. Foreign rules never enter `present`,
/// which is why the reconciler cannot touch them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reconciliation {
    /// Desired openings not yet present: create these.
    pub add: Vec<AllowRule>,
    /// Present managed openings no longer desired: withdraw these.
    pub remove: Vec<AllowRule>,
    /// Openings both present and desired: leave these alone.
    pub keep: Vec<AllowRule>,
}

/// Decides which managed rules to add, withdraw, and keep.
///
/// The load-bearing set difference, matched on [`AllowRule::same_opening`].
/// Because callers pass `with_ssh(desired)`, the SSH opening is always desired
/// and so can only land in `add` or `keep`, never `remove`.
pub fn diff(present: &[AllowRule], desired: &[AllowRule]) -> Reconciliation {
    let mut plan = Reconciliation::default();
    for rule in desired {
        if present.iter().any(|held| held.same_opening(rule)) {
            plan.keep.push(rule.clone());
        } else {
            plan.add.push(rule.clone());
        }
    }
    for held in present {
        if !desired.iter().any(|rule| rule.same_opening(held)) {
            plan.remove.push(held.clone());
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp(port: u16, scope: Scope, tag: &str) -> AllowRule {
        AllowRule { port, proto: Proto::Tcp, scope, tag: tag.into() }
    }

    fn server(manage: bool, scope: Scope) -> Server {
        let mut server = Server {
            http_bind: "0.0.0.0:80".into(),
            https_bind: "0.0.0.0:443".into(),
            acme_email: "a@example.com".into(),
            acme: selfhost_config::AcmeEnvironment::SelfSigned,
            data_dir: "./data".into(),
            admin_bind: "127.0.0.1:9191".into(),
            firewall: selfhost_config::Firewall::default(),
        };
        server.firewall.manage = manage;
        server.firewall.scope = scope;
        server
    }

    #[test]
    fn an_unmanaged_firewall_wants_no_rules_at_all() {
        assert!(desired_rules(&server(false, Scope::Internet), None).is_empty());
    }

    #[test]
    fn loopback_scope_is_the_default_block_and_wants_no_rules() {
        // A public bind under loopback scope is deliberately firewalled off, not
        // opened to loopback — the default deny is the whole policy.
        assert!(desired_rules(&server(true, Scope::Loopback), None).is_empty());
    }

    #[test]
    fn a_managed_public_bind_opens_its_two_ports_under_the_chosen_scope() {
        let rules = desired_rules(&server(true, Scope::Lan), None);
        assert_eq!(rules, vec![tcp(80, Scope::Lan, "http"), tcp(443, Scope::Lan, "https")]);
    }

    fn mail() -> Mail {
        Mail {
            hostname: "mail.example.com".into(),
            domains: vec!["example.com".into()],
            mailboxes: Vec::new(),
            dkim: None,
            relay: None,
            bind: selfhost_config::MailBind::default(),
            max_message_bytes: 1024,
            require_tls_for_auth: true,
        }
    }

    #[test]
    fn a_mail_section_opens_its_five_binds_alongside_the_web_ports() {
        let rules = desired_rules(&server(true, Scope::Internet), Some(&mail()));
        let ports: Vec<u16> = rules.iter().map(|rule| rule.port).collect();
        assert_eq!(ports, vec![80, 443, 25, 587, 465, 143, 993]);
    }

    #[test]
    fn a_loopback_mail_bind_is_left_closed_like_a_loopback_web_bind() {
        let mut mail = mail();
        mail.bind.imap = "127.0.0.1:143".into();
        let rules = desired_rules(&server(true, Scope::Internet), Some(&mail));
        assert!(!rules.iter().any(|rule| rule.port == 143), "{rules:?}");
        assert!(rules.iter().any(|rule| rule.port == 25), "{rules:?}");
    }

    #[test]
    fn a_loopback_bind_is_left_closed_even_when_managing() {
        let mut server = server(true, Scope::Internet);
        server.http_bind = "127.0.0.1:80".into();
        // https stays public, http is loopback-only: only https gets a rule.
        let rules = desired_rules(&server, None);
        assert_eq!(rules, vec![tcp(443, Scope::Internet, "https")]);
    }

    #[test]
    fn openings_are_identified_by_transport_and_port_not_by_scope_or_label() {
        assert!(tcp(443, Scope::Lan, "https").same_opening(&tcp(443, Scope::Internet, "x")));
        assert!(!tcp(443, Scope::Lan, "https").same_opening(&tcp(80, Scope::Lan, "http")));
    }

    #[test]
    fn an_empty_firewall_adds_every_desired_opening_and_removes_nothing() {
        let desired = vec![tcp(80, Scope::Lan, "http"), tcp(443, Scope::Lan, "https")];
        let plan = diff(&[], &desired);
        assert_eq!(plan.add, desired);
        assert!(plan.remove.is_empty());
        assert!(plan.keep.is_empty());
    }

    #[test]
    fn a_converged_firewall_keeps_everything_and_changes_nothing() {
        let desired = with_ssh(&[tcp(80, Scope::Lan, "http"), tcp(443, Scope::Lan, "https")]);
        let plan = diff(&desired, &desired);
        assert_eq!(plan.keep, desired);
        assert!(plan.add.is_empty(), "{:?}", plan.add);
        assert!(plan.remove.is_empty(), "{:?}", plan.remove);
    }

    #[test]
    fn a_stale_managed_opening_is_withdrawn_and_a_new_one_added() {
        let present = vec![tcp(80, Scope::Lan, "http"), tcp(8080, Scope::Lan, "old")];
        let desired = vec![tcp(80, Scope::Lan, "http"), tcp(443, Scope::Lan, "https")];
        let plan = diff(&present, &desired);
        assert_eq!(plan.add, vec![tcp(443, Scope::Lan, "https")]);
        assert_eq!(plan.remove, vec![tcp(8080, Scope::Lan, "old")]);
        assert_eq!(plan.keep, vec![tcp(80, Scope::Lan, "http")]);
    }

    #[test]
    fn the_ssh_opening_is_always_desired_and_so_can_never_be_removed() {
        // Even when the operator's config asks for nothing, with_ssh keeps SSH in
        // the desired set, so a present SSH rule lands in keep — never remove.
        let present = with_ssh(&[]);
        let desired = with_ssh(&[]);
        let plan = diff(&present, &desired);
        assert!(plan.keep.iter().any(|r| r.port == SSH_PORT));
        assert!(!plan.remove.iter().any(|r| r.port == SSH_PORT), "SSH must never be withdrawn");
    }

    #[test]
    fn with_ssh_is_idempotent_and_does_not_double_the_opening() {
        let once = with_ssh(&[tcp(443, Scope::Lan, "https")]);
        let twice = with_ssh(&once);
        assert_eq!(once, twice);
        assert_eq!(once.iter().filter(|r| r.port == SSH_PORT).count(), 1);
    }
}
