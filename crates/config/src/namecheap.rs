//! Namecheap's Dynamic DNS, for a domain whose nameservers stay with Namecheap.
//!
//! This is deliberately separate from [`crate::dns::Dns`]: that module is for a
//! domain whose nameservers point *at this machine* — full authority, its own
//! zone, a secondary to keep the domain resolving when this box is down. A
//! domain that stays on Namecheap's own DNS wants something much smaller: keep
//! one A record pointed at this machine's current WAN address, because a
//! residential connection's address moves without warning. Namecheap's
//! "Dynamic DNS" feature is exactly that — a per-domain password and one HTTPS
//! GET per update, no delegation, nothing else about the domain's DNS changes.
//!
//! Choosing this over full delegation is the smaller commitment: it can be
//! proven on a throwaway subdomain and reverted by turning the feature back off
//! in Namecheap's panel, where moving nameservers is a change that affects
//! every record the domain has, including mail.

use serde::{Deserialize, Serialize};

use crate::validate::Problem;

/// One Namecheap-hosted domain (or subdomain) kept pointed at this machine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamecheapDdns {
    /// The domain as Namecheap's Dynamic DNS panel names it — the registered
    /// domain, not a full hostname (`example.com`, not `www.example.com`).
    pub domain: String,

    /// Which record under `domain` to update: `@` for the apex, `www` for
    /// `www.example.com`, or any other single label Namecheap's DNS already
    /// lists for this domain. Dynamic DNS updates an existing record; it does
    /// not create one, so this must already appear in Namecheap's Advanced DNS
    /// tab for `domain`.
    pub host: String,

    /// The domain's Dynamic DNS password, from Namecheap's Advanced DNS tab —
    /// distinct from the account password and scoped to this one feature.
    ///
    /// This is a secret with the same handling as every other one in this
    /// project: it belongs only in the local, gitignored `selfhost.config.toml`
    /// and nowhere that gets committed.
    pub password: String,
}

impl NamecheapDdns {
    /// Collects every structural problem with this entry.
    ///
    /// `at` is the dotted path problems are reported against, matching every
    /// other `check` in this crate.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if self.domain.trim().is_empty() {
            problems.push(Problem {
                field: format!("{at}.domain"),
                message: "name the domain as Namecheap's Dynamic DNS panel does, e.g. \
                          \"example.com\""
                    .into(),
            });
        }
        if self.host.trim().is_empty() {
            problems.push(Problem {
                field: format!("{at}.host"),
                message: "name the record to update — \"@\" for the apex, \"www\" for a \
                          www subdomain"
                    .into(),
            });
        }
        if self.password.is_empty() {
            problems.push(Problem {
                field: format!("{at}.password"),
                message: "the domain's Dynamic DNS password, from Namecheap's Advanced DNS \
                          tab, is required — without it there is nothing to authenticate \
                          the update with"
                    .into(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry() -> NamecheapDdns {
        NamecheapDdns { domain: "example.com".into(), host: "@".into(), password: "secret".into() }
    }

    fn problems_of(entry: &NamecheapDdns) -> Vec<Problem> {
        let mut problems = Vec::new();
        entry.check("namecheap_ddns[0]", &mut problems);
        problems
    }

    #[test]
    fn a_well_formed_entry_has_no_problems() {
        assert!(problems_of(&entry()).is_empty());
    }

    #[test]
    fn an_empty_domain_host_or_password_is_refused() {
        let mut missing_domain = entry();
        missing_domain.domain = String::new();
        assert!(problems_of(&missing_domain).iter().any(|p| p.field.ends_with(".domain")));

        let mut missing_host = entry();
        missing_host.host = String::new();
        assert!(problems_of(&missing_host).iter().any(|p| p.field.ends_with(".host")));

        let mut missing_password = entry();
        missing_password.password = String::new();
        assert!(problems_of(&missing_password).iter().any(|p| p.field.ends_with(".password")));
    }
}
