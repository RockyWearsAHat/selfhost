//! The registrar that hosts this deployment's DNS, and how to reach its API.
//!
//! This is the third DNS posture the config can describe, alongside its
//! siblings: [`crate::dns::Dns`] is for a domain whose nameservers point *at
//! this machine*, and [`crate::namecheap::NamecheapDdns`] keeps one record
//! fresh on Namecheap's own DNS. `[registrar]` covers the middle ground — the
//! domain's DNS stays wherever it is registered, and `selfhost dns sync`
//! pushes the records the config implies *to* that registrar over its API.
//!
//! The section only names the provider and holds its credentials; deriving the
//! records and talking to the API live in `selfhost-registrar`, which this
//! crate never depends on — the same one-way arrangement `mail` and `dns`
//! keep. Providers without an API (Squarespace and friends) are served by
//! `provider = "manual"`, which needs no credentials at all: the sync command
//! then prints the records for the operator to add by hand.

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::validate::Problem;

/// Which registrar API `selfhost dns sync` speaks, or `manual` for none.
///
/// A closed set, lowercase in TOML like every other tag in this crate, so a
/// typo'd provider fails at load with serde naming the accepted values rather
/// than at sync time with a mystery connection error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistrarProvider {
    /// Namecheap's XML API (`setHosts` — a whole-zone replace).
    Namecheap,
    /// Cloudflare's v4 JSON API, authenticated by a scoped token.
    Cloudflare,
    /// GoDaddy's v1 JSON API, authenticated by an `sso-key` pair.
    Godaddy,
    /// Porkbun's v3 JSON API, authenticated by an API key pair.
    Porkbun,
    /// No API: `selfhost dns sync` prints the records for the operator to add
    /// by hand. This is the answer for every registrar without an API.
    Manual,
}

impl RegistrarProvider {
    /// The TOML spelling of this provider, matching its serde form — so error
    /// messages name the exact word the config must contain.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Namecheap => "namecheap",
            Self::Cloudflare => "cloudflare",
            Self::Godaddy => "godaddy",
            Self::Porkbun => "porkbun",
            Self::Manual => "manual",
        }
    }
}

/// The `[registrar]` section: one provider and its credentials.
///
/// The credential fields are a union across providers — each provider reads
/// the subset it needs, and [`Registrar::check`] enforces per-provider
/// presence so a missing key fails at `selfhost check` rather than as an API
/// refusal mid-sync. Every one of them is a secret with the standing rule:
/// it belongs only in the local, gitignored `selfhost.config.toml`, never in
/// anything committed or world-readable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registrar {
    /// Which registrar API to speak.
    pub provider: RegistrarProvider,

    /// The API username. Namecheap only (`ApiUser`, normally the account name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_user: Option<String>,

    /// The API key: Namecheap's `ApiKey`, Cloudflare's scoped token,
    /// GoDaddy's key half, Porkbun's `apikey`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,

    /// The API secret, for providers whose credential is a pair:
    /// GoDaddy's secret half, Porkbun's `secretapikey`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_secret: Option<String>,

    /// The public IPv4 address whitelisted in the account. Namecheap only —
    /// its API rejects calls from any address the account has not listed, so
    /// the address is part of the credential.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
}

impl Registrar {
    /// Collects every structural problem with this section.
    ///
    /// `at` is the dotted path problems are reported against (`registrar`),
    /// matching every other `check` in this crate. Each provider's required
    /// credentials are named with where to find them, because "missing field"
    /// alone sends the operator hunting through four vendors' dashboards.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        let mut require = |field: &str, value: &Option<String>, message: &str| {
            if value.as_deref().is_none_or(|text| text.trim().is_empty()) {
                problems.push(Problem {
                    field: format!("{at}.{field}"),
                    message: message.into(),
                });
            }
        };

        match self.provider {
            RegistrarProvider::Namecheap => {
                require(
                    "api_user",
                    &self.api_user,
                    "Namecheap needs api_user — the account name, from the account's \
                     API settings page",
                );
                require(
                    "api_key",
                    &self.api_key,
                    "Namecheap needs api_key, from the account's API settings page \
                     (API access must be enabled there first)",
                );
                require(
                    "client_ip",
                    &self.client_ip,
                    "Namecheap needs client_ip — the public IPv4 address whitelisted \
                     in the account's API settings; calls from any other address are \
                     rejected",
                );
                if let Some(given) = self.client_ip.as_deref() {
                    if !given.trim().is_empty() && given.trim().parse::<Ipv4Addr>().is_err() {
                        problems.push(Problem {
                            field: format!("{at}.client_ip"),
                            message: format!(
                                "\"{given}\" is not an IPv4 address; Namecheap whitelists \
                                 dotted IPv4 only"
                            ),
                        });
                    }
                }
            }
            RegistrarProvider::Cloudflare => {
                require(
                    "api_key",
                    &self.api_key,
                    "Cloudflare needs api_key — an API token with Zone:Read and \
                     DNS:Edit, created at dash.cloudflare.com → My Profile → API Tokens",
                );
            }
            RegistrarProvider::Godaddy => {
                require(
                    "api_key",
                    &self.api_key,
                    "GoDaddy needs api_key — the key half of a production key pair \
                     from developer.godaddy.com",
                );
                require(
                    "api_secret",
                    &self.api_secret,
                    "GoDaddy needs api_secret — the secret half of the key pair \
                     from developer.godaddy.com",
                );
            }
            RegistrarProvider::Porkbun => {
                require(
                    "api_key",
                    &self.api_key,
                    "Porkbun needs api_key, created at porkbun.com → Account → API \
                     Access (and API access enabled per domain)",
                );
                require(
                    "api_secret",
                    &self.api_secret,
                    "Porkbun needs api_secret — the secretapikey issued alongside \
                     the api_key",
                );
            }
            // Manual means "print the records"; there is nothing to
            // authenticate, so nothing is required and nothing is refused.
            RegistrarProvider::Manual => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A section for `provider` with every credential filled, which each test
    /// then blanks selectively.
    fn full(provider: RegistrarProvider) -> Registrar {
        Registrar {
            provider,
            api_user: Some("rocky".into()),
            api_key: Some("key".into()),
            api_secret: Some("secret".into()),
            client_ip: Some("172.83.6.109".into()),
        }
    }

    fn problems_of(registrar: &Registrar) -> Vec<Problem> {
        let mut problems = Vec::new();
        registrar.check("registrar", &mut problems);
        problems
    }

    #[test]
    fn manual_needs_no_credentials_at_all() {
        // The whole point of "manual": a registrar without an API must be
        // usable with nothing but the provider line.
        let bare = Registrar {
            provider: RegistrarProvider::Manual,
            api_user: None,
            api_key: None,
            api_secret: None,
            client_ip: None,
        };
        assert!(problems_of(&bare).is_empty());
    }

    #[test]
    fn each_api_provider_with_its_full_credentials_is_valid() {
        for provider in [
            RegistrarProvider::Namecheap,
            RegistrarProvider::Cloudflare,
            RegistrarProvider::Godaddy,
            RegistrarProvider::Porkbun,
        ] {
            assert!(problems_of(&full(provider)).is_empty(), "{provider:?}");
        }
    }

    #[test]
    fn namecheap_requires_user_key_and_whitelisted_ip() {
        // A missing Namecheap credential fails as an opaque API refusal at
        // sync time; these three must be caught at `selfhost check` instead.
        for field in ["api_user", "api_key", "client_ip"] {
            let mut broken = full(RegistrarProvider::Namecheap);
            match field {
                "api_user" => broken.api_user = None,
                "api_key" => broken.api_key = None,
                _ => broken.client_ip = None,
            }
            let problems = problems_of(&broken);
            assert!(
                problems.iter().any(|p| p.field == format!("registrar.{field}")),
                "missing {field}: {problems:?}"
            );
        }
    }

    #[test]
    fn namecheap_refuses_a_client_ip_that_is_not_ipv4() {
        let mut broken = full(RegistrarProvider::Namecheap);
        broken.client_ip = Some("not-an-address".into());
        let problems = problems_of(&broken);
        assert!(problems.iter().any(|p| p.field == "registrar.client_ip"), "{problems:?}");
    }

    #[test]
    fn cloudflare_needs_only_the_token() {
        let mut token_only = full(RegistrarProvider::Cloudflare);
        token_only.api_user = None;
        token_only.api_secret = None;
        token_only.client_ip = None;
        assert!(problems_of(&token_only).is_empty());

        let mut broken = token_only;
        broken.api_key = None;
        assert!(problems_of(&broken).iter().any(|p| p.field == "registrar.api_key"));
    }

    #[test]
    fn godaddy_and_porkbun_require_the_key_pair() {
        for provider in [RegistrarProvider::Godaddy, RegistrarProvider::Porkbun] {
            let mut broken = full(provider);
            broken.api_secret = None;
            let problems = problems_of(&broken);
            assert!(
                problems.iter().any(|p| p.field == "registrar.api_secret"),
                "{provider:?}: {problems:?}"
            );
        }
    }

    #[test]
    fn a_blank_credential_counts_as_missing() {
        // An empty string satisfies Option::is_some but authenticates nothing;
        // it must be refused exactly like an absent field.
        let mut blank = full(RegistrarProvider::Cloudflare);
        blank.api_key = Some("   ".into());
        assert!(problems_of(&blank).iter().any(|p| p.field == "registrar.api_key"));
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

[registrar]
provider = "porkbun"
api_key = "pk1_x"
api_secret = "sk1_y"
"#,
        )
        .expect("valid");
        let registrar = with.registrar.expect("registrar present");
        assert_eq!(registrar.provider, RegistrarProvider::Porkbun);
        assert_eq!(registrar.api_key.as_deref(), Some("pk1_x"));

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
        assert!(without.registrar.is_none(), "the section is opt-in");
    }

    #[test]
    fn an_incomplete_section_fails_validation_at_load() {
        // The end-to-end promise: `selfhost check` names the missing
        // credential, rather than `dns sync` failing against the live API.
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

[registrar]
provider = "godaddy"
api_key = "only-half"
"#,
        );
        match outcome {
            Err(crate::ConfigError::Invalid(problems)) => {
                assert!(problems.iter().any(|p| p.field == "registrar.api_secret"), "{problems:?}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn provider_tags_match_their_toml_spelling() {
        // tag() feeds error messages; it must equal the serde wire form or an
        // error would tell the operator to write a word the parser rejects.
        for provider in [
            RegistrarProvider::Namecheap,
            RegistrarProvider::Cloudflare,
            RegistrarProvider::Godaddy,
            RegistrarProvider::Porkbun,
            RegistrarProvider::Manual,
        ] {
            let wire = toml::to_string(&Wrap { provider }).expect("serialises");
            assert!(wire.contains(provider.tag()), "{wire}");
        }
    }

    #[derive(Serialize, Deserialize)]
    struct Wrap {
        provider: RegistrarProvider,
    }
}
