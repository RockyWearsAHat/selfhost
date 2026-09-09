//! The `[github_app]` section: a GitHub App installation this deployment
//! authenticates as, for a future increment's Netlify-style deploy bot.
//!
//! Absent `[github_app]` means the feature does not exist: no webhook route,
//! no installation store, nothing minted — the same "absence is the default"
//! posture [`crate::git::SelfUpdate`] and every other opt-in section here
//! follow. This section only names *how this deployment identifies itself to
//! GitHub as an App*; it says nothing about which repositories deploy or how —
//! that is [`crate::git::GitWatch`]'s job, wired up in a later increment.

use serde::{Deserialize, Serialize};

use crate::validate::Problem;

/// A GitHub App this deployment authenticates as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubApp {
    /// The App's numeric id, as GitHub's App settings page shows it.
    pub app_id: u64,

    /// Path to the App's private key, PEM-encoded, as GitHub hands it out.
    ///
    /// Resolved relative to `data_dir` the same way every other secret-bearing
    /// path in this configuration is — never committed, never world-readable;
    /// see `docs/SECURITY.md`'s credential inventory.
    pub private_key_path: String,

    /// A shared secret GitHub signs every webhook delivery with
    /// (`X-Hub-Signature-256`).
    ///
    /// The same mechanism, guarantees and threat model as
    /// [`crate::git::GitWatch::webhook_secret`] — read that field's
    /// documentation, it is the authority — except this secret is set once at
    /// App-creation time on github.com, not chosen freely: whatever value is
    /// entered there must be copied here verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub webhook_secret: Option<String>,
}

impl GithubApp {
    /// Collects every structural problem with this section, reported against
    /// the dotted path `at` exactly as every other opt-in section's `check`
    /// does.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if self.app_id == 0 {
            problems.push(Problem {
                field: format!("{at}.app_id"),
                message: "must be the App's real numeric id, not 0".into(),
            });
        }

        if self.private_key_path.trim().is_empty() {
            problems.push(Problem {
                field: format!("{at}.private_key_path"),
                message: "say where the App's private key PEM lives".into(),
            });
        }

        if self.webhook_secret.as_deref().is_some_and(str::is_empty) {
            problems.push(Problem {
                field: format!("{at}.webhook_secret"),
                message: "is present but empty; omit it entirely to leave webhook deliveries \
                          unauthenticated-and-refused rather than authenticated-with-nothing"
                    .into(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> GithubApp {
        GithubApp {
            app_id: 4606064,
            private_key_path: "secrets/github-app.private-key.pem".into(),
            webhook_secret: None,
        }
    }

    fn problems(app: &GithubApp) -> Vec<Problem> {
        let mut problems = Vec::new();
        app.check("github_app", &mut problems);
        problems
    }

    #[test]
    fn a_minimal_github_app_is_valid() {
        assert!(problems(&minimal()).is_empty());
    }

    #[test]
    fn a_zero_app_id_is_refused() {
        let mut app = minimal();
        app.app_id = 0;
        assert!(problems(&app).iter().any(|p| p.field == "github_app.app_id"));
    }

    #[test]
    fn an_empty_private_key_path_is_refused() {
        let mut app = minimal();
        app.private_key_path = "  ".into();
        assert!(problems(&app).iter().any(|p| p.field == "github_app.private_key_path"));
    }

    #[test]
    fn an_empty_webhook_secret_is_refused_rather_than_silently_ignored() {
        let mut app = minimal();
        app.webhook_secret = Some(String::new());
        assert!(problems(&app).iter().any(|p| p.field == "github_app.webhook_secret"));
    }

    #[test]
    fn a_present_nonempty_webhook_secret_is_valid() {
        let mut app = minimal();
        app.webhook_secret = Some("deadbeef".into());
        assert!(problems(&app).is_empty());
    }

    #[test]
    fn parses_from_toml_with_and_without_a_webhook_secret() {
        let with_secret = r#"
            app_id = 4606064
            private_key_path = "secrets/github-app.private-key.pem"
            webhook_secret = "deadbeef"
        "#;
        let app: GithubApp = toml::from_str(with_secret).unwrap();
        assert_eq!(app.app_id, 4606064);
        assert_eq!(app.webhook_secret.as_deref(), Some("deadbeef"));

        let without_secret = r#"
            app_id = 4606064
            private_key_path = "secrets/github-app.private-key.pem"
        "#;
        let app: GithubApp = toml::from_str(without_secret).unwrap();
        assert_eq!(app.webhook_secret, None);
    }
}
