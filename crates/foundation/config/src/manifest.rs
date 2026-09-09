//! A repository's own description of how to build and run it: `selfhost.toml`,
//! read from the tip of a tracked repository, never from this deployment's own
//! config tree.
//!
//! # Why this exists
//!
//! Before this type, "how does this repo build and serve" lived nowhere but an
//! operator's memory and whatever they typed after `--serve`/`--build` on
//! `selfhost repo configure` — the incident this module answers
//! (`docs/incidents/2026-09-08-ai-studio-checkout-divergence.md`) is exactly
//! what happens when that knowledge only exists in one person's head and a
//! second attempt reconstructs it differently. A [`RepoManifest`] lets the
//! repository state its own answer once, in the tree it is versioned with, so
//! reconfiguring it — by hand or by an agent — reads the same authority every
//! time instead of guessing.
//!
//! # Why reading it is never automatic
//!
//! A manifest is authored by whoever can push to the repository, which is not
//! always whoever operates this deployment. Folding its `build`/`serve`
//! commands into a running service means the daemon will later execute
//! whatever shell command that file names — so reading it automatically, the
//! moment a clone contains one, would silently hand build/serve execution to
//! anyone with push access to the repository. That is a materially bigger
//! trust boundary than an operator's own CLI flags or a hand-written
//! `selfhost.config.toml`, so — per this project's posture in
//! `docs/SECURITY.md` of making trust boundaries explicit rather than
//! automatic — nothing in this crate ever reads a manifest on its own. The
//! opt-in (`selfhost repo configure --from-manifest`, or
//! `services_repo_configure(from_manifest=true)`) lives in the callers that
//! fetch one; this module only says what the document may contain once
//! somebody has decided to trust it.
//!
//! # Same conventions as [`crate::git::GitWatch`]
//!
//! `Problem`-based validation collecting every issue at once, absence as the
//! default, and a present-but-empty optional field refused rather than
//! silently treated as "no build step" — see [`RepoManifest::check`].

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::validate::Problem;

/// A repository's own description of how it builds and runs, as read from
/// `selfhost.toml` at the tip of a tracked repository.
///
/// Every field mirrors something an operator is already asked for by hand —
/// via `selfhost repo configure`'s `--serve`/`--build`/`--port` flags, or via
/// [`crate::service::ServiceSpec`]'s own fields — so this type exists to let
/// the repository answer those same questions itself, not to add new ones.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RepoManifest {
    /// The command that starts the server, program first, already split — the
    /// same shape and the same reason as
    /// [`crate::service::ServiceSpec::args`]: a single string has to be
    /// word-split by someone, and every implementation does it slightly
    /// differently.
    ///
    /// Required: a manifest that does not say how to serve the application is
    /// not a usable manifest, and defaulting it to nothing would install a
    /// service that starts and immediately exits.
    #[serde(default)]
    pub serve: Vec<String>,

    /// A command run in the working copy before `serve` starts. `None` means
    /// there is no build step.
    ///
    /// `Some(vec![])` is refused rather than treated as "no build step" — the
    /// exact rule [`crate::git::GitWatch::post_pull`] states for the identical
    /// reason: omit the field entirely when there is nothing to run, so a
    /// present-but-empty list is never ambiguous between "no build" and a
    /// mistake that dropped the command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<Vec<String>>,

    /// The port the server binds. `None` lets the operator's own `--port` (or
    /// the caller composing an [`crate::service::ServiceSpec`] some other way)
    /// decide, so a manifest does not have to know which port this deployment
    /// happened to free up for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Environment variables the process needs, on top of whatever the
    /// deployment injects (e.g. `PORT`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,

    /// Path probed to decide whether the running instance is healthy.
    /// `None` leaves the deployment's own default in place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_path: Option<String>,
}

impl RepoManifest {
    /// Collects every structural problem with this manifest.
    ///
    /// `at` is the dotted path problems are reported against, matching every
    /// other `check` in this crate.
    pub fn check(&self, at: &str, problems: &mut Vec<Problem>) {
        if self.serve.is_empty() {
            problems.push(Problem {
                field: format!("{at}.serve"),
                message: "name the command that starts the server; a manifest with no serve \
                          command cannot describe a running application"
                    .into(),
            });
        } else if self.serve.iter().any(|word| word.is_empty()) {
            problems.push(Problem {
                field: format!("{at}.serve"),
                message: "contains an empty word; check for an accidental blank entry".into(),
            });
        }

        if let Some(build) = &self.build {
            if build.is_empty() {
                problems.push(Problem {
                    field: format!("{at}.build"),
                    message: "is present but empty; omit it entirely when there is no build step"
                        .into(),
                });
            } else if build.iter().any(|word| word.is_empty()) {
                problems.push(Problem {
                    field: format!("{at}.build"),
                    message: "contains an empty word; check for an accidental blank entry".into(),
                });
            }
        }

        if let Some(port) = self.port
            && port == 0
        {
            problems.push(Problem {
                field: format!("{at}.port"),
                message: "must be between 1 and 65535; 0 does not name a bindable port".into(),
            });
        }

        for key in self.env.keys() {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                problems.push(Problem {
                    field: format!("{at}.env"),
                    message: format!("\"{key}\" is not a usable variable name"),
                });
            }
        }

        if self.health_path.as_deref().is_some_and(str::is_empty) {
            problems.push(Problem {
                field: format!("{at}.health_path"),
                message: "is present but empty; omit it entirely to use the deployment's default"
                    .into(),
            });
        }
    }

    /// Parses a manifest from TOML text, validating it.
    pub fn parse(text: &str) -> Result<Self, crate::ConfigError> {
        let manifest: Self =
            toml::from_str(text).map_err(|e| crate::ConfigError::Syntax(e.to_string()))?;
        let mut problems = Vec::new();
        manifest.check("manifest", &mut problems);
        if problems.is_empty() {
            Ok(manifest)
        } else {
            Err(crate::ConfigError::Invalid(problems))
        }
    }
}

/// The filename a repository's manifest is read from, at the tip of the
/// tracked branch — never anywhere in this deployment's own config tree.
pub const MANIFEST_FILENAME: &str = "selfhost.toml";

#[cfg(test)]
mod tests {
    use super::*;

    fn problems_of(manifest: &RepoManifest) -> Vec<Problem> {
        let mut problems = Vec::new();
        manifest.check("manifest", &mut problems);
        problems
    }

    fn valid() -> RepoManifest {
        RepoManifest {
            serve: vec!["node".into(), "server.js".into()],
            build: Some(vec!["npm".into(), "ci".into()]),
            port: Some(5050),
            env: BTreeMap::from([("NODE_ENV".into(), "production".into())]),
            health_path: Some("/healthz".into()),
        }
    }

    #[test]
    fn a_fully_specified_manifest_is_valid() {
        assert!(problems_of(&valid()).is_empty());
    }

    #[test]
    fn a_minimal_manifest_with_only_serve_is_valid() {
        let manifest = RepoManifest { serve: vec!["node".into(), "server.js".into()], ..Default::default() };
        assert!(problems_of(&manifest).is_empty());
    }

    #[test]
    fn an_empty_serve_is_refused() {
        let manifest = RepoManifest::default();
        let problems = problems_of(&manifest);
        assert!(problems.iter().any(|p| p.field.ends_with(".serve")), "{problems:?}");
    }

    #[test]
    fn a_present_but_empty_build_is_refused_rather_than_meaning_no_build_step() {
        let mut manifest = valid();
        manifest.build = Some(Vec::new());
        let problems = problems_of(&manifest);
        assert!(problems.iter().any(|p| p.field.ends_with(".build")), "{problems:?}");
    }

    #[test]
    fn an_absent_build_is_fine_and_means_no_build_step() {
        let mut manifest = valid();
        manifest.build = None;
        assert!(problems_of(&manifest).is_empty());
    }

    #[test]
    fn a_zero_port_is_refused() {
        let mut manifest = valid();
        manifest.port = Some(0);
        let problems = problems_of(&manifest);
        assert!(problems.iter().any(|p| p.field.ends_with(".port")), "{problems:?}");
    }

    #[test]
    fn an_out_of_range_port_does_not_parse_as_a_u16_in_the_first_place() {
        // Garbage like 99999 cannot even be represented in the field's type,
        // so the refusal happens at TOML parse time rather than in `check`.
        let text = "serve = [\"node\", \"server.js\"]\nport = 99999\n";
        assert!(RepoManifest::parse(text).is_err());
    }

    #[test]
    fn an_empty_health_path_is_refused_rather_than_treated_as_none() {
        let mut manifest = valid();
        manifest.health_path = Some(String::new());
        let problems = problems_of(&manifest);
        assert!(problems.iter().any(|p| p.field.ends_with(".health_path")), "{problems:?}");
    }

    #[test]
    fn an_env_key_with_an_equals_sign_is_refused() {
        let mut manifest = valid();
        manifest.env = BTreeMap::from([("BAD=KEY".into(), "x".into())]);
        let problems = problems_of(&manifest);
        assert!(problems.iter().any(|p| p.field.ends_with(".env")), "{problems:?}");
    }

    #[test]
    fn parse_reports_every_problem_at_once() {
        let text = "serve = []\nbuild = []\nport = 0\n";
        match RepoManifest::parse(text) {
            Err(crate::ConfigError::Invalid(problems)) => {
                assert!(problems.len() >= 3, "expected several problems, got {problems:?}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn parse_accepts_a_realistic_document() {
        let text = r#"
serve = ["node", "server.js"]
build = ["npm", "ci"]
port = 5050
health_path = "/healthz"

[env]
NODE_ENV = "production"
"#;
        let manifest = RepoManifest::parse(text).expect("valid");
        assert_eq!(manifest.serve, vec!["node".to_owned(), "server.js".to_owned()]);
        assert_eq!(manifest.port, Some(5050));
        assert_eq!(manifest.env.get("NODE_ENV").map(String::as_str), Some("production"));
    }
}
