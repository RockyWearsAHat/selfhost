//! Bridging this crate's installation-token cache to [`selfhost_git::CredentialSource`],
//! so a watched repository the App has installed is fetched over authenticated
//! HTTPS instead of needing a static SSH deploy key.
//!
//! Kept in this crate (not `selfhost-git`) because it is the one place that
//! already holds an [`AppCredentials`] and a [`Store`] together — `selfhost-git`
//! only ever sees the trait, never these concrete types.

use std::future::Future;
use std::pin::Pin;
use std::time::SystemTime;

use selfhost_git::CredentialSource;

use crate::store::parse_owner_repo;
use crate::token::InstallationTokenCache;
use crate::{AppCredentials, Store};

/// A [`CredentialSource`] backed by this box's GitHub App installation and
/// token cache.
///
/// `authenticated_url` answers `None` — not an error — for any repository
/// that is not `github.com`, or is `github.com` but not tracked by an
/// installation this App has: both leave the caller's existing unauthenticated
/// or SSH behavior untouched, which is the whole point of a fallback-shaped
/// trait rather than a `Result`.
pub struct AppCredentialSource {
    credentials: AppCredentials,
    store: Store,
    tokens: InstallationTokenCache,
}

impl AppCredentialSource {
    /// Builds a source from the App's identity, its installation store, and a
    /// fresh (empty) token cache.
    pub fn new(credentials: AppCredentials, store: Store) -> Self {
        Self { credentials, store, tokens: InstallationTokenCache::new() }
    }

    /// The installation id this App has for `owner/repo`, if any — read from
    /// the store fresh each call, since a repo can be added or removed at any
    /// time by an `installation_repositories` webhook.
    fn installation_for(&self, owner: &str, repo: &str) -> Option<u64> {
        let state = self.store.state().ok()?;
        state
            .installations
            .into_iter()
            .find(|installation| {
                installation
                    .repos
                    .iter()
                    .any(|tracked| tracked.owner.eq_ignore_ascii_case(owner) && tracked.name.eq_ignore_ascii_case(repo))
            })
            .map(|installation| installation.installation_id)
    }
}

impl CredentialSource for AppCredentialSource {
    fn authenticated_url(&self, repository: &str) -> Pin<Box<dyn Future<Output = Option<String>> + Send + '_>> {
        let repository = repository.to_owned();
        Box::pin(async move {
            let (owner, repo) = parse_owner_repo(&repository)?;
            let installation_id = self.installation_for(&owner, &repo)?;

            let client = crate::transport::HttpsClient::new().ok()?;
            let now = SystemTime::now();
            let token = self.tokens.token_for(installation_id, &self.credentials, &client, now).await.ok()?;

            Some(selfhost_git::plan::authenticated_url(&owner, &repo, &token))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhook::RepoRef;

    fn scratch_store(name: &str) -> Store {
        let path = std::env::temp_dir()
            .join(format!("selfhost-github-app-credentials-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Store::load(path.join("github-installations.toml")).unwrap()
    }

    fn source(store: Store) -> AppCredentialSource {
        let credentials = AppCredentials { app_id: 1, private_key_pkcs8_pem_path: "/nonexistent.pem".into() };
        AppCredentialSource::new(credentials, store)
    }

    #[test]
    fn installation_for_finds_a_tracked_repo_case_insensitively() {
        let store = scratch_store("found");
        store.upsert_installation(42, "RockyWearsAHat").unwrap();
        store.add_repos(42, &[RepoRef { owner: "RockyWearsAHat".into(), name: "ai-studio".into() }]).unwrap();

        let source = source(store);
        assert_eq!(source.installation_for("rockywearsahat", "AI-Studio"), Some(42));
    }

    #[test]
    fn installation_for_is_none_when_the_repo_is_not_tracked() {
        let store = scratch_store("untracked");
        store.upsert_installation(42, "RockyWearsAHat").unwrap();
        store.add_repos(42, &[RepoRef { owner: "RockyWearsAHat".into(), name: "ai-studio".into() }]).unwrap();

        let source = source(store);
        assert_eq!(source.installation_for("rockywearsahat", "some-other-repo"), None);
    }

    #[tokio::test]
    async fn authenticated_url_is_none_for_an_untracked_repository_without_touching_the_network() {
        // No credentials/network are exercised: the App-key path would fail
        // `AppCredentials::load()` (a nonexistent path) if it were ever reached,
        // so reaching `None` here proves the untracked-repo short circuit works.
        let store = scratch_store("no-network");
        let source = source(store);

        let url = source.authenticated_url("https://github.com/rockywearsahat/untracked-repo.git").await;
        assert_eq!(url, None);
    }

    #[tokio::test]
    async fn authenticated_url_is_none_for_a_non_github_remote() {
        let store = scratch_store("non-github");
        let source = source(store);

        let url = source.authenticated_url("https://example.com/owner/repo.git").await;
        assert_eq!(url, None);
    }
}
