//! Minting and caching installation access tokens.
//!
//! GitHub installation tokens are short-lived (one hour) and must be re-minted
//! per installation. [`InstallationTokenCache`] holds the freshest token this
//! process has seen per installation, in memory only — nothing here is ever
//! written to disk. The pure parts (deciding whether a cached token is still
//! usable, building the mint request, parsing the response) are split from the
//! network call itself, so they carry unit tests that never touch a socket —
//! same split as `crates/services/git/src/plan.rs`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::Mutex;

use crate::jwt::app_jwt;
use crate::transport::HttpsClient;
use crate::{AppCredentials, GithubAppError};

/// GitHub's own installation-token host.
const API_HOST: &str = "api.github.com";

/// Identifies this client to GitHub, which refuses requests with none.
const USER_AGENT: &str = "selfhost-github-app/0.1";

/// Re-mint a cached token this long before its real expiry.
///
/// GitHub tokens live one hour; refreshing fifteen minutes early absorbs clock
/// skew and the time a caller spends actually using the token, so a deploy that
/// starts just under the wire never hands a request a token that expires
/// mid-flight.
const REFRESH_MARGIN: Duration = Duration::from_secs(900);

/// One cached installation token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedToken {
    /// The token value, as GitHub returned it.
    pub token: String,
    /// When GitHub says this token stops working.
    pub expires_at: SystemTime,
}

impl CachedToken {
    /// Whether this token is still safe to hand out at `now`, honoring
    /// [`REFRESH_MARGIN`].
    fn is_fresh(&self, now: SystemTime) -> bool {
        match self.expires_at.checked_sub(REFRESH_MARGIN) {
            Some(refresh_at) => now < refresh_at,
            // expires_at is closer to the epoch than the margin: never fresh.
            None => false,
        }
    }
}

/// An in-memory cache of installation access tokens, one per installation id.
///
/// Cheap to clone: the map lives behind an `Arc<Mutex<_>>`, so every clone
/// shares the same cache — the shape a shared service (a deploy bot handling
/// many installations concurrently) needs.
#[derive(Clone, Default)]
pub struct InstallationTokenCache {
    tokens: Arc<Mutex<HashMap<u64, CachedToken>>>,
}

impl InstallationTokenCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns a usable token for `installation_id`, minting a fresh one via
    /// `credentials` and `client` when the cached one (if any) is missing or
    /// within [`REFRESH_MARGIN`] of expiry.
    pub async fn token_for(
        &self,
        installation_id: u64,
        credentials: &AppCredentials,
        client: &HttpsClient,
        now: SystemTime,
    ) -> Result<String, GithubAppError> {
        {
            let cache = self.tokens.lock().await;
            if let Some(cached) = cache.get(&installation_id) {
                if cached.is_fresh(now) {
                    return Ok(cached.token.clone());
                }
            }
        }

        let key_der = credentials.load()?;
        let jwt = app_jwt(credentials.app_id, &key_der, now)?;
        let headers = mint_request_headers(&jwt);
        let path = mint_path(installation_id);

        let response = client
            .request(API_HOST, "POST", &path, &headers, b"")
            .await?;

        if response.status.0 < 200 || response.status.0 >= 300 {
            return Err(GithubAppError::Api {
                status: response.status.0,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            });
        }

        let cached = parse_token_response(&response.body)?;
        self.tokens.lock().await.insert(installation_id, cached.clone());
        Ok(cached.token)
    }
}

/// The headers a token-mint request always carries.
fn mint_request_headers(jwt: &str) -> Vec<(String, String)> {
    vec![
        ("Authorization".to_owned(), format!("Bearer {jwt}")),
        ("Accept".to_owned(), "application/vnd.github+json".to_owned()),
        ("X-GitHub-Api-Version".to_owned(), "2022-11-28".to_owned()),
        ("User-Agent".to_owned(), USER_AGENT.to_owned()),
    ]
}

/// The request path for minting an installation token.
fn mint_path(installation_id: u64) -> String {
    format!("/app/installations/{installation_id}/access_tokens")
}

/// Parses GitHub's `{"token": "...", "expires_at": "2026-01-01T00:00:00Z", ...}`
/// response into a [`CachedToken`].
fn parse_token_response(body: &[u8]) -> Result<CachedToken, GithubAppError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| GithubAppError::InvalidResponse("response body was not UTF-8".into()))?;
    let json = selfhost_json::parse(text)
        .map_err(|error| GithubAppError::InvalidResponse(format!("response was not JSON: {error}")))?;

    let token = json
        .get("token")
        .and_then(selfhost_json::Json::as_str)
        .ok_or_else(|| GithubAppError::InvalidResponse("response had no \"token\" field".into()))?
        .to_owned();

    let expires_at_text = json
        .get("expires_at")
        .and_then(selfhost_json::Json::as_str)
        .ok_or_else(|| GithubAppError::InvalidResponse("response had no \"expires_at\" field".into()))?;

    let expires_at_unix = parse_iso8601_utc(expires_at_text).ok_or_else(|| {
        GithubAppError::InvalidResponse(format!("could not parse \"expires_at\": {expires_at_text}"))
    })?;

    let expires_at = SystemTime::UNIX_EPOCH + Duration::from_secs(expires_at_unix.max(0) as u64);

    Ok(CachedToken { token, expires_at })
}

/// Parses a `YYYY-MM-DDTHH:MM:SSZ` timestamp (GitHub's `expires_at` shape,
/// RFC 3339 UTC) into seconds since the Unix epoch.
///
/// `crates/foundation/http::date` deliberately parses only the RFC 9110
/// `IMF-fixdate` form GitHub does not use here, so this is a second, minimal
/// parser rather than a misuse of that one — GitHub's format is fixed-width
/// and always `Z`, so the grammar is a straight field split, using the same
/// proleptic-Gregorian day count (Howard Hinnant's `days_from_civil`) that
/// module uses internally.
fn parse_iso8601_utc(text: &str) -> Option<i64> {
    let text = text.trim().strip_suffix('Z')?;
    let (date, time) = text.split_once('T')?;

    let mut date_parts = date.split('-');
    let year: i64 = date_parts.next()?.parse().ok()?;
    let month: u32 = date_parts.next()?.parse().ok()?;
    let day: u32 = date_parts.next()?.parse().ok()?;
    if date_parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }

    let mut time_parts = time.split(':');
    let hour: i64 = time_parts.next()?.parse().ok()?;
    let minute: i64 = time_parts.next()?.parse().ok()?;
    let second: i64 = time_parts.next()?.parse().ok()?;
    if time_parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }

    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// Converts a civil year, month, and day into a day count since 1970-01-01.
///
/// Identical algorithm to the private `days_from_civil` in
/// `crates/foundation/http/src/date.rs` — not reused because that module keeps
/// it private (only its public `format`/`parse` are meant as the API surface).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = (year - era * 400) as u64;
    let month = month as u64;
    let day_of_year = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day as u64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era as i64 - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_path_addresses_the_right_installation() {
        assert_eq!(mint_path(42), "/app/installations/42/access_tokens");
    }

    #[test]
    fn mint_headers_carry_a_bearer_jwt_and_required_github_headers() {
        let headers = mint_request_headers("abc.def.ghi");
        assert!(headers.contains(&("Authorization".to_owned(), "Bearer abc.def.ghi".to_owned())));
        assert!(headers.iter().any(|(k, v)| k == "Accept" && v.contains("vnd.github+json")));
        assert!(headers.iter().any(|(k, v)| k == "X-GitHub-Api-Version" && v == "2022-11-28"));
        assert!(headers.iter().any(|(k, _)| k == "User-Agent"));
    }

    #[test]
    fn parses_a_well_formed_token_response() {
        let body = br#"{"token":"ghs_abc123","expires_at":"2030-01-01T00:00:00Z","permissions":{}}"#;
        let cached = parse_token_response(body).unwrap();
        assert_eq!(cached.token, "ghs_abc123");
        assert!(cached.expires_at > SystemTime::UNIX_EPOCH);
    }

    #[test]
    fn a_response_missing_the_token_field_is_rejected() {
        let body = br#"{"expires_at":"2030-01-01T00:00:00Z"}"#;
        assert!(matches!(parse_token_response(body), Err(GithubAppError::InvalidResponse(_))));
    }

    #[test]
    fn a_response_that_is_not_json_is_rejected() {
        assert!(matches!(parse_token_response(b"not json"), Err(GithubAppError::InvalidResponse(_))));
    }

    #[test]
    fn a_token_well_inside_its_lifetime_is_fresh() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let cached = CachedToken { token: "t".into(), expires_at: now + Duration::from_secs(3600) };
        assert!(cached.is_fresh(now));
    }

    #[test]
    fn a_token_inside_the_refresh_margin_is_not_fresh() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        // Exactly at the boundary: expires_at - margin == now, so `now < refresh_at` is false.
        let cached = CachedToken { token: "t".into(), expires_at: now + REFRESH_MARGIN };
        assert!(!cached.is_fresh(now));
    }

    #[test]
    fn a_token_one_second_before_the_margin_boundary_is_still_fresh() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let cached =
            CachedToken { token: "t".into(), expires_at: now + REFRESH_MARGIN + Duration::from_secs(1) };
        assert!(cached.is_fresh(now));
    }

    #[test]
    fn an_already_expired_token_is_not_fresh() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        let cached = CachedToken { token: "t".into(), expires_at: now - Duration::from_secs(10) };
        assert!(!cached.is_fresh(now));
    }

    #[test]
    fn parses_a_github_expires_at_timestamp() {
        assert_eq!(parse_iso8601_utc("2030-01-01T00:00:00Z"), Some(1_893_456_000));
    }

    #[test]
    fn rejects_a_timestamp_without_a_trailing_z() {
        assert_eq!(parse_iso8601_utc("2030-01-01T00:00:00"), None);
    }

    #[tokio::test]
    async fn a_fresh_cached_token_is_returned_without_touching_credentials_or_network() {
        // No credentials/client are exercised on this path: a bogus AppCredentials
        // pointing at a nonexistent file would fail `load()` if it were ever
        // reached, proving the fresh-cache branch never calls it.
        let cache = InstallationTokenCache::new();
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        cache
            .tokens
            .lock()
            .await
            .insert(7, CachedToken { token: "cached-token".into(), expires_at: now + Duration::from_secs(3600) });

        let credentials = AppCredentials {
            app_id: 4606064,
            private_key_pkcs8_pem_path: "/nonexistent/does-not-exist.pem".into(),
        };
        let client = HttpsClient::new().unwrap();

        let token = cache.token_for(7, &credentials, &client, now).await.unwrap();
        assert_eq!(token, "cached-token");
    }
}
