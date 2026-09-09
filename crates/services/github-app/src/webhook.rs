//! Parsing GitHub webhook deliveries into typed events, and a delivery-log
//! record shape for a later increment to persist.
//!
//! This module is pure: no network, no file I/O, no clock reads. GitHub names
//! the event kind in the `X-GitHub-Event` header and puts the payload in the
//! request body — [`parse_event`] takes both as plain values and returns a
//! [`GithubEvent`]. The HTTP receiver (a later increment, in
//! `crates/app/proxy/src/server.rs`) already has its own `signature_matches`
//! HMAC check; this module never re-derives or trusts a signature itself.
//!
//! # Push events carry no commit to act on
//!
//! Per `crates/services/git/src/nudge.rs`'s `Nudge` design — a push arriving
//! is a signal to re-check reality (`ls-remote`), never a payload whose
//! contents are trusted and acted on directly — [`PushEvent`] deliberately
//! carries only `(owner, repo, git_ref)`, enough to know *what* to nudge.
//! GitHub's push payload includes a `head_commit` SHA and full commit list;
//! this type does not surface either, so a caller cannot accidentally deploy
//! a SHA lifted straight from an unauthenticated-until-checked webhook body.

use selfhost_json::Json;

/// One parsed GitHub webhook event, tagged by kind.
///
/// [`GithubEvent::Unhandled`] covers any `X-GitHub-Event` header this crate
/// does not yet interpret (`pull_request`, `release`, ...) so a caller can
/// log-and-ignore rather than the parse failing outright.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GithubEvent {
    /// A GitHub App installation was created, deleted, suspended, etc.
    Installation(InstallationEvent),
    /// The set of repositories an installation can access changed.
    InstallationRepositories(InstallationRepositoriesEvent),
    /// A push landed on a branch of a repository this App can see.
    Push(PushEvent),
    /// Any event kind not yet handled; carries the raw `X-GitHub-Event` value.
    Unhandled(String),
}

/// What happened to a GitHub App installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallationAction {
    /// The App was newly installed on an account.
    Created,
    /// The App was uninstalled from an account.
    Deleted,
    /// Any other action GitHub sends (`suspend`, `unsuspend`,
    /// `new_permissions_accepted`, ...), captured verbatim rather than
    /// rejected, so a caller can log and ignore it.
    Other(String),
}

impl InstallationAction {
    fn from_str(action: &str) -> Self {
        match action {
            "created" => InstallationAction::Created,
            "deleted" => InstallationAction::Deleted,
            other => InstallationAction::Other(other.to_owned()),
        }
    }
}

/// GitHub's `installation` webhook event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationEvent {
    /// What happened to the installation.
    pub action: InstallationAction,
    /// The installation's numeric id.
    pub installation_id: u64,
    /// The login of the account (user or org) the App is installed on.
    pub account_login: String,
}

/// A single `owner/name` repository reference, as GitHub's `full_name` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoRef {
    /// The repository owner's login.
    pub owner: String,
    /// The repository's name, without the owner prefix.
    pub name: String,
}

impl RepoRef {
    /// Splits a GitHub `full_name` (`"owner/name"`) into a [`RepoRef`].
    ///
    /// Errors if the string does not contain exactly one `/`.
    fn from_full_name(full_name: &str) -> Result<Self, WebhookParseError> {
        let mut parts = full_name.split('/');
        let owner = parts.next();
        let name = parts.next();
        let extra = parts.next();
        match (owner, name, extra) {
            (Some(owner), Some(name), None) if !owner.is_empty() && !name.is_empty() => {
                Ok(RepoRef { owner: owner.to_owned(), name: name.to_owned() })
            }
            _ => Err(WebhookParseError::MalformedFullName(full_name.to_owned())),
        }
    }
}

/// GitHub's `installation_repositories` webhook event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallationRepositoriesEvent {
    /// The installation's numeric id.
    pub installation_id: u64,
    /// The login of the account (user or org) the App is installed on.
    pub account_login: String,
    /// Repositories newly granted to the installation.
    pub repositories_added: Vec<RepoRef>,
    /// Repositories removed from the installation.
    pub repositories_removed: Vec<RepoRef>,
}

/// GitHub's `push` webhook event, reduced to only what a deploy-trigger needs
/// to know *what* to nudge — never a commit to act on directly (see the
/// module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushEvent {
    /// The repository owner's login.
    pub owner: String,
    /// The repository name.
    pub repo: String,
    /// The full ref that was pushed to, e.g. `"refs/heads/main"`.
    pub git_ref: String,
}

/// Everything that can go wrong parsing a webhook delivery body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookParseError {
    /// The body was not valid JSON at all.
    MalformedJson(String),
    /// A field this event kind requires was absent or the wrong type.
    MissingField(&'static str),
    /// A `full_name`-shaped field did not split into exactly one `/`.
    MalformedFullName(String),
}

impl std::fmt::Display for WebhookParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebhookParseError::MalformedJson(detail) => write!(f, "malformed webhook JSON: {detail}"),
            WebhookParseError::MissingField(field) => write!(f, "webhook body missing field \"{field}\""),
            WebhookParseError::MalformedFullName(full_name) => {
                write!(f, "expected \"owner/name\", got: {full_name}")
            }
        }
    }
}

impl std::error::Error for WebhookParseError {}

/// Parses one webhook delivery: `event_header` is the `X-GitHub-Event` header
/// value, `body` is the raw JSON bytes GitHub POSTed.
///
/// An `event_header` this crate does not yet interpret produces
/// [`GithubEvent::Unhandled`] rather than an error — GitHub adds new event
/// kinds and re-sends existing ones with new actions over time, and a caller
/// should be able to log-and-ignore rather than have the whole delivery fail.
pub fn parse_event(event_header: &str, body: &[u8]) -> Result<GithubEvent, WebhookParseError> {
    match event_header {
        "installation" => Ok(GithubEvent::Installation(parse_installation(body)?)),
        "installation_repositories" => {
            Ok(GithubEvent::InstallationRepositories(parse_installation_repositories(body)?))
        }
        "push" => Ok(GithubEvent::Push(parse_push(body)?)),
        other => Ok(GithubEvent::Unhandled(other.to_owned())),
    }
}

/// Parses raw bytes into [`Json`], mapping any failure to
/// [`WebhookParseError::MalformedJson`].
fn parse_json(body: &[u8]) -> Result<Json, WebhookParseError> {
    let text = std::str::from_utf8(body)
        .map_err(|error| WebhookParseError::MalformedJson(error.to_string()))?;
    selfhost_json::parse(text).map_err(|error| WebhookParseError::MalformedJson(error.to_string()))
}

fn parse_installation(body: &[u8]) -> Result<InstallationEvent, WebhookParseError> {
    let json = parse_json(body)?;

    let action = json
        .get("action")
        .and_then(Json::as_str)
        .ok_or(WebhookParseError::MissingField("action"))?;

    let installation = json.get("installation").ok_or(WebhookParseError::MissingField("installation"))?;
    let installation_id =
        installation.get("id").and_then(Json::as_u64).ok_or(WebhookParseError::MissingField("installation.id"))?;
    let account_login = installation
        .get("account")
        .and_then(|account| account.get("login"))
        .and_then(Json::as_str)
        .ok_or(WebhookParseError::MissingField("installation.account.login"))?;

    Ok(InstallationEvent {
        action: InstallationAction::from_str(action),
        installation_id,
        account_login: account_login.to_owned(),
    })
}

fn parse_repo_refs(json: &Json, field: &'static str) -> Result<Vec<RepoRef>, WebhookParseError> {
    let array = json.get(field).and_then(Json::as_array).ok_or(WebhookParseError::MissingField(field))?;
    array
        .iter()
        .map(|entry| {
            let full_name =
                entry.get("full_name").and_then(Json::as_str).ok_or(WebhookParseError::MissingField(field))?;
            RepoRef::from_full_name(full_name)
        })
        .collect()
}

fn parse_installation_repositories(
    body: &[u8],
) -> Result<InstallationRepositoriesEvent, WebhookParseError> {
    let json = parse_json(body)?;

    let installation = json.get("installation").ok_or(WebhookParseError::MissingField("installation"))?;
    let installation_id =
        installation.get("id").and_then(Json::as_u64).ok_or(WebhookParseError::MissingField("installation.id"))?;
    let account_login = installation
        .get("account")
        .and_then(|account| account.get("login"))
        .and_then(Json::as_str)
        .ok_or(WebhookParseError::MissingField("installation.account.login"))?;

    let repositories_added = parse_repo_refs(&json, "repositories_added")?;
    let repositories_removed = parse_repo_refs(&json, "repositories_removed")?;

    Ok(InstallationRepositoriesEvent {
        installation_id,
        account_login: account_login.to_owned(),
        repositories_added,
        repositories_removed,
    })
}

fn parse_push(body: &[u8]) -> Result<PushEvent, WebhookParseError> {
    let json = parse_json(body)?;

    let git_ref =
        json.get("ref").and_then(Json::as_str).ok_or(WebhookParseError::MissingField("ref"))?;
    let full_name = json
        .get("repository")
        .and_then(|repository| repository.get("full_name"))
        .and_then(Json::as_str)
        .ok_or(WebhookParseError::MissingField("repository.full_name"))?;
    let repo_ref = RepoRef::from_full_name(full_name)?;

    Ok(PushEvent { owner: repo_ref.owner, repo: repo_ref.name, git_ref: git_ref.to_owned() })
}

/// A one-line, human-readable summary of a parsed [`GithubEvent`], for a
/// delivery log a later increment will append to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubEventSummary(String);

impl std::fmt::Display for GithubEventSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Builds a one-line summary of `event`, suitable for a delivery log.
pub fn summarize(event: &GithubEvent) -> GithubEventSummary {
    let text = match event {
        GithubEvent::Installation(installation) => {
            let action = match &installation.action {
                InstallationAction::Created => "created".to_owned(),
                InstallationAction::Deleted => "deleted".to_owned(),
                InstallationAction::Other(other) => other.clone(),
            };
            format!("installation {action} for {}", installation.account_login)
        }
        GithubEvent::InstallationRepositories(event) => format!(
            "installation_repositories for {} (+{} -{})",
            event.account_login,
            event.repositories_added.len(),
            event.repositories_removed.len()
        ),
        GithubEvent::Push(push) => format!("push {}/{} {}", push.owner, push.repo, push.git_ref),
        GithubEvent::Unhandled(kind) => format!("unhandled event: {kind}"),
    };
    GithubEventSummary(text)
}

/// The outcome of processing one webhook delivery, for [`WebhookDelivery`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryOutcome {
    /// The body parsed successfully into a [`GithubEvent`]; carries its summary.
    Parsed(GithubEventSummary),
    /// The delivery's signature failed verification and was never parsed.
    SignatureRejected,
    /// The body failed to parse; carries the error's display text.
    ParseFailed(String),
}

/// One row of a webhook delivery log: what arrived, whether its signature
/// checked out, and what came of it.
///
/// A later increment appends these to a log file; this type only defines the
/// shape — nothing in this module performs file I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebhookDelivery {
    /// When this delivery was received, as Unix seconds — always supplied by
    /// the caller, never read from the clock in this module.
    pub received_at_unix: u64,
    /// The `X-GitHub-Event` header value as received.
    pub event: &'static str,
    /// Whether the HMAC signature (verified elsewhere, by the proxy's
    /// existing `signature_matches`) checked out.
    pub signature_valid: bool,
    /// What came of processing the delivery.
    pub outcome: DeliveryOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;

    const INSTALLATION_CREATED: &str = r#"{
        "action": "created",
        "installation": {
            "id": 12345678,
            "account": { "login": "octocat", "type": "User" }
        },
        "repositories": [
            { "id": 1, "full_name": "octocat/hello-world" }
        ]
    }"#;

    const INSTALLATION_REPOSITORIES_ADDED: &str = r#"{
        "action": "added",
        "installation": {
            "id": 12345678,
            "account": { "login": "octocat", "type": "User" }
        },
        "repository_selection": "selected",
        "repositories_added": [
            { "id": 1, "full_name": "octocat/hello-world" }
        ],
        "repositories_removed": []
    }"#;

    const PUSH_TO_MAIN: &str = r#"{
        "ref": "refs/heads/main",
        "before": "0000000000000000000000000000000000000000",
        "after": "abcdef1234567890abcdef1234567890abcdef12",
        "repository": {
            "id": 1296269,
            "full_name": "octocat/hello-world"
        },
        "pusher": { "name": "octocat", "email": "octocat@github.com" },
        "head_commit": {
            "id": "abcdef1234567890abcdef1234567890abcdef12",
            "message": "fix: typo"
        }
    }"#;

    #[test]
    fn parses_an_installation_created_event() {
        let event = parse_event("installation", INSTALLATION_CREATED.as_bytes()).unwrap();
        assert_eq!(
            event,
            GithubEvent::Installation(InstallationEvent {
                action: InstallationAction::Created,
                installation_id: 12345678,
                account_login: "octocat".to_owned(),
            })
        );
    }

    #[test]
    fn parses_an_installation_repositories_added_event() {
        let event =
            parse_event("installation_repositories", INSTALLATION_REPOSITORIES_ADDED.as_bytes()).unwrap();
        assert_eq!(
            event,
            GithubEvent::InstallationRepositories(InstallationRepositoriesEvent {
                installation_id: 12345678,
                account_login: "octocat".to_owned(),
                repositories_added: vec![RepoRef { owner: "octocat".into(), name: "hello-world".into() }],
                repositories_removed: vec![],
            })
        );
    }

    #[test]
    fn parses_a_push_event_without_carrying_the_commit_sha() {
        let event = parse_event("push", PUSH_TO_MAIN.as_bytes()).unwrap();
        assert_eq!(
            event,
            GithubEvent::Push(PushEvent {
                owner: "octocat".into(),
                repo: "hello-world".into(),
                git_ref: "refs/heads/main".into(),
            })
        );
    }

    #[test]
    fn an_unrecognized_event_header_is_unhandled_not_an_error() {
        let event = parse_event("pull_request", b"{}").unwrap();
        assert_eq!(event, GithubEvent::Unhandled("pull_request".to_owned()));
    }

    #[test]
    fn a_truncated_body_is_malformed_json() {
        let result = parse_event("push", b"{\"ref\": \"refs/heads/main\"");
        assert!(matches!(result, Err(WebhookParseError::MalformedJson(_))));
    }

    #[test]
    fn a_push_missing_the_ref_field_is_reported() {
        let body = br#"{"repository": {"full_name": "octocat/hello-world"}}"#;
        let result = parse_event("push", body);
        assert!(matches!(result, Err(WebhookParseError::MissingField("ref"))));
    }

    #[test]
    fn a_full_name_without_a_slash_is_malformed() {
        let body = br#"{"ref": "refs/heads/main", "repository": {"full_name": "not-a-full-name"}}"#;
        let result = parse_event("push", body);
        assert!(matches!(result, Err(WebhookParseError::MalformedFullName(_))));
    }

    #[test]
    fn a_full_name_with_two_slashes_is_malformed() {
        let body = br#"{"ref": "refs/heads/main", "repository": {"full_name": "a/b/c"}}"#;
        let result = parse_event("push", body);
        assert!(matches!(result, Err(WebhookParseError::MalformedFullName(_))));
    }

    #[test]
    fn summarizes_a_push_event_on_one_line() {
        let event = parse_event("push", PUSH_TO_MAIN.as_bytes()).unwrap();
        let summary = summarize(&event).to_string();
        assert_eq!(summary, "push octocat/hello-world refs/heads/main");
    }

    #[test]
    fn summarizes_an_installation_created_event() {
        let event = parse_event("installation", INSTALLATION_CREATED.as_bytes()).unwrap();
        let summary = summarize(&event).to_string();
        assert_eq!(summary, "installation created for octocat");
    }
}
