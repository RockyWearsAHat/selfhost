//! What a report is, which project it is *about*, and what this box accepts as one.
//!
//! Everything in this module treats its input as hostile, because the intake is open to the
//! internet: a report arrives from an agent on a machine nobody here administers, and the
//! text in it goes on to become a database record, a mail header, and — once a subscribed
//! checkout syncs — a block in that project's own `reports.dx`. Three consequences shape the
//! module:
//!
//! - **Single-line fields are made single-line here, once.** [`one_line`] collapses every run
//!   of whitespace — CR and LF included — into one space, so a title carrying
//!   `\r\nBcc: someone@else` cannot become a second header when [`crate::notify`] writes
//!   `Subject:`. The header-injection defence lives at the parse boundary rather than at the
//!   place that formats a message, because there is one parse boundary and there will be more
//!   than one formatter.
//! - **Identity fields are refused when too long; content fields are truncated.** A 4 KB
//!   "title" is a mistake worth telling the reporter about; a long detail is a reporter being
//!   thorough, and cutting it is better than losing the report.
//! - **A report names the project it is about, not the machine it came from.** `project` is
//!   the subscribable key — `dx` — and it must be one the box already knows; `workspace` is
//!   the *name* of the folder the reporter was standing in, never its path.
//!
//! # The fingerprint is the identity, and it is computed here
//!
//! A report's id is `report-` and the first eight hex digits of the SHA-256 of its kind, its
//! lowercased title, and its lowercased route — deliberately the same recipe `dx` uses for the
//! block id in `reports.dx`, so the id an agent is told locally, the id this box stores, and
//! the block id a subscribed checkout ends up with are one string. It is computed from the
//! cleaned fields and never read from the request: a client that could choose its own id could
//! overwrite another report's record.

use ring::digest::{digest, SHA256};
use selfhost_json::Json;

/// Longest accepted title. Longer is refused: the title is identity, and one that does not
/// fit on a line is a paste that would fingerprint as its own defect forever.
pub const MAX_TITLE: usize = 200;
/// Longest accepted route (the tool or surface involved). Refused when longer.
pub const MAX_ROUTE: usize = 120;
/// Longest accepted project key. Refused when longer.
pub const MAX_PROJECT: usize = 40;
/// Longest accepted workspace name. Refused when longer.
pub const MAX_WORKSPACE: usize = 120;
/// Longest accepted reporter name and version, e.g. `dx 0.1.0`. Refused when longer.
pub const MAX_TOOL: usize = 60;
/// Longest accepted platform word. Refused when longer.
pub const MAX_PLATFORM: usize = 40;
/// Longest kept detail. A longer one is truncated rather than refused.
pub const MAX_DETAIL: usize = 8_000;
/// Longest kept reproduction. A longer one is truncated rather than refused.
pub const MAX_REPRO: usize = 2_000;

/// What is appended to a field this crate had to cut.
const TRUNCATED: &str = " […]";

/// What kind of thing is being reported.
///
/// The same three words `dx` files under, because a report that changes kind in transit is a
/// report that cannot be matched to the one the reporter can see locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Something the tool did wrong.
    Bug,
    /// Something it could do better.
    Suggestion,
    /// How it behaved, with no claim about whether that is wrong.
    Observation,
}

impl Kind {
    /// The kind named by `word`, case-insensitively.
    ///
    /// # Errors
    /// Returns a sentence naming the three words that work, because the caller is usually an
    /// agent that guessed a synonym and can correct itself from the message.
    pub fn parse(word: &str) -> Result<Self, String> {
        match word.trim().to_ascii_lowercase().as_str() {
            "bug" => Ok(Self::Bug),
            "suggestion" | "feature" | "request" => Ok(Self::Suggestion),
            "observation" | "note" => Ok(Self::Observation),
            other => Err(format!(
                "`{}` is not a report kind — it is bug, suggestion, or observation",
                one_line(other).chars().take(40).collect::<String>()
            )),
        }
    }

    /// The word this kind is written as, everywhere.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bug => "bug",
            Self::Suggestion => "suggestion",
            Self::Observation => "observation",
        }
    }
}

/// One report, cleaned and stamped by this box.
///
/// Every string field has already been through [`one_line`] or [`lines`]: no control
/// characters survive, so nothing downstream has to remember to escape them again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// The project this is about — the key a checkout subscribes to.
    pub project: String,
    /// What kind of thing this is.
    pub kind: Kind,
    /// One line naming the defect. Part of the identity.
    pub title: String,
    /// What happened, what was expected, and anything else the fixer needs.
    pub detail: String,
    /// The tool, command, or surface involved. Part of the identity.
    pub route: String,
    /// The smallest sequence that shows it, when the reporter has one.
    pub repro: String,
    /// The reporter and its version, as the reporter names itself — `dx 0.1.0`.
    pub tool: String,
    /// The operating system it happened on.
    pub platform: String,
    /// The name of the folder the reporter was working in — a name, never a path.
    pub workspace: String,
    /// When this box accepted it, ISO-8601 UTC. The reporter's own clock is not trusted.
    pub at: String,
    /// A one-way, truncated hash of the source address — enough to see that fifty reports came
    /// from one place, not enough to be a record of who filed what.
    pub source: String,
}

/// Why a request was not accepted as a report.
///
/// Every variant is a client error: the message is written to be read by the agent that sent
/// it, so it says what to change rather than what went wrong internally.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal(String);

impl Refusal {
    /// A refusal carrying `message`.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The sentence the reporter is given.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

impl Report {
    /// Reads one report out of a decoded JSON body, stamping it with `at` and `source`.
    ///
    /// `kind`, `title` and `detail` are required; everything else is optional and becomes an
    /// empty string when missing, so a minimal reporter is still a reporter. A body with no
    /// `project` is about `default_project`, which is what lets `curl` file a dx report with
    /// three fields.
    ///
    /// **`workspace` is a name, not a path.** A reporter that sends
    /// `/Users/someone/code/App` has the value reduced to `App`: the intake is public, and an
    /// absolute path is somebody else's directory layout, which this box has no business
    /// storing.
    ///
    /// # Errors
    /// Returns a [`Refusal`] naming the field to fix: a body that is not an object, an unknown
    /// kind, an empty title or detail, a project key that is not a key, or an identity field
    /// over its cap. Whether the project *exists* is decided by [`crate::store`], not here.
    pub fn parse(
        body: &Json,
        default_project: &str,
        at: String,
        source: String,
    ) -> Result<Self, Refusal> {
        if body.get("kind").is_none() && body.get("title").is_none() {
            return Err(Refusal(
                "a report is a JSON object with at least `kind`, `title` and `detail`".to_string(),
            ));
        }
        let text = |key: &str| body.get(key).and_then(Json::as_str).unwrap_or_default();

        let named = text("project").trim();
        let project = if named.is_empty() {
            default_project.to_string()
        } else {
            project_key(named)?
        };

        let kind = Kind::parse(text("kind")).map_err(Refusal)?;
        let title = one_line(text("title"));
        if title.is_empty() {
            return Err(Refusal(
                "`title` is required: one line naming what went wrong".to_string(),
            ));
        }
        if title.chars().count() > MAX_TITLE {
            return Err(Refusal(format!(
                "`title` is longer than {MAX_TITLE} characters — that belongs in `detail`"
            )));
        }
        let detail = lines(text("detail"), MAX_DETAIL);
        if detail.is_empty() {
            return Err(Refusal(
                "`detail` is required: what you did, what you expected, what happened instead"
                    .to_string(),
            ));
        }
        let route = capped(one_line(text("route")), MAX_ROUTE, "route")?;
        let workspace = capped(folder_name(text("workspace")), MAX_WORKSPACE, "workspace")?;
        let tool = capped(one_line(text("tool")), MAX_TOOL, "tool")?;
        let platform = capped(one_line(text("platform")), MAX_PLATFORM, "platform")?;

        Ok(Self {
            project,
            kind,
            title,
            detail,
            route,
            repro: lines(text("repro"), MAX_REPRO),
            tool,
            platform,
            workspace,
            at,
            source,
        })
    }

    /// The id this report is stored under: `report-` and eight hex digits of its identity.
    ///
    /// The identity is the kind, the lowercased title and the lowercased route — never the
    /// detail, which two reporters describing one defect will always word differently. Two
    /// sightings of the same thing therefore land on one record with a count, which is what
    /// makes *how often does this happen* answerable.
    #[must_use]
    pub fn id(&self) -> String {
        let identity = format!(
            "{}\n{}\n{}",
            self.kind.as_str(),
            self.title.to_lowercase(),
            self.route.to_lowercase()
        );
        format!("report-{}", &hex(identity.as_bytes())[..8])
    }
}

/// The canonical form of a project key: lowercase, `[a-z0-9-]`, no leading or trailing dash.
///
/// A key names a directory in the database and appears in a URL, so it is validated rather
/// than escaped — an intake that accepted `../../` as a project name would be a write
/// primitive, and one that accepted anything at all would let a stranger create directories
/// until the disk filled.
///
/// # Errors
/// Returns a [`Refusal`] naming what a key may contain.
pub fn project_key(value: &str) -> Result<String, Refusal> {
    let lowered = one_line(value).to_lowercase();
    let key: String = lowered
        .chars()
        .map(|character| if character == '_' || character == ' ' { '-' } else { character })
        .collect();
    let trimmed = key.trim_matches('-');
    let legal = !trimmed.is_empty()
        && trimmed.chars().count() <= MAX_PROJECT
        && trimmed
            .chars()
            .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-');
    if !legal {
        return Err(Refusal(format!(
            "`{}` is not a project key — a key is 1 to {MAX_PROJECT} characters of a-z, 0-9 and -",
            trimmed.chars().take(40).collect::<String>()
        )));
    }
    Ok(trimmed.to_string())
}

/// A short, one-way hash of `address`, used as [`Report::source`].
///
/// Eight hex digits over the address and a fixed label: enough to group a flood, and not a
/// stored record of which address filed which report. It is not a secret and is not treated as
/// one — an address space small enough to enumerate is reversible by anyone who wants to,
/// which is exactly why nothing in this crate makes a decision from it.
#[must_use]
pub fn source_hash(address: &str) -> String {
    hex(format!("selfhost-reports\n{address}").as_bytes())[..8].to_string()
}

/// Lowercase hex of the SHA-256 of `bytes`.
fn hex(bytes: &[u8]) -> String {
    digest(&SHA256, bytes)
        .as_ref()
        .iter()
        .fold(String::new(), |mut out, byte| {
            out.push_str(&format!("{byte:02x}"));
            out
        })
}

/// Collapses every run of whitespace — including CR, LF and other control characters — into a
/// single space, and trims.
///
/// This is what makes a field safe to write into a mail header, and it is why the check is here
/// and not there: a value that has been through this function cannot carry a line break,
/// whoever formats it later.
#[must_use]
pub fn one_line(text: &str) -> String {
    text.chars()
        .map(|character| if character.is_control() { ' ' } else { character })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Normalises a multi-line field: CRLF becomes LF, other control characters become spaces, the
/// result is trimmed, and anything past `max` characters is cut with a marker.
///
/// Truncation rather than refusal, because a long detail is a thorough reporter and the report
/// is worth more than the tail of it.
#[must_use]
pub fn lines(text: &str, max: usize) -> String {
    let normalised: String = text
        .replace("\r\n", "\n")
        .chars()
        .map(|character| match character {
            '\n' | '\t' => character,
            other if other.is_control() => ' ',
            other => other,
        })
        .collect();
    let trimmed = normalised.trim();
    if trimmed.chars().count() <= max {
        return trimmed.to_string();
    }
    let cut: String = trimmed.chars().take(max).collect();
    format!("{cut}{TRUNCATED}")
}

/// Refuses `value` when it is longer than `max`, naming the field.
fn capped(value: String, max: usize, field: &str) -> Result<String, Refusal> {
    if value.chars().count() > max {
        return Err(Refusal(format!("`{field}` is longer than {max} characters")));
    }
    Ok(value)
}

/// The last component of whatever the reporter called its workspace.
///
/// A reporter that sends a path gets its basename stored; one that sends a name gets the name
/// back. Both separators are handled, because the reporter may be on Windows.
fn folder_name(value: &str) -> String {
    let cleaned = one_line(value);
    cleaned
        .rsplit(['/', '\\'])
        .find(|part| !part.trim().is_empty())
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// The report as the JSON object one API answer or database record carries.
#[must_use]
pub fn to_json(report: &Report) -> Json {
    Json::object([
        ("project", Json::string(&report.project)),
        ("kind", Json::string(report.kind.as_str())),
        ("title", Json::string(&report.title)),
        ("detail", Json::string(&report.detail)),
        ("route", Json::string(&report.route)),
        ("repro", Json::string(&report.repro)),
        ("tool", Json::string(&report.tool)),
        ("platform", Json::string(&report.platform)),
        ("workspace", Json::string(&report.workspace)),
        ("at", Json::string(&report.at)),
        ("source", Json::string(&report.source)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(text: &str) -> Json {
        selfhost_json::parse(text).expect("test body parses")
    }

    fn filed(text: &str) -> Result<Report, Refusal> {
        Report::parse(
            &body(text),
            "dx",
            "2026-08-11T00:00:00Z".to_string(),
            "abcd1234".to_string(),
        )
    }

    #[test]
    fn a_minimal_report_is_about_the_default_project_and_stamped_by_this_box() {
        let report =
            filed(r#"{"kind":"bug","title":"search misses","detail":"it did"}"#).expect("accepted");
        assert_eq!(report.project, "dx");
        assert_eq!(report.kind, Kind::Bug);
        assert_eq!(report.at, "2026-08-11T00:00:00Z");
        assert_eq!(report.source, "abcd1234");
        assert!(report.route.is_empty());
    }

    #[test]
    fn a_report_may_name_the_project_it_is_about() {
        let report = filed(r#"{"project":"Self-Host","kind":"bug","title":"t","detail":"d"}"#)
            .expect("accepted");
        assert_eq!(report.project, "self-host", "a key is canonical, not as typed");
    }

    #[test]
    fn a_project_key_cannot_name_a_directory_elsewhere() {
        let error = project_key("../../etc").expect_err("refused");
        assert!(error.message().contains("not a project key"), "{error}");
        assert!(project_key("").is_err());
        assert!(project_key("dx").is_ok());
        assert_eq!(project_key("My Project").expect("key"), "my-project");
    }

    /// The whole reason single-line cleaning happens at the parse boundary.
    #[test]
    fn a_title_carrying_a_header_break_becomes_one_line() {
        let report =
            filed(r#"{"kind":"bug","title":"boom\r\nBcc: victim@example.com","detail":"d"}"#)
                .expect("accepted");
        assert_eq!(report.title, "boom Bcc: victim@example.com");
        assert!(!report.title.contains('\r') && !report.title.contains('\n'));
    }

    #[test]
    fn a_nul_byte_in_a_field_does_not_survive() {
        let report = filed("{\"kind\":\"bug\",\"title\":\"a\\u0000b\",\"detail\":\"d\\u0000e\"}")
            .expect("accepted");
        assert_eq!(report.title, "a b");
        assert!(!report.detail.contains('\0'));
    }

    #[test]
    fn the_identity_is_the_kind_the_title_and_the_route() {
        let one =
            filed(r#"{"kind":"bug","title":"Search Misses","detail":"a","route":"dx_search"}"#)
                .expect("accepted");
        let again = filed(
            r#"{"kind":"bug","title":"search   misses","detail":"worded differently","route":"DX_SEARCH"}"#,
        )
        .expect("accepted");
        assert_eq!(one.id(), again.id(), "one defect, one id");

        let other =
            filed(r#"{"kind":"suggestion","title":"search misses","detail":"a","route":"dx_search"}"#)
                .expect("accepted");
        assert_ne!(one.id(), other.id(), "a different kind is a different thing");
        assert!(one.id().starts_with("report-") && one.id().len() == 15);
    }

    #[test]
    fn a_workspace_path_is_reduced_to_its_name() {
        let report =
            filed(r#"{"kind":"bug","title":"t","detail":"d","workspace":"/Users/someone/code/App"}"#)
                .expect("accepted");
        assert_eq!(report.workspace, "App");

        let windows =
            filed(r#"{"kind":"bug","title":"t","detail":"d","workspace":"C:\\Users\\A\\Proj"}"#)
                .expect("accepted");
        assert_eq!(windows.workspace, "Proj");
    }

    #[test]
    fn an_identity_field_over_its_cap_is_refused_by_name() {
        let long = "x".repeat(MAX_TITLE + 1);
        let error =
            filed(&format!(r#"{{"kind":"bug","title":"{long}","detail":"d"}}"#)).expect_err("refused");
        assert!(error.message().contains("`title` is longer"), "{error}");
    }

    #[test]
    fn a_long_detail_is_kept_and_cut_rather_than_lost() {
        let long = "y".repeat(MAX_DETAIL + 500);
        let report =
            filed(&format!(r#"{{"kind":"bug","title":"t","detail":"{long}"}}"#)).expect("accepted");
        assert_eq!(report.detail.chars().count(), MAX_DETAIL + TRUNCATED.chars().count());
        assert!(report.detail.ends_with(TRUNCATED));
    }

    #[test]
    fn an_empty_title_or_detail_says_which_one() {
        let no_title = filed(r#"{"kind":"bug","title":"   ","detail":"d"}"#).expect_err("refused");
        assert!(no_title.message().contains("`title` is required"), "{no_title}");
        let no_detail = filed(r#"{"kind":"bug","title":"t","detail":""}"#).expect_err("refused");
        assert!(no_detail.message().contains("`detail` is required"), "{no_detail}");
    }

    #[test]
    fn a_feature_request_is_a_suggestion_rather_than_a_refusal() {
        let report = filed(r#"{"kind":"feature","title":"t","detail":"d"}"#).expect("accepted");
        assert_eq!(report.kind, Kind::Suggestion);
        let error = filed(r#"{"kind":"catastrophe","title":"t","detail":"d"}"#).expect_err("refused");
        assert!(error.message().contains("bug, suggestion, or observation"), "{error}");
    }

    /// A refusal is shown to whoever sent the request, so it may not echo their bytes back
    /// unbounded — that is a reflection vector and a log-flooding one.
    #[test]
    fn a_refusal_does_not_echo_an_unbounded_field() {
        let shout = "z".repeat(5_000);
        let error =
            filed(&format!(r#"{{"kind":"{shout}","title":"t","detail":"d"}}"#)).expect_err("refused");
        assert!(error.message().len() < 200, "{}", error.message().len());
    }

    #[test]
    fn a_body_that_is_not_a_report_says_what_a_report_is() {
        let error = Report::parse(&body("[1,2,3]"), "dx", String::new(), String::new())
            .expect_err("refused");
        assert!(error.message().contains("JSON object"), "{error}");
    }

    #[test]
    fn the_source_hash_is_stable_and_short() {
        assert_eq!(source_hash("203.0.113.7"), source_hash("203.0.113.7"));
        assert_ne!(source_hash("203.0.113.7"), source_hash("203.0.113.8"));
        assert_eq!(source_hash("203.0.113.7").len(), 8);
    }
}
