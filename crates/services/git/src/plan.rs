//! What to run, and what to do about the answer. Pure, so it is all testable.
//!
//! Nothing here spawns a process or touches a disk. Every `git` invocation this
//! crate makes is built by a function in this module and every decision it takes
//! is made by [`decide`], which means the interesting behaviour — "a branch that
//! has not moved must not restart a service" — is asserted directly rather than
//! inferred from a repository fixture.

use selfhost_config::GitWatch;
use std::path::Path;

/// Options given to every `git` invocation, before the subcommand.
///
/// `protocol.ext.allow=never` is defence in depth. The repository URL is already
/// validated (`selfhost_config::git` refuses `ext::`), and this makes the same
/// answer true even if a URL reaches `git` some other way — through a submodule,
/// or an `insteadOf` rule in a config file the daemon user happens to have.
///
/// `credential.helper=` empties the list of helpers rather than adding one, so a
/// helper configured for the daemon user's own work cannot silently supply
/// credentials to a deployment.
fn global_options() -> Vec<String> {
    vec![
        "-c".into(),
        "protocol.ext.allow=never".into(),
        "-c".into(),
        "credential.helper=".into(),
    ]
}

/// The URL a `git` invocation should actually use: `authenticated` when one was
/// minted for this poll, `watch.repository` otherwise.
///
/// Kept separate from `watch.repository` everywhere a URL might be logged —
/// `authenticated` carries a live installation token in its userinfo, and
/// `watch.repository` is what error messages and the service's own output are
/// allowed to print. Never let an `authenticated` value reach a `format!` that
/// isn't building `git` arguments.
fn repository_url(watch: &GitWatch, authenticated: Option<&str>) -> String {
    match authenticated {
        Some(url) => url.to_owned(),
        None => watch.repository.trim().to_owned(),
    }
}

/// Arguments for asking the remote what commit a branch points at.
///
/// `--exit-code` is what turns "that branch does not exist" into a failure
/// instead of an empty answer that reads exactly like "nothing has changed".
///
/// `authenticated`, when given, is used in place of `watch.repository` — see
/// [`repository_url`].
pub fn ls_remote_args(watch: &GitWatch, authenticated: Option<&str>) -> Vec<String> {
    let mut args = global_options();
    args.push("ls-remote".into());
    args.push("--exit-code".into());
    args.push(repository_url(watch, authenticated));
    args.push(watch.remote_ref());
    args
}

/// Arguments for the first checkout of a watched branch.
///
/// `--single-branch` because a deployment needs one branch, and cloning every
/// branch of a large repository is bandwidth spent on history nobody will read.
///
/// `authenticated`, when given, is used in place of `watch.repository` — see
/// [`repository_url`].
pub fn clone_args(watch: &GitWatch, into: &Path, authenticated: Option<&str>) -> Vec<String> {
    let mut args = global_options();
    args.push("clone".into());
    args.push("--single-branch".into());
    args.push("--branch".into());
    args.push(watch.branch.clone());
    args.push("--".into());
    args.push(repository_url(watch, authenticated));
    args.push(into.display().to_string());
    args
}

/// Arguments for fetching the watched branch into an existing working copy.
///
/// `authenticated`, when given, is used in place of `watch.repository` — see
/// [`repository_url`].
pub fn fetch_args(watch: &GitWatch, at: &Path, authenticated: Option<&str>) -> Vec<String> {
    let mut args = global_options();
    args.push("-C".into());
    args.push(at.display().to_string());
    args.push("fetch".into());
    args.push("--prune".into());
    args.push("--".into());
    args.push(repository_url(watch, authenticated));
    args.push(watch.remote_ref());
    args
}

/// Splits a `github.com` remote — SSH (`git@github.com:owner/repo.git`) or
/// HTTPS (`https://github.com/owner/repo.git`, with or without a `.git` suffix
/// or trailing slash) — into its owner and repository name.
///
/// `None` for anything else: a non-`github.com` host, a malformed URL, or a
/// URL missing either segment. This is the gate for whether a repository is
/// even worth asking the GitHub App about — an installation token is only ever
/// useful for a `github.com` remote.
pub fn parse_github_owner_repo(repository: &str) -> Option<(String, String)> {
    let repository = repository.trim();
    let path = if let Some(rest) = repository.strip_prefix("git@github.com:") {
        rest
    } else if let Some(rest) = repository.strip_prefix("ssh://git@github.com/") {
        rest
    } else if let Some(rest) = repository.strip_prefix("https://github.com/") {
        rest
    } else if let Some(rest) = repository.strip_prefix("http://github.com/") {
        rest
    } else {
        return None;
    };

    let path = path.trim_end_matches('/').strip_suffix(".git").unwrap_or(path.trim_end_matches('/'));
    let (owner, repo) = path.split_once('/')?;
    if owner.is_empty() || repo.is_empty() || repo.contains('/') {
        return None;
    }
    Some((owner.to_owned(), repo.to_owned()))
}

/// Builds the authenticated HTTPS URL `git` should fetch from, given a
/// short-lived GitHub App installation token.
///
/// `x-access-token` is GitHub's documented username for this: any string
/// works as the username when the password is an installation token, and
/// `x-access-token` is what GitHub's own docs use, so a URL that leaks into a
/// stray log line is at least recognizable as what it is rather than
/// mistaken for a personal credential.
pub fn authenticated_url(owner: &str, repo: &str, token: &str) -> String {
    format!("https://x-access-token:{token}@github.com/{owner}/{repo}.git")
}

/// Arguments for moving the working copy onto what was just fetched.
///
/// A hard reset, not a merge or a rebase: a deployment that can stop on a
/// conflict is a deployment that stops at four in the morning with nobody
/// watching. Untracked files are deliberately *not* removed — `node_modules`,
/// a build cache, and an `.env` written by the operator all live there, and a
/// deployment that deletes them is a deployment that also has to restore them.
pub fn reset_args(at: &Path) -> Vec<String> {
    let mut args = global_options();
    args.push("-C".into());
    args.push(at.display().to_string());
    args.push("reset".into());
    args.push("--hard".into());
    args.push("FETCH_HEAD".into());
    args
}

/// Arguments for moving the working copy onto a specific, already-known commit.
///
/// The rollback half of [`reset_args`]: a build that fails after the tree was
/// updated must put the tree back on the commit the running build came from, or
/// the next poll reads the new commit as deployed and never retries. The commit
/// only ever comes from [`parse_head`]/[`commit_for_ref`], so it is hexadecimal
/// and cannot reach `git` as an option.
pub fn reset_to_args(at: &Path, commit: &str) -> Vec<String> {
    let mut args = global_options();
    args.push("-C".into());
    args.push(at.display().to_string());
    args.push("reset".into());
    args.push("--hard".into());
    args.push(commit.to_owned());
    args
}

/// Arguments for asking whether tracked files in a working copy are modified.
///
/// `-uno` leaves untracked files out of the answer on purpose — the same rule
/// as [`reset_args`]: untracked files (a build cache, an operator's `.env`)
/// belong to the deployment and must neither block nor be destroyed by one.
/// Empty output means clean.
pub fn status_args(at: &Path) -> Vec<String> {
    let mut args = global_options();
    args.push("-C".into());
    args.push(at.display().to_string());
    args.push("status".into());
    args.push("--porcelain".into());
    args.push("-uno".into());
    args
}

/// Arguments for asking whether `commit` is an ancestor of what was fetched.
///
/// Exit 0 answers yes, exit 1 answers no, anything else is a real failure —
/// `git merge-base --is-ancestor`'s own contract. Asked before a self-update's
/// hard reset: a fetch that is *not* a fast-forward means the working copy
/// holds commits the branch does not, and resetting would discard them.
pub fn is_ancestor_args(at: &Path, commit: &str) -> Vec<String> {
    let mut args = global_options();
    args.push("-C".into());
    args.push(at.display().to_string());
    args.push("merge-base".into());
    args.push("--is-ancestor".into());
    args.push(commit.to_owned());
    args.push("FETCH_HEAD".into());
    args
}

/// Arguments for reading the commit a working copy is currently on.
pub fn head_args(at: &Path) -> Vec<String> {
    let mut args = global_options();
    args.push("-C".into());
    args.push(at.display().to_string());
    args.push("rev-parse".into());
    args.push("HEAD".into());
    args
}

/// Reads the commit for one ref out of `git ls-remote` output.
///
/// Matched exactly against the fully-qualified ref. `ls-remote` answers with
/// every ref that matched the pattern — including the peeled `refs/tags/x^{}`
/// form — and taking the first line would resolve a tag that shares a name with
/// the branch, which is a deployment of the wrong commit.
pub fn commit_for_ref(output: &str, wanted: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let (commit, name) = line.split_once(char::is_whitespace)?;
        (name.trim() == wanted && is_commit(commit)).then(|| commit.to_owned())
    })
}

/// Whether text is a hexadecimal object name, as `git` writes them.
fn is_commit(text: &str) -> bool {
    let length = text.len();
    (7..=64).contains(&length) && text.chars().all(|c| c.is_ascii_hexdigit())
}

/// Reads the commit `git rev-parse HEAD` answered with.
pub fn parse_head(output: &str) -> Option<String> {
    let head = output.trim();
    is_commit(head).then(|| head.to_owned())
}

/// The first seven characters of a commit, for a log line a person reads.
pub fn short(commit: &str) -> &str {
    &commit[..commit.len().min(7)]
}

/// What a poll concluded should happen next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// The working copy is already on the branch's commit.
    UpToDate,
    /// There is no working copy yet; clone before anything else.
    Clone {
        /// The commit the clone is expected to land on.
        to: String,
    },
    /// The branch moved and the watch may act: update and restart.
    Deploy {
        /// The commit the working copy is on now, if it has one.
        from: Option<String>,
        /// The commit to deploy.
        to: String,
    },
    /// The branch moved and the watch may only report it.
    Behind {
        /// The commit the working copy is on now, if it has one.
        from: Option<String>,
        /// The commit the branch is on.
        to: String,
    },
}

impl Step {
    /// Whether this step changes anything on disk or in the supervisor.
    pub fn acts(&self) -> bool {
        matches!(self, Self::Clone { .. } | Self::Deploy { .. })
    }

    /// A line for the service's own output, in an operator's terms.
    pub fn describe(&self) -> String {
        match self {
            Self::UpToDate => "up to date".to_owned(),
            Self::Clone { to } => format!("no working copy yet; cloning at {}", short(to)),
            Self::Deploy { from: Some(from), to } => {
                format!("{} → {}: deploying", short(from), short(to))
            }
            Self::Deploy { from: None, to } => format!("deploying {}", short(to)),
            Self::Behind { from: Some(from), to } => format!(
                "{} → {}: the branch has moved, and auto_update is off — deploy it by hand",
                short(from),
                short(to)
            ),
            Self::Behind { from: None, to } => format!(
                "the branch is at {} and there is no working copy, but auto_update is off",
                short(to)
            ),
        }
    }
}

/// Decides what a poll should do.
///
/// `local` is the commit the working copy is on, or `None` when there is no
/// working copy yet. `remote` is what the branch points at now.
///
/// A watch with `auto_update` off still reaches a conclusion — it just reports it
/// rather than acting on it. That is the difference between a switch that turns
/// the feature off and one that turns the *watching* off, and only the first is
/// useful for answering "is production behind?".
pub fn decide(watch: &GitWatch, local: Option<&str>, remote: &str) -> Step {
    decide_forced(watch, local, remote, false)
}

/// Same as [`decide`], but `force` skips the "already on the branch's commit"
/// short-circuit: an unmoved branch still produces a [`Step::Deploy`] rather
/// than [`Step::UpToDate`].
///
/// This is specifically the "someone asked for a redeploy right now" case
/// (`services_deploy`'s `force: true`, `selfhost repo configure`'s explicit
/// redeploy) — never what a background poll passes, because an unattended poll
/// that redeployed on every tick regardless of whether anything moved would
/// make "poll" and "redeploy" the same word. A watch with no working copy yet
/// (`local: None`) ignores `force` and still clones exactly as [`decide`]
/// would: there is no previous build to redo.
pub fn decide_forced(watch: &GitWatch, local: Option<&str>, remote: &str, force: bool) -> Step {
    match local {
        Some(local) if local == remote && force => {
            Step::Deploy { from: Some(local.to_owned()), to: remote.to_owned() }
        }
        Some(local) if local == remote => Step::UpToDate,
        Some(local) if watch.auto_update => {
            Step::Deploy { from: Some(local.to_owned()), to: remote.to_owned() }
        }
        Some(local) => Step::Behind { from: Some(local.to_owned()), to: remote.to_owned() },
        None if watch.auto_update => Step::Clone { to: remote.to_owned() },
        None => Step::Behind { from: None, to: remote.to_owned() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn watch() -> GitWatch {
        GitWatch::new("https://github.com/owner/repo.git", "checkouts/site")
    }

    #[test]
    fn every_invocation_disables_the_transport_that_runs_commands() {
        let at = PathBuf::from("/data/site");
        for args in [
            ls_remote_args(&watch(), None),
            clone_args(&watch(), &at, None),
            fetch_args(&watch(), &at, None),
            reset_args(&at),
            head_args(&at),
        ] {
            assert!(
                args.windows(2).any(|pair| pair == ["-c", "protocol.ext.allow=never"]),
                "{args:?}"
            );
        }
    }

    #[test]
    fn the_remote_is_asked_for_the_fully_qualified_branch_and_must_find_it() {
        let args = ls_remote_args(&watch(), None);
        assert!(args.contains(&"--exit-code".to_owned()), "an absent branch must fail, not read as unchanged");
        assert_eq!(args.last().map(String::as_str), Some("refs/heads/main"));
    }

    #[test]
    fn a_repository_url_is_separated_from_the_options_that_precede_it() {
        // The URL is validated before it gets here, so this is the second lock on
        // the same door: even a URL starting with a dash lands as a repository.
        let at = PathBuf::from("/data/site");
        for args in [clone_args(&watch(), &at, None), fetch_args(&watch(), &at, None)] {
            let end = args.iter().position(|a| a == "--").expect("a separator");
            assert!(args[end + 1..].iter().any(|a| a.contains("github.com")), "{args:?}");
        }
    }

    #[test]
    fn an_authenticated_url_replaces_the_configured_repository_in_every_arg_builder() {
        let at = PathBuf::from("/data/site");
        let token_url = "https://x-access-token:ghs_secret@github.com/owner/repo.git";
        for args in [
            ls_remote_args(&watch(), Some(token_url)),
            clone_args(&watch(), &at, Some(token_url)),
            fetch_args(&watch(), &at, Some(token_url)),
        ] {
            assert!(args.contains(&token_url.to_owned()), "{args:?}");
            assert!(!args.iter().any(|a| a == "https://github.com/owner/repo.git"), "{args:?}");
        }
    }

    #[test]
    fn ssh_and_https_github_remotes_yield_the_same_owner_and_repo() {
        for repository in [
            "git@github.com:RockyWearsAHat/ai-studio.git",
            "ssh://git@github.com/RockyWearsAHat/ai-studio.git",
            "https://github.com/RockyWearsAHat/ai-studio.git",
            "https://github.com/RockyWearsAHat/ai-studio",
            "https://github.com/RockyWearsAHat/ai-studio/",
            "http://github.com/RockyWearsAHat/ai-studio.git",
        ] {
            assert_eq!(
                parse_github_owner_repo(repository),
                Some(("RockyWearsAHat".to_owned(), "ai-studio".to_owned())),
                "{repository}"
            );
        }
    }

    #[test]
    fn a_non_github_remote_has_no_owner_and_repo() {
        assert_eq!(parse_github_owner_repo("https://example.com/owner/repo.git"), None);
        assert_eq!(parse_github_owner_repo("git@example.com:owner/repo.git"), None);
    }

    #[test]
    fn a_malformed_github_remote_has_no_owner_and_repo() {
        assert_eq!(parse_github_owner_repo("https://github.com/onlyowner"), None);
        assert_eq!(parse_github_owner_repo("https://github.com/"), None);
        assert_eq!(parse_github_owner_repo("git@github.com:owner/nested/repo.git"), None);
    }

    #[test]
    fn the_authenticated_url_carries_the_token_as_the_https_password() {
        assert_eq!(
            authenticated_url("RockyWearsAHat", "ai-studio", "ghs_abc123"),
            "https://x-access-token:ghs_abc123@github.com/RockyWearsAHat/ai-studio.git"
        );
    }

    #[test]
    fn a_rollback_aims_at_the_named_commit_with_the_same_hard_reset() {
        let args = reset_to_args(Path::new("/data/site"), "1111111111111111111111111111111111111111");
        assert!(args.contains(&"--hard".to_owned()));
        assert_eq!(args.last().map(String::as_str), Some("1111111111111111111111111111111111111111"));
        assert!(args.windows(2).any(|pair| pair == ["-c", "protocol.ext.allow=never"]));
    }

    #[test]
    fn the_ancestry_question_compares_the_working_copy_against_what_was_fetched() {
        let args = is_ancestor_args(Path::new("/data/site"), "1111111");
        assert!(args.contains(&"--is-ancestor".to_owned()));
        assert_eq!(args.last().map(String::as_str), Some("FETCH_HEAD"));
        assert!(args.windows(2).any(|pair| pair == ["-c", "protocol.ext.allow=never"]));
    }

    #[test]
    fn a_dirt_check_ignores_untracked_files_for_the_same_reason_reset_spares_them() {
        let args = status_args(Path::new("/data/site"));
        assert!(args.contains(&"-uno".to_owned()), "{args:?}");
        assert!(args.contains(&"--porcelain".to_owned()), "{args:?}");
    }

    #[test]
    fn updating_resets_rather_than_merging_and_leaves_untracked_files_alone() {
        let args = reset_args(Path::new("/data/site"));
        assert!(args.contains(&"--hard".to_owned()));
        assert!(args.contains(&"FETCH_HEAD".to_owned()));
        assert!(!args.iter().any(|a| a == "clean"), "a build cache must survive a deployment");
    }

    #[test]
    fn the_commit_is_read_from_the_line_whose_ref_matches_exactly() {
        let output = "\
1111111111111111111111111111111111111111\trefs/heads/main-old\n\
2222222222222222222222222222222222222222\trefs/heads/main\n";
        assert_eq!(
            commit_for_ref(output, "refs/heads/main").as_deref(),
            Some("2222222222222222222222222222222222222222")
        );
    }

    #[test]
    fn a_tag_sharing_the_branchs_name_cannot_be_deployed_instead() {
        // ls-remote answers with the tag first, and its peeled form after it.
        let output = "\
3333333333333333333333333333333333333333\trefs/tags/main\n\
4444444444444444444444444444444444444444\trefs/tags/main^{}\n\
5555555555555555555555555555555555555555\trefs/heads/main\n";
        assert_eq!(
            commit_for_ref(output, "refs/heads/main").as_deref(),
            Some("5555555555555555555555555555555555555555")
        );
    }

    #[test]
    fn output_without_the_branch_yields_nothing_rather_than_a_guess() {
        assert!(commit_for_ref("", "refs/heads/main").is_none());
        assert!(commit_for_ref("not a ref line\n", "refs/heads/main").is_none());
        assert!(
            commit_for_ref("zzzz\trefs/heads/main\n", "refs/heads/main").is_none(),
            "an object name that is not hexadecimal is not a commit"
        );
    }

    #[test]
    fn a_head_is_read_with_its_trailing_newline_removed() {
        assert_eq!(
            parse_head("6666666666666666666666666666666666666666\n").as_deref(),
            Some("6666666666666666666666666666666666666666")
        );
        assert!(parse_head("fatal: not a git repository\n").is_none());
        assert!(parse_head("").is_none());
    }

    #[test]
    fn an_unmoved_branch_does_nothing_at_all() {
        let step = decide(&watch(), Some("abc1234abc"), "abc1234abc");
        assert_eq!(step, Step::UpToDate);
        assert!(!step.acts(), "a poll that changes nothing must not restart a service");
    }

    #[test]
    fn a_moved_branch_deploys_and_says_which_commits() {
        let step = decide(&watch(), Some("1111111"), "2222222");
        assert_eq!(step, Step::Deploy { from: Some("1111111".into()), to: "2222222".into() });
        assert!(step.acts());
        assert!(step.describe().contains("1111111"), "{}", step.describe());
        assert!(step.describe().contains("2222222"));
    }

    #[test]
    fn a_missing_working_copy_clones_before_anything_else() {
        assert_eq!(decide(&watch(), None, "2222222"), Step::Clone { to: "2222222".into() });
    }

    #[test]
    fn a_watch_that_may_not_act_still_reaches_and_reports_a_conclusion() {
        let mut watch = watch();
        watch.auto_update = false;

        let behind = decide(&watch, Some("1111111"), "2222222");
        assert_eq!(behind, Step::Behind { from: Some("1111111".into()), to: "2222222".into() });
        assert!(!behind.acts(), "auto_update off must not touch the working copy");
        assert!(behind.describe().contains("auto_update"), "{}", behind.describe());

        // And it must not clone either, for the same reason.
        assert!(!decide(&watch, None, "2222222").acts());
        // But an unmoved branch is still simply up to date.
        assert_eq!(decide(&watch, Some("2222222"), "2222222"), Step::UpToDate);
    }

    #[test]
    fn an_unmoved_branch_deploys_anyway_when_forced() {
        // The forced counterpart of `an_unmoved_branch_does_nothing_at_all`:
        // an explicit "redeploy this now" must actually redo the build, even
        // when the branch tip is exactly where it already was.
        let step = decide_forced(&watch(), Some("abc1234abc"), "abc1234abc", true);
        assert_eq!(step, Step::Deploy { from: Some("abc1234abc".into()), to: "abc1234abc".into() });
        assert!(step.acts(), "a forced redeploy must actually run the build step again");
    }

    #[test]
    fn force_changes_nothing_when_the_branch_already_moved() {
        // Forcing is only meant to skip the "nothing to do" short-circuit, not
        // to change what a moved branch already decides.
        assert_eq!(
            decide_forced(&watch(), Some("1111111"), "2222222", true),
            decide(&watch(), Some("1111111"), "2222222")
        );
    }

    #[test]
    fn force_does_not_invent_a_working_copy_that_does_not_exist() {
        // There is no previous build to redo, so a forced first-time watch
        // clones exactly as an ordinary one would.
        assert_eq!(decide_forced(&watch(), None, "2222222", true), decide(&watch(), None, "2222222"));
    }

    #[test]
    fn an_unforced_decision_is_unchanged() {
        assert_eq!(decide_forced(&watch(), Some("2222222"), "2222222", false), Step::UpToDate);
    }

    #[test]
    fn a_short_commit_is_short_without_panicking_on_a_shorter_one() {
        assert_eq!(short("1234567890abcdef"), "1234567");
        assert_eq!(short("abc"), "abc");
    }
}
