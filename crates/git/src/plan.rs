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

/// Arguments for asking the remote what commit a branch points at.
///
/// `--exit-code` is what turns "that branch does not exist" into a failure
/// instead of an empty answer that reads exactly like "nothing has changed".
pub fn ls_remote_args(watch: &GitWatch) -> Vec<String> {
    let mut args = global_options();
    args.push("ls-remote".into());
    args.push("--exit-code".into());
    args.push(watch.repository.trim().to_owned());
    args.push(watch.remote_ref());
    args
}

/// Arguments for the first checkout of a watched branch.
///
/// `--single-branch` because a deployment needs one branch, and cloning every
/// branch of a large repository is bandwidth spent on history nobody will read.
pub fn clone_args(watch: &GitWatch, into: &Path) -> Vec<String> {
    let mut args = global_options();
    args.push("clone".into());
    args.push("--single-branch".into());
    args.push("--branch".into());
    args.push(watch.branch.clone());
    args.push("--".into());
    args.push(watch.repository.trim().to_owned());
    args.push(into.display().to_string());
    args
}

/// Arguments for fetching the watched branch into an existing working copy.
pub fn fetch_args(watch: &GitWatch, at: &Path) -> Vec<String> {
    let mut args = global_options();
    args.push("-C".into());
    args.push(at.display().to_string());
    args.push("fetch".into());
    args.push("--prune".into());
    args.push("--".into());
    args.push(watch.repository.trim().to_owned());
    args.push(watch.remote_ref());
    args
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
    match local {
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
            ls_remote_args(&watch()),
            clone_args(&watch(), &at),
            fetch_args(&watch(), &at),
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
        let args = ls_remote_args(&watch());
        assert!(args.contains(&"--exit-code".to_owned()), "an absent branch must fail, not read as unchanged");
        assert_eq!(args.last().map(String::as_str), Some("refs/heads/main"));
    }

    #[test]
    fn a_repository_url_is_separated_from_the_options_that_precede_it() {
        // The URL is validated before it gets here, so this is the second lock on
        // the same door: even a URL starting with a dash lands as a repository.
        let at = PathBuf::from("/data/site");
        for args in [clone_args(&watch(), &at), fetch_args(&watch(), &at)] {
            let end = args.iter().position(|a| a == "--").expect("a separator");
            assert!(args[end + 1..].iter().any(|a| a.contains("github.com")), "{args:?}");
        }
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
    fn a_short_commit_is_short_without_panicking_on_a_shorter_one() {
        assert_eq!(short("1234567890abcdef"), "1234567");
        assert_eq!(short("abc"), "abc");
    }
}
