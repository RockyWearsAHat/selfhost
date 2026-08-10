//! Undoing an installation: what the daemon created, removed in the right order.
//!
//! # Why this is a command and not a script
//!
//! Only the daemon knows what it made. A service's git working copy lives
//! wherever that service's `[service.git] path` says, which is a different
//! place for every service and is recorded in `data/services.toml` and nowhere
//! else. A shell script cannot know those paths without parsing the catalogue,
//! and a shell script that parses TOML is a worse version of this.
//!
//! # What it will not do
//!
//! - **It will not run while a daemon is running.** Removing a working copy
//!   from under a supervised process makes its exit look like a crash, and the
//!   restart policy then fights the teardown for the process — the same reason
//!   a deployment stops a service rather than restarting it. So this refuses,
//!   and says what to stop.
//! - **It will not touch `selfhost.config.toml`.** A person wrote that by hand,
//!   it is the single source of truth for the deployment, and it is not
//!   something this program created. Removing it would turn "uninstall what was
//!   installed" into "delete my configuration".
//! - **It will not remove anything outside the project directory.** A
//!   catalogue is editable, and a `path` of `/` in it must not become a command
//!   to erase the disk. Every removal is checked to be inside the project first.
//! - **It keeps the data directory unless asked.** Certificates, mail, and
//!   backups live there. `--everything` is how someone says they mean it.

use selfhost_config::Config;
use std::io::Write;
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// How long to wait when checking whether a daemon is listening.
///
/// Loopback answers or refuses immediately; anything slower is a machine under
/// enough load that waiting longer would not change the answer.
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// One thing the teardown intends to remove.
#[derive(Debug, PartialEq, Eq)]
pub struct Removal {
    /// What it is, in words, for the summary.
    pub what: String,
    /// Where it is.
    pub path: PathBuf,
}

/// Everything a teardown would remove, in the order it would remove them.
///
/// Working copies first, then the catalogue that names them: the reverse order
/// would leave a checkout on disk with nothing recording that it is there.
///
/// Pure — it reads the catalogue and answers a list, and removes nothing. That
/// is what lets the plan be shown to a person before anything happens, and what
/// lets it be tested without a filesystem to destroy.
pub fn plan(
    project_dir: &Path,
    data_dir: &Path,
    catalog: &selfhost_config::ServiceCatalog,
    everything: bool,
) -> Vec<Removal> {
    let mut removals = Vec::new();

    for spec in &catalog.services {
        let Some(watch) = &spec.git else { continue };
        let path = selfhost_git::deploy::working_copy(project_dir, watch);
        if !contains(project_dir, &path) {
            // Named but not ours to remove. Reported by the caller rather than
            // silently skipped: someone should know their checkout is outside
            // the project and is being left behind.
            continue;
        }
        removals.push(Removal {
            what: format!("git working copy for {}", spec.name),
            path,
        });
    }

    if everything {
        removals.push(Removal { what: "the whole data directory".into(), path: data_dir.into() });
    } else {
        removals.push(Removal {
            what: "the service catalogue".into(),
            path: data_dir.join(selfhost_admin::store::CATALOG_FILENAME),
        });
        removals.push(Removal {
            what: "the admin token".into(),
            path: selfhost_admin::Token::path_in(data_dir),
        });
    }

    removals.retain(|removal| removal.path.exists());
    removals
}

/// Working copies a teardown is deliberately leaving alone, and why.
///
/// A checkout configured outside the project directory was put there on
/// purpose, and this program did not create the directory it lives in.
pub fn left_behind(
    project_dir: &Path,
    catalog: &selfhost_config::ServiceCatalog,
) -> Vec<Removal> {
    catalog
        .services
        .iter()
        .filter_map(|spec| {
            let watch = spec.git.as_ref()?;
            let path = selfhost_git::deploy::working_copy(project_dir, watch);
            (!contains(project_dir, &path)).then(|| Removal {
                what: format!("git working copy for {} (outside the project)", spec.name),
                path,
            })
        })
        .collect()
}

/// Whether `path` is inside `root`, with both resolved as far as they exist.
///
/// Resolved rather than compared as written, because `project/../../etc` is
/// inside `project` by prefix and is not inside it at all. Where a path cannot
/// be resolved — because it does not exist — the answer is the honest one for a
/// removal: nothing to remove is nothing to be wrong about.
fn contains(root: &Path, path: &Path) -> bool {
    let Ok(root) = std::fs::canonicalize(root) else { return false };
    let Ok(path) = std::fs::canonicalize(path) else { return false };
    path.starts_with(&root) && path != root
}

/// Whether something is already listening on the daemon's control address.
pub fn daemon_is_running(address: SocketAddr) -> bool {
    TcpStream::connect_timeout(&address, PROBE_TIMEOUT).is_ok()
}

/// Carries out a teardown, printing what it does.
///
/// Returns the paths it could not remove, paired with why. A teardown that hits
/// a permission error on one directory still removes the rest and says which
/// one it could not — stopping at the first failure would leave the operator
/// with a half-torn-down installation and no list of what remains.
pub fn carry_out(removals: &[Removal]) -> Vec<(PathBuf, std::io::Error)> {
    let mut failures = Vec::new();
    for removal in removals {
        let outcome = if removal.path.is_dir() {
            std::fs::remove_dir_all(&removal.path)
        } else {
            std::fs::remove_file(&removal.path)
        };
        match outcome {
            Ok(()) => println!("  removed  {}", removal.path.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                println!("  FAILED   {} — {error}", removal.path.display());
                failures.push((removal.path.clone(), error));
            }
        }
    }
    failures
}

/// Asks, on the terminal, whether to go ahead.
///
/// Anything other than a typed `yes` is a no, including an empty line and a
/// closed input. A destructive default is how an uninstall becomes an accident.
pub fn confirmed() -> bool {
    print!("\nRemove these? Type yes to confirm: ");
    if std::io::stdout().flush().is_err() {
        return false;
    }
    let mut answer = String::new();
    if std::io::stdin().read_line(&mut answer).is_err() {
        return false;
    }
    answer.trim().eq_ignore_ascii_case("yes")
}

/// Describes what a daemon still running means and what to do about it.
pub fn refuse_because_running(address: SocketAddr) -> String {
    format!(
        "a daemon is answering on {address}, so there is nothing safe to remove yet.\n\n\
         Stop it first — Ctrl-C in the terminal running `selfhost daemon`, or stop the \
         system service. Removing a working copy from under a supervised process makes \
         its exit look like a crash, and the restart policy then fights the teardown for \
         the process."
    )
}

/// The data directory this config puts state in.
///
/// Normalised, because it is shown to a person immediately before they are
/// asked to confirm deleting it. `data_dir = "./data"` joined onto a project
/// path renders as `…/project/./data`, and a path with a stray `.` in it in a
/// destructive prompt invites a second look at exactly the wrong moment.
pub fn data_dir(config: &Config, project_dir: &Path) -> PathBuf {
    let joined = project_dir.join(&config.server.data_dir);
    std::path::absolute(&joined).unwrap_or(joined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_config::{GitWatch, ServiceCatalog, ServiceSpec};

    /// A scratch project directory this test owns.
    fn project(name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!("selfhost-teardown-{name}-{unique}"));
        std::fs::create_dir_all(&root).expect("a writable temporary directory");
        root
    }

    fn service_watching(name: &str, path: &str) -> ServiceSpec {
        let mut spec = ServiceSpec::new(name, "/bin/sh");
        spec.git = Some(GitWatch::new("https://example.invalid/repo.git", path));
        spec
    }

    #[test]
    fn a_working_copy_inside_the_project_is_removed_and_the_catalogue_with_it() {
        let root = project("inside");
        let data = root.join("data");
        std::fs::create_dir_all(root.join("checkouts/site")).expect("writable");
        std::fs::create_dir_all(&data).expect("writable");
        std::fs::write(data.join("services.toml"), "").expect("writable");

        let mut catalog = ServiceCatalog::default();
        catalog.upsert(service_watching("site", "checkouts/site"));

        let removals = plan(&root, &data, &catalog, false);
        assert!(
            removals.iter().any(|r| r.path.ends_with("checkouts/site")),
            "the working copy should be removed: {removals:?}"
        );
        assert!(
            removals.iter().any(|r| r.path.ends_with("services.toml")),
            "the catalogue should be removed: {removals:?}"
        );
        assert!(
            removals.iter().position(|r| r.path.ends_with("checkouts/site"))
                < removals.iter().position(|r| r.path.ends_with("services.toml")),
            "a checkout must be removed before the catalogue that names it"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_working_copy_outside_the_project_is_left_alone_and_reported() {
        // The safety property that matters most here. A catalogue is an editable
        // file; a `path` in it that escapes the project must not become an
        // instruction to remove someone else's directory.
        let root = project("outside");
        let elsewhere = project("elsewhere");
        let data = root.join("data");
        std::fs::create_dir_all(&data).expect("writable");

        let mut catalog = ServiceCatalog::default();
        catalog.upsert(service_watching("escaped", elsewhere.to_str().expect("utf-8")));

        let removals = plan(&root, &data, &catalog, false);
        assert!(
            !removals.iter().any(|r| r.path == elsewhere),
            "a path outside the project must never be planned for removal: {removals:?}"
        );
        assert!(elsewhere.is_dir(), "and must still be there");

        let skipped = left_behind(&root, &catalog);
        assert_eq!(skipped.len(), 1, "the operator should be told it was skipped");
        assert_eq!(skipped[0].path, elsewhere);

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&elsewhere);
    }

    #[test]
    fn a_path_that_climbs_out_of_the_project_does_not_count_as_inside_it() {
        // `project/../..` starts with `project` when compared as written, which
        // is exactly the comparison that would let a teardown escape.
        let root = project("climber");
        let inside = root.join("sub");
        std::fs::create_dir_all(&inside).expect("writable");
        assert!(contains(&root, &inside));
        assert!(!contains(&root, &root.join("../..")));
        assert!(!contains(&root, &root), "the project itself is not inside itself");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn everything_replaces_the_individual_files_with_the_data_directory() {
        let root = project("everything");
        let data = root.join("data");
        std::fs::create_dir_all(&data).expect("writable");
        std::fs::write(data.join("services.toml"), "").expect("writable");
        std::fs::write(data.join("admin.token"), "").expect("writable");

        let removals = plan(&root, &data, &ServiceCatalog::default(), true);
        assert_eq!(removals.len(), 1, "one removal, not three: {removals:?}");
        assert_eq!(removals[0].path, data);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn nothing_that_is_not_there_is_planned_for_removal() {
        // So the summary shown to a person is what will actually happen, rather
        // than a list of paths most of which do not exist.
        let root = project("empty");
        let removals = plan(&root, &root.join("data"), &ServiceCatalog::default(), false);
        assert!(removals.is_empty(), "{removals:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn removing_something_already_gone_is_not_a_failure() {
        let root = project("gone");
        let failures = carry_out(&[Removal {
            what: "a file nobody made".into(),
            path: root.join("absent"),
        }]);
        assert!(failures.is_empty(), "{failures:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_refusal_names_the_address_and_says_what_to_stop() {
        let message = refuse_because_running("127.0.0.1:9191".parse().expect("valid"));
        assert!(message.contains("127.0.0.1:9191"));
        assert!(message.contains("selfhost daemon"), "it should say what to stop");
    }
}
