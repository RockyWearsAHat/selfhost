//! Persistence for the service catalogue.
//!
//! The daemon is the only writer of `data/services.toml`. Deployment settings —
//! server, nodes, sites — stay in `selfhost.config.toml`, which the daemon never
//! writes, so the comments a person put there cannot be destroyed by a console
//! save. See [`selfhost_config::service`] for the reasoning.

use selfhost_config::{ServiceCatalog, ServiceSpec};
use std::io;
use std::path::{Path, PathBuf};
use tokio::sync::Mutex;

/// The catalogue file's name inside the data directory.
pub const CATALOG_FILENAME: &str = "services.toml";

/// Reads and writes the service catalogue.
///
/// The mutex serialises writes: two consoles saving at once would otherwise both
/// read, both modify their own copy, and the second write would silently discard
/// the first one's service.
#[derive(Debug)]
pub struct Store {
    path: PathBuf,
    guard: Mutex<()>,
}

impl Store {
    /// A store backed by `services.toml` in the given data directory.
    pub fn new(data_dir: &Path) -> Self {
        Self { path: data_dir.join(CATALOG_FILENAME), guard: Mutex::new(()) }
    }

    /// Where the catalogue is written.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the catalogue, returning an empty one if the file does not exist yet.
    ///
    /// A missing file is a first run, not a failure. A *malformed* file is a
    /// failure and is reported, because silently starting with no services would
    /// look identical to someone's entire catalogue having been deleted.
    pub fn load(&self, known_nodes: &[&str]) -> io::Result<ServiceCatalog> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(ServiceCatalog::default());
            }
            Err(error) => return Err(error),
        };

        ServiceCatalog::parse(&text, known_nodes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} is not usable: {error}", self.path.display()),
            )
        })
    }

    /// Adds or replaces a service in the stored catalogue.
    pub async fn upsert(&self, spec: ServiceSpec) -> io::Result<()> {
        let _held = self.guard.lock().await;
        let mut catalog = self.load(&[])?;
        catalog.upsert(spec);
        self.write(&catalog)
    }

    /// Removes a service from the stored catalogue.
    pub async fn remove(&self, name: &str) -> io::Result<()> {
        let _held = self.guard.lock().await;
        let mut catalog = self.load(&[])?;
        catalog.remove(name);
        self.write(&catalog)
    }

    /// Writes the catalogue atomically.
    ///
    /// Written to a temporary file and renamed, because `rename` is atomic within
    /// a directory: a crash or a full disk halfway through leaves the previous
    /// catalogue intact rather than a truncated one. Truncating the real file
    /// first would make losing every service definition a routine risk of saving.
    fn write(&self, catalog: &ServiceCatalog) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let temporary = self.path.with_extension("toml.new");
        std::fs::write(&temporary, catalog.to_toml())?;
        std::fs::rename(&temporary, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-store-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[tokio::test]
    async fn a_missing_catalogue_reads_as_empty_rather_than_failing() {
        let dir = scratch("missing");
        let store = Store::new(&dir);
        assert!(store.load(&[]).expect("first run is not an error").services.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_saved_service_is_read_back() {
        let dir = scratch("roundtrip");
        let store = Store::new(&dir);
        store.upsert(ServiceSpec::new("mongod", "/usr/bin/mongod")).await.expect("saved");

        let catalog = store.load(&[]).expect("loaded");
        assert_eq!(catalog.services.len(), 1);
        assert_eq!(catalog.services[0].name, "mongod");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn saving_twice_replaces_rather_than_duplicates() {
        let dir = scratch("replace");
        let store = Store::new(&dir);
        store.upsert(ServiceSpec::new("api", "/bin/old")).await.unwrap();
        store.upsert(ServiceSpec::new("api", "/bin/new")).await.unwrap();

        let catalog = store.load(&[]).unwrap();
        assert_eq!(catalog.services.len(), 1);
        assert_eq!(catalog.services[0].program, PathBuf::from("/bin/new"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn removing_leaves_the_others_alone() {
        let dir = scratch("remove");
        let store = Store::new(&dir);
        store.upsert(ServiceSpec::new("a", "/bin/a")).await.unwrap();
        store.upsert(ServiceSpec::new("b", "/bin/b")).await.unwrap();
        store.remove("a").await.unwrap();

        let catalog = store.load(&[]).unwrap();
        assert_eq!(catalog.services.len(), 1);
        assert_eq!(catalog.services[0].name, "b");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_malformed_catalogue_is_reported_rather_than_silently_ignored() {
        // Starting with no services would be indistinguishable from someone's
        // entire catalogue having been deleted.
        let dir = scratch("malformed");
        std::fs::write(dir.join(CATALOG_FILENAME), "this is not toml {{{").unwrap();
        let store = Store::new(&dir);
        assert!(store.load(&[]).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn no_temporary_file_is_left_behind_after_a_save() {
        let dir = scratch("atomic");
        let store = Store::new(&dir);
        store.upsert(ServiceSpec::new("a", "/bin/a")).await.unwrap();

        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.ends_with(".new"))
            .collect();
        assert!(leftovers.is_empty(), "temporary files left behind: {leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
