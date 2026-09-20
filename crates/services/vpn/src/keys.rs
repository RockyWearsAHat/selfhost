//! Where a relay's key material lives, and what has to be true of it before the
//! relay is started.
//!
//! **This module never generates, parses, or writes a key.** It resolves paths
//! and reports what is missing. Generating a keypair is the tunnel
//! implementation's job (`scripts/securevpn/rotate-keys.sh` on this deployment).
//!
//! A Peer's `.pub` file is written by enrolment ([`crate::enrol`]) and read by
//! the tunnel; [`crate::roster::Roster`] reports a listed Peer whose file is
//! gone. What [`inspect`] answers is the relay's own half: its directory, its
//! private key, and a leftover shared key that should not be there.

use selfhost_config::vpn::{RESERVED_PEER_NAMES, Relay};
use selfhost_json::Json;
use std::path::{Path, PathBuf};

/// The file holding the relay's own private key, inside the key directory.
///
/// Named `server.key` because that is what the deployed tunnel reads for
/// `--identity server`; see [`crate::runner::SERVER_IDENTITY`].
pub const SERVER_KEY_FILE: &str = "server.key";

/// The extension a peer's public key file carries.
///
/// One file per roster entry, named for the entry — `dad.pub` for `--peer dad`.
/// That is why `config`'s peer name is held to `[a-z0-9-]`: it is a filename
/// before it is anything else.
pub const PEER_KEY_SUFFIX: &str = ".pub";

/// The tag `key_manager.py` writes at the start of every public key file.
///
/// Read off `scripts/securevpn/app/key_manager.py`, which writes
/// `securevpn-ed25519 <base64> <name>` and refuses to load a file whose first
/// field is anything else. Named here so the two agree by construction rather
/// than by somebody remembering.
pub const PEER_KEY_TAG: &str = "securevpn-ed25519";

/// The permission bits a key directory must not grant, on a platform with modes.
///
/// `0o077` is group and world, all three of read, write and execute. The private
/// key inside is the whole perimeter — `docs/SECURITY.md` calls the client key the
/// outermost layer of it — and a directory any local account can list is a
/// directory any local account can copy that key out of.
#[cfg(unix)]
const FORBIDDEN_MODE_BITS: u32 = 0o077;

/// Where this relay's keys live, resolved against the deployment's data
/// directory.
///
/// The one place the resolution happens. `Relay::key_dir` gives the relative path
/// — validated at load to be relative and free of `..`, so a private key cannot
/// be moved outside the one directory whose permissions, backups and teardown are
/// written about — and this joins it. Two call sites deriving this separately is
/// how a relay ends up reading keys from a directory nobody inspected.
pub fn key_dir(relay: &Relay, data_dir: &Path) -> PathBuf {
    data_dir.join(relay.key_dir())
}

/// The file holding one peer's public key.
pub fn peer_key_file(key_dir: &Path, peer: &str) -> PathBuf {
    key_dir.join(format!("{peer}{PEER_KEY_SUFFIX}"))
}

/// The file holding this relay's own private key.
pub fn server_key_file(key_dir: &Path) -> PathBuf {
    key_dir.join(SERVER_KEY_FILE)
}

/// What is on disk for one relay, and what is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyReport {
    /// The directory that was inspected.
    pub dir: PathBuf,
    /// Whether the directory exists at all.
    pub dir_present: bool,
    /// Whether the relay's own private key is there.
    pub server_key: bool,
    /// Public key files named for a role rather than a device (`client.pub`).
    ///
    /// The shared key every device once used. It is never a Peer, so it is
    /// something to delete, not something to enrol.
    pub shared_keys: Vec<String>,
    /// On a platform with POSIX modes, whether the directory is readable by
    /// anybody but its owner. `None` where the concept does not apply.
    pub too_open: Option<bool>,
}

impl KeyReport {
    /// Whether the relay has its directory and its own private key.
    pub fn is_startable(&self) -> bool {
        self.dir_present && self.server_key
    }

    /// Every non-fatal observation, phrased for a service log.
    ///
    /// Written into the relay's own captured output by [`crate::Relays::up`] with
    /// a `[vpn]` tag, the way a deployment's notes are tagged `[git]`.
    pub fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if let Some(true) = self.too_open {
            notes.push(format!(
                "[vpn] {} is readable by more than its owner; the private key inside it is this \
                 relay's whole perimeter. chmod 700 it",
                self.dir.display()
            ));
        }
        for file in &self.shared_keys {
            notes.push(format!(
                "[vpn] {} is a shared key, not a device. Nobody is admitted with it; delete it",
                self.dir.join(file).display()
            ));
        }
        notes
    }

    /// The report as it goes over the wire.
    pub fn to_json(&self) -> Json {
        Json::object([
            ("dir", Json::string(self.dir.display().to_string())),
            ("present", Json::Bool(self.dir_present)),
            ("serverKey", Json::Bool(self.server_key)),
            ("startable", Json::Bool(self.is_startable())),
            ("sharedKeys", Json::array(self.shared_keys.iter().map(Json::string))),
            ("tooOpen", self.too_open.map(Json::Bool).unwrap_or(Json::Null)),
        ])
    }
}

/// Reads what is on disk for one relay.
///
/// The impure half of this module, and it only ever reads: nothing here creates
/// the directory, writes a key, or repairs a mode.
pub async fn inspect(key_dir: &Path) -> KeyReport {
    let dir_present = tokio::fs::metadata(key_dir).await.is_ok_and(|meta| meta.is_dir());
    let server_key = tokio::fs::metadata(server_key_file(key_dir))
        .await
        .is_ok_and(|meta| meta.is_file());

    // `server.pub` is the relay's own public half and belongs there.
    let mut shared_keys = Vec::new();
    for name in RESERVED_PEER_NAMES.iter().filter(|name| **name != crate::runner::SERVER_IDENTITY) {
        if tokio::fs::metadata(peer_key_file(key_dir, name)).await.is_ok() {
            shared_keys.push(format!("{name}{PEER_KEY_SUFFIX}"));
        }
    }

    KeyReport {
        dir: key_dir.to_path_buf(),
        dir_present,
        server_key,
        shared_keys,
        too_open: directory_too_open(key_dir).await,
    }
}

/// Whether the key directory grants anything to group or world.
///
/// `None` on a platform without POSIX modes, and that is not the same answer as
/// `Some(false)`: Windows protects the deployed key directory with an explicit
/// ACL (`install-vpn-service.ps1` locks it to Administrators and SYSTEM), which
/// this crate does not read, so claiming "closed" there would be a claim nobody
/// checked.
#[cfg(unix)]
async fn directory_too_open(key_dir: &Path) -> Option<bool> {
    use std::os::unix::fs::PermissionsExt;
    let meta = tokio::fs::metadata(key_dir).await.ok()?;
    Some(meta.permissions().mode() & FORBIDDEN_MODE_BITS != 0)
}

#[cfg(not(unix))]
async fn directory_too_open(key_dir: &Path) -> Option<bool> {
    let _ = key_dir;
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::forwarding_relay;

    /// A scratch key directory, unique per test so the suite can run in parallel.
    async fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("selfhost-vpn-keys-{}-{tag}", std::process::id()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
        tokio::fs::create_dir_all(&dir).await.expect("a scratch directory");
        dir
    }

    #[test]
    fn the_key_directory_is_resolved_inside_the_data_directory() {
        let relay = forwarding_relay();
        assert_eq!(
            key_dir(&relay, Path::new("/var/selfhost")),
            PathBuf::from("/var/selfhost").join("vpn").join("console")
        );
    }

    #[test]
    fn a_peers_file_is_named_for_the_roster_entry() {
        let dir = PathBuf::from("/keys");
        assert_eq!(peer_key_file(&dir, "dad"), PathBuf::from("/keys/dad.pub"));
        assert_eq!(server_key_file(&dir), PathBuf::from("/keys/server.key"));
    }

    #[tokio::test]
    async fn a_directory_that_does_not_exist_is_not_startable() {
        let report = inspect(Path::new("/selfhost-vpn/no/such/directory")).await;
        assert!(!report.dir_present);
        assert!(!report.is_startable());
    }

    #[tokio::test]
    async fn a_relay_with_no_private_key_of_its_own_is_not_startable() {
        let dir = scratch("no-server-key").await;
        let report = inspect(&dir).await;
        assert!(!report.server_key);
        assert!(!report.is_startable());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn a_stray_shared_client_key_is_something_to_delete() {
        let dir = scratch("stray-client").await;
        tokio::fs::write(server_key_file(&dir), "private").await.expect("write");
        tokio::fs::write(dir.join("server.pub"), "public").await.expect("write");
        tokio::fs::write(peer_key_file(&dir, "client"), "public").await.expect("write");

        let report = inspect(&dir).await;
        assert!(report.is_startable(), "a leftover file does not take the door down");
        assert_eq!(report.shared_keys, vec!["client.pub".to_owned()]);
        assert!(report.notes().iter().any(|note| note.contains("delete it")), "{:?}", report.notes());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_world_readable_key_directory_is_noticed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("too-open").await;
        tokio::fs::write(server_key_file(&dir), "private").await.expect("write");

        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .await
            .expect("chmod");
        let open = inspect(&dir).await;
        assert_eq!(open.too_open, Some(true));
        assert!(open.notes().iter().any(|note| note.contains("chmod 700")), "{:?}", open.notes());
        // Still startable: a mode this crate did not set is the operator's to
        // fix, and refusing would take the console down for a warning.
        assert!(open.is_startable());

        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .await
            .expect("chmod");
        assert_eq!(inspect(&dir).await.too_open, Some(false));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
