//! Where a relay's key material lives, and what has to be true of it before the
//! relay is started.
//!
//! **This module never generates, parses, or writes a key.** It resolves paths,
//! reads a public key file to compare it with the roster, and reports what is
//! missing. Generating a keypair is the tunnel implementation's job
//! (`scripts/securevpn/rotate-keys.sh` on this deployment), and the workspace
//! dependency policy is that cryptography is not written here — which includes
//! half-writing it.
//!
//! # Why the check exists at all
//!
//! A relay's roster lives in two places and they can drift. The config's
//! `[[vpn.peers]]` block is the reviewable, diffable half — the property this
//! subsystem was believed to have lost, and the reason the roster was put in the
//! config at all. (The belief was mistaken: the tunnel's own source is reviewable
//! too, in the operator's repository. The roster still belongs here, because a
//! *deployment's* enrolments are this deployment's document to review, not
//! upstream's.) The `*.pub` files under the key directory are the
//! half the tunnel actually reads. A peer enrolled in the config with no file on
//! disk is a person who has been told they have access and does not; the relay
//! starts, the port binds, and their handshake fails with a message that says only
//! that it did not complete. So [`inspect`] answers that before anything is
//! spawned, and [`crate::Relays::up`] refuses on a missing file rather than
//! starting a door somebody cannot come through.
//!
//! # What the comparison can and cannot claim
//!
//! Until 2026-08-17 this module compared the whole trimmed text of `<peer>.pub`
//! against the roster's base64, under a comment saying the file's format belonged
//! to an implementation nobody here could read. It could always have been read —
//! `key_manager.py` is committed in the Secure-VPN repository and was on this Mac
//! besides — and reading it (vendored at `scripts/securevpn/app/`) showed
//! the guess was **wrong**: a `.pub` file is
//! `securevpn-ed25519 <base64> <name>\n`, three space-separated fields, so the
//! whole-text comparison could never match a file the tunnel actually wrote and
//! every peer on every real deployment would have been reported as unconfirmed.
//! [`parse_public_key`] reads the real format now, and accepts a bare base64 line
//! as well — a key pasted into a file by hand is the shape an operator produces
//! and it is not evidence of anything being wrong.
//!
//! [`KeyReport::unconfirmed_peers`] still **reports** rather than refuses, and the
//! reason has changed from "this crate cannot read the format" to something
//! narrower: the tunnel is the authority on its own key files, and a start refused
//! here on a disagreement would take the deployment's only door down over a file
//! this crate does not own.

use selfhost_config::vpn::Relay;
use selfhost_json::Json;
use std::path::{Path, PathBuf};

use crate::roster::Roster;

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

/// The base64 public key inside a `.pub` file, or `None` when the text is not one.
///
/// Two accepted shapes, and both are real. `key_manager.py`'s own format is three
/// space-separated fields with [`PEER_KEY_TAG`] first; a bare base64 line is what
/// an operator produces when they paste a key into a file by hand, and refusing
/// that would report a working key as broken. Anything else is not a key, and
/// saying so is more useful than reporting it as a mismatch.
pub fn parse_public_key(text: &str) -> Option<&str> {
    let mut fields = text.split_whitespace();
    let first = fields.next()?;
    if first == PEER_KEY_TAG {
        return fields.next();
    }
    // A bare key is one field and nothing after it. A first field that is not the
    // tag *and* is followed by more text is some other file entirely.
    fields.next().is_none().then_some(first)
}

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
    /// Enrolled peers with no public key file. Each one is somebody who has been
    /// told they have access and does not.
    pub missing_peers: Vec<String>,
    /// Peers whose file exists but does not hold the roster's base64.
    ///
    /// Reported, never enforced — see the module documentation for what this can
    /// and cannot claim.
    pub unconfirmed_peers: Vec<String>,
    /// Peers whose file this crate could not parse as a public key at all.
    ///
    /// Separate from [`Self::unconfirmed_peers`] because they are different
    /// things for an operator to do: a key that disagrees with the roster is two
    /// records drifting, and a file that is not a key is a truncated copy, a
    /// private key pasted into the wrong name, or a directory listing saved by
    /// mistake. Also reported rather than enforced, for the same reason.
    pub unreadable_peers: Vec<String>,
    /// On a platform with POSIX modes, whether the directory is readable by
    /// anybody but its owner. `None` where the concept does not apply.
    pub too_open: Option<bool>,
}

impl KeyReport {
    /// Whether the relay has everything it needs to admit the roster it was given.
    ///
    /// The private key and one public key per enrolled peer. Anything else is a
    /// relay that binds a port and then refuses somebody it was configured to
    /// admit, which is the failure this exists to move earlier.
    pub fn is_startable(&self) -> bool {
        self.dir_present && self.server_key && self.missing_peers.is_empty()
    }

    /// Every non-fatal observation, phrased for a service log.
    ///
    /// Written into the relay's own captured output by [`crate::Relays::up`] with
    /// a `[vpn]` tag, the way a deployment's notes are tagged `[git]`, so that "a
    /// key file could not be confirmed" sits next to the tunnel's own output
    /// rather than in a second place an operator has to correlate by timestamp.
    pub fn notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if let Some(true) = self.too_open {
            notes.push(format!(
                "[vpn] {} is readable by more than its owner; the private key inside it is this \
                 relay's whole perimeter. chmod 700 it",
                self.dir.display()
            ));
        }
        for peer in &self.unconfirmed_peers {
            notes.push(format!(
                "[vpn] {peer}{PEER_KEY_SUFFIX} holds a different key from the one this relay's \
                 roster records for \"{peer}\". The tunnel reads the file and this crate reads \
                 the config, so the two have drifted; whichever is stale, that peer connects as \
                 whatever the file says and is recorded as whatever the config says. Reported \
                 rather than refused, because a start blocked here takes the only door down"
            ));
        }
        for peer in &self.unreadable_peers {
            notes.push(format!(
                "[vpn] {peer}{PEER_KEY_SUFFIX} is not a public key file. \
                 scripts/securevpn/app/key_manager.py writes \"{PEER_KEY_TAG} <base64> <name>\" \
                 and refuses anything else, so this file will fail the tunnel's own load — a \
                 truncated copy, or a private key written to the wrong name"
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
            ("missingPeers", Json::array(self.missing_peers.iter().map(Json::string))),
            ("unconfirmedPeers", Json::array(self.unconfirmed_peers.iter().map(Json::string))),
            ("unreadablePeers", Json::array(self.unreadable_peers.iter().map(Json::string))),
            ("tooOpen", self.too_open.map(Json::Bool).unwrap_or(Json::Null)),
        ])
    }
}

/// Reads what is on disk for one relay's roster.
///
/// The impure half of this module, and it only ever reads: nothing here creates
/// the directory, writes a key, or repairs a mode. That is the same discipline
/// `crates/net/firewall` and `smb` follow — report a plan, never assert one — and
/// here it matters more, because the thing that would be "repaired" is the file
/// that decides who may reach this machine.
pub async fn inspect(key_dir: &Path, roster: &Roster) -> KeyReport {
    let dir_present = tokio::fs::metadata(key_dir).await.is_ok_and(|meta| meta.is_dir());
    let server_key = tokio::fs::metadata(server_key_file(key_dir))
        .await
        .is_ok_and(|meta| meta.is_file());

    let mut missing_peers = Vec::new();
    let mut unconfirmed_peers = Vec::new();
    let mut unreadable_peers = Vec::new();
    for entry in roster.enrolled() {
        let path = peer_key_file(key_dir, &entry.peer);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                match parse_public_key(&text) {
                    // The roster may spell the key padded or unpadded, and the
                    // file may spell it the other way; `config` accepts both, so
                    // comparing them literally would report a working key as a
                    // mismatch on the strength of one "=".
                    Some(key) => {
                        if unpadded(key) != unpadded(&entry.public_key) {
                            unconfirmed_peers.push(entry.peer.clone());
                        }
                    }
                    None => unreadable_peers.push(entry.peer.clone()),
                }
            }
            Err(_) => missing_peers.push(entry.peer.clone()),
        }
    }

    KeyReport {
        dir: key_dir.to_path_buf(),
        dir_present,
        server_key,
        missing_peers,
        unconfirmed_peers,
        unreadable_peers,
        too_open: directory_too_open(key_dir).await,
    }
}

/// A base64 key without its optional padding, for comparing two spellings of one
/// key. Not a decode: this crate does not link base64 and does not need to.
fn unpadded(key: &str) -> &str {
    key.trim().trim_end_matches('=')
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
    use crate::roster::Roster;
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
        let roster = Roster::build(&forwarding_relay());
        let report = inspect(Path::new("/selfhost-vpn/no/such/directory"), &roster).await;
        assert!(!report.dir_present);
        assert!(!report.is_startable());
        assert_eq!(report.missing_peers, vec!["alex-mac".to_owned()]);
    }

    #[tokio::test]
    async fn a_peer_with_no_key_file_blocks_the_start_and_is_named() {
        // The failure this moves earlier: the relay binds, the person is told
        // they have access, and their handshake fails saying only that it did
        // not complete.
        let dir = scratch("missing-peer").await;
        tokio::fs::write(server_key_file(&dir), "private").await.expect("write");

        let roster = Roster::build(&forwarding_relay());
        let report = inspect(&dir, &roster).await;
        assert!(!report.is_startable());
        assert_eq!(report.missing_peers, vec!["alex-mac".to_owned()]);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn a_relay_with_no_private_key_of_its_own_is_not_startable() {
        let dir = scratch("no-server-key").await;
        let roster = Roster::build(&forwarding_relay());
        tokio::fs::write(peer_key_file(&dir, "alex-mac"), roster.enrolled()[0].public_key.clone())
            .await
            .expect("write");

        let report = inspect(&dir, &roster).await;
        assert!(!report.server_key);
        assert!(!report.is_startable());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[test]
    fn the_key_file_format_is_the_one_key_manager_py_actually_writes() {
        // The bug vendoring the implementation exposed. `key_manager.py` writes
        // "securevpn-ed25519 <base64> <name>", so the old whole-text comparison
        // could never match a file the tunnel had written, and every peer on
        // every real deployment would have been reported as unconfirmed.
        let key = "A".repeat(43);
        assert_eq!(
            parse_public_key(&format!("{PEER_KEY_TAG} {key} alex-mac\n")),
            Some(key.as_str())
        );
        // A key pasted into a file by hand is one field and nothing else, and
        // refusing it would report a working key as broken.
        assert_eq!(parse_public_key(&format!("  {key}  \n")), Some(key.as_str()));
        // Anything else is not a key file at all.
        for not_a_key in ["", "   ", "ssh-ed25519 AAAA alex@mac", "-----BEGIN PRIVATE KEY-----"] {
            assert_eq!(parse_public_key(not_a_key), None, "{not_a_key:?}");
        }
    }

    #[tokio::test]
    async fn a_complete_key_directory_is_startable_and_silent() {
        let dir = scratch("complete").await;
        let roster = Roster::build(&forwarding_relay());
        tokio::fs::write(server_key_file(&dir), "private").await.expect("write");
        // Written the way the tunnel writes it, trailing newline and all.
        tokio::fs::write(
            peer_key_file(&dir, "alex-mac"),
            format!("{PEER_KEY_TAG} {} alex-mac\n", roster.enrolled()[0].public_key),
        )
        .await
        .expect("write");

        let report = inspect(&dir, &roster).await;
        assert!(report.is_startable());
        assert!(report.unconfirmed_peers.is_empty(), "{report:?}");
        assert!(report.unreadable_peers.is_empty(), "{report:?}");
        assert!(report.notes().is_empty() || report.too_open == Some(true), "{:?}", report.notes());

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn one_padding_character_is_not_a_drift() {
        // `config` accepts a key padded or unpadded and the two tools disagree
        // about which they write, so a literal comparison would report a working
        // deployment as drifting on the strength of a single "=".
        let dir = scratch("padding").await;
        let mut relay = forwarding_relay();
        relay.peers[0].public_key = format!("{}=", "A".repeat(43));
        let roster = Roster::build(&relay);
        tokio::fs::write(server_key_file(&dir), "private").await.expect("write");
        tokio::fs::write(
            peer_key_file(&dir, "alex-mac"),
            format!("{PEER_KEY_TAG} {} alex-mac\n", "A".repeat(43)),
        )
        .await
        .expect("write");

        let report = inspect(&dir, &roster).await;
        assert!(report.unconfirmed_peers.is_empty(), "{report:?}");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn a_key_file_that_disagrees_with_the_roster_is_reported_and_not_enforced() {
        // The two truths drifting is exactly what this check is for; refusing on
        // it would take the deployment's only door down over a file this crate
        // does not own.
        let dir = scratch("drifted").await;
        let roster = Roster::build(&forwarding_relay());
        tokio::fs::write(server_key_file(&dir), "private").await.expect("write");
        tokio::fs::write(
            peer_key_file(&dir, "alex-mac"),
            format!("{PEER_KEY_TAG} {} alex-mac\n", "Z".repeat(43)),
        )
        .await
        .expect("write");

        let report = inspect(&dir, &roster).await;
        assert!(report.is_startable(), "a drift must not take the door down");
        assert_eq!(report.unconfirmed_peers, vec!["alex-mac".to_owned()]);
        let notes = report.notes();
        assert!(notes.iter().any(|note| note.contains("alex-mac")), "{notes:?}");
        assert!(notes.iter().any(|note| note.contains("drifted")), "{notes:?}");

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn a_file_that_is_not_a_key_at_all_is_its_own_report() {
        // A different thing for an operator to do: a truncated copy or a private
        // key written to the wrong name, not two records drifting.
        let dir = scratch("not-a-key").await;
        let roster = Roster::build(&forwarding_relay());
        tokio::fs::write(server_key_file(&dir), "private").await.expect("write");
        tokio::fs::write(peer_key_file(&dir, "alex-mac"), "ssh-ed25519 AAAA alex@mac\n")
            .await
            .expect("write");

        let report = inspect(&dir, &roster).await;
        assert!(report.is_startable(), "still not fatal");
        assert_eq!(report.unreadable_peers, vec!["alex-mac".to_owned()]);
        assert!(report.unconfirmed_peers.is_empty(), "the two reports are not the same report");
        assert!(
            report.notes().iter().any(|note| note.contains(PEER_KEY_TAG)),
            "the note must say what the format is: {:?}",
            report.notes()
        );

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_world_readable_key_directory_is_noticed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("too-open").await;
        let roster = Roster::build(&forwarding_relay());
        tokio::fs::write(server_key_file(&dir), "private").await.expect("write");
        tokio::fs::write(peer_key_file(&dir, "alex-mac"), roster.enrolled()[0].public_key.clone())
            .await
            .expect("write");

        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))
            .await
            .expect("chmod");
        let open = inspect(&dir, &roster).await;
        assert_eq!(open.too_open, Some(true));
        assert!(open.notes().iter().any(|note| note.contains("chmod 700")), "{:?}", open.notes());
        // Still startable: a mode this crate did not set is the operator's to
        // fix, and refusing would take the console down for a warning.
        assert!(open.is_startable());

        tokio::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .await
            .expect("chmod");
        assert_eq!(inspect(&dir, &roster).await.too_open, Some(false));

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
