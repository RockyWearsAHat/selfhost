//! `selfhost breakglass` — a recovery credential the SSH relay can trust
//! without asking the People registry anything (index.dx rule 9: "Control
//! never depends on what it controls").
//!
//! # What already does not depend on People
//!
//! The relay's key-pinning layer admits a device only because a signed-in
//! account enrolled it (`crates/services/vpn/src/roster.rs`), which needs the
//! daemon and the identity system to be working. A break-glass device should
//! not need any of that: an owner recovering a locked-out box wants to drop in
//! a key and be done.
//!
//! This module adds exactly that and nothing else: one flat file, one CLI,
//! reusing the *same* key-file format and validation the ordinary roster
//! already uses (`selfhost_vpn::keys`, `selfhost_config::vpn::peer_name_problem`)
//! so there is still only one copy of "what a valid Ed25519 pin looks like"
//! in the workspace — this is not a second key format, just a second place a
//! label may be entered from.
//!
//! # What this module does not fix
//!
//! Investigating `runner::plan` while building this (`crates/services/vpn/src/runner.rs`)
//! turned up a second, deeper rule-9 gap that this round does not close: a
//! completed handshake still has to clear a `vpn.access:<relay>` capability
//! check against the daemon's own admin API (`--account-manager
//! http://<admin_bind>`) before the tunnel forwards anything. That check can
//! only ever be answered by the running daemon, so an SSH relay whose crypto
//! layer is perfectly healthy still refuses every peer — a break-glass one
//! included — while the daemon (and the People/Grants store behind its admin
//! API) is down. Wiring a break-glass label into that capability check, or
//! giving the admin API's `check-access` handler an escape hatch that reads
//! this file directly with no People lookup, is real future work; it is not
//! attempted here because it touches the same command line a byte-for-byte
//! test (`runner::tests::the_invocation_is_the_one_the_production_box_already_runs`)
//! asserts against a live production box, and "smallest clean design" does
//! not mean "risk the one door that is already working." Recorded in
//! `docs/labs/breakglass-watchdog-lab.dx` and `index.dx`'s gaps list.
//!
//! # What this module does do
//!
//! `add`/`remove` write straight to `<data_dir>/breakglass.keys` (list format:
//! one `<label> <key>` per line, `key` in the exact shape
//! `selfhost_vpn::keys::parse_public_key` already accepts — either
//! `securevpn-ed25519 <base64>` or a bare base64 line) and, best-effort, also
//! materialise the same key as `<key_dir>/breakglass-<label>.pub` inside the
//! **`ssh`** relay's own key directory, in the exact format
//! `key_manager.py` writes, so the file the relay's key-presence check and
//! (once wired) the tunnel itself read is never a second format to keep in
//! sync by hand. All of this is plain file I/O — no daemon needs to be
//! running, no network call is made, and nothing here parses or generates key
//! bytes; the base64 is carried as opaque text throughout, matching the
//! workspace's "cryptography is not written here" policy.

use selfhost_config::Config;
use selfhost_config::vpn::peer_name_problem;
use selfhost_vpn::keys::{PEER_KEY_SUFFIX, PEER_KEY_TAG, key_dir, parse_public_key};
use std::path::{Path, PathBuf};

/// The file this deployment's break-glass keys live in, directly under the
/// data directory — never inside a relay's own key directory, so it reads
/// and edits with no config and no relay declared at all.
pub const FILE_NAME: &str = "breakglass.keys";

/// The relay this break-glass store exists for. SSH is the box's break-glass
/// door (`docs/SECURITY.md` SSH-02, index.dx rule 9); the console relay keeps
/// using the ordinary roster only.
const RELAY_NAME: &str = "ssh";

/// The prefix a mirrored key file is written under, inside the relay's key
/// directory — distinct from an ordinary roster peer's own file name so a
/// break-glass entry can never collide with, or be mistaken for, one.
const MIRROR_PREFIX: &str = "breakglass-";

pub const USAGE: &str = "\
Usage
  selfhost breakglass list                    Every pinned device, by label
  selfhost breakglass add <label> <pubkey>    Pin a device's Ed25519 public key
  selfhost breakglass remove <label>          Un-pin a device

<pubkey> is what the device's own Secure-VPN client already prints: either a
bare base64 key, or a full \"securevpn-ed25519 <base64> <name>\" line copied
from that device's own .pub file — either is accepted, following the same
key_manager.py format the SSH relay's ordinary roster already reads.

This edits a local file (<data_dir>/breakglass.keys) directly. No daemon
needs to be running, and nothing here touches the People registry or any
grant — see the module documentation in breakglass.rs for exactly what that
does and does not mean for the running relay.
";

/// One pinned device: a label, and the key text exactly as it was entered
/// (never decoded — this crate does not touch key bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub label: String,
    pub key: String,
}

/// Where the break-glass file lives for this deployment.
pub fn path(data_dir: &Path) -> PathBuf {
    data_dir.join(FILE_NAME)
}

/// Reads every entry, oldest first. An absent file is an empty list, not an
/// error — the ordinary state before the first device is ever pinned.
pub fn load(data_dir: &Path) -> Result<Vec<Entry>, String> {
    let file = path(data_dir);
    let text = match std::fs::read_to_string(&file) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("cannot read {}: {error}", file.display())),
    };
    let mut entries = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_line(line) {
            Some(entry) => entries.push(entry),
            None => {
                return Err(format!(
                    "{}:{}: not a valid \"<label> <key>\" line",
                    file.display(),
                    number + 1
                ));
            }
        }
    }
    Ok(entries)
}

/// Splits one line into a label and the key text after it, requiring the key
/// half to parse exactly as an ordinary roster peer's `.pub` file would.
fn parse_line(line: &str) -> Option<Entry> {
    let (label, rest) = line.split_once(char::is_whitespace)?;
    let rest = rest.trim();
    parse_public_key(rest)?;
    Some(Entry { label: label.to_owned(), key: rest.to_owned() })
}

/// Writes the whole list back, atomically: a temporary sibling, then a
/// rename, the same shape `self_update::install_atomically` and
/// `proxy::tls::write_atomic` use for the identical reason — a reader must
/// never see a half-written file.
fn save(data_dir: &Path, entries: &[Entry]) -> Result<(), String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|error| format!("cannot create {}: {error}", data_dir.display()))?;
    let file = path(data_dir);
    let temp = file.with_extension("keys.tmp");
    let mut text = String::new();
    for entry in entries {
        text.push_str(&entry.label);
        text.push(' ');
        text.push_str(&entry.key);
        text.push('\n');
    }
    std::fs::write(&temp, text).map_err(|error| format!("cannot write {}: {error}", temp.display()))?;
    std::fs::rename(&temp, &file).map_err(|error| format!("cannot install {}: {error}", file.display()))
}

/// Pins a device's key under `label`, refusing a duplicate label or a key
/// that does not parse, and mirrors it into the `ssh` relay's own key
/// directory when one is configured.
pub fn add(config: &Config, data_dir: &Path, label: &str, key: &str) -> Result<(), String> {
    if let Some(problem) = peer_name_problem(label) {
        return Err(format!("\"{label}\" is not a usable label: {problem}"));
    }
    let key = key.trim();
    if parse_public_key(key).is_none() {
        return Err(format!(
            "\"{key}\" is not a key `parse_public_key` recognises — expected \
             \"{PEER_KEY_TAG} <base64>\" or a bare base64 line"
        ));
    }
    let mut entries = load(data_dir)?;
    if entries.iter().any(|entry| entry.label == label) {
        return Err(format!(
            "\"{label}\" is already pinned — remove it first if you mean to replace it"
        ));
    }
    entries.push(Entry { label: label.to_owned(), key: key.to_owned() });
    save(data_dir, &entries)?;
    mirror_install(config, data_dir, label, key)
}

/// Un-pins a label, refusing one that is not there, and removes its mirrored
/// key file when one was written.
pub fn remove(config: &Config, data_dir: &Path, label: &str) -> Result<(), String> {
    let mut entries = load(data_dir)?;
    let before = entries.len();
    entries.retain(|entry| entry.label != label);
    if entries.len() == before {
        return Err(format!("\"{label}\" is not pinned"));
    }
    save(data_dir, &entries)?;
    mirror_remove(config, data_dir, label)
}

/// The path a label's key would be mirrored to inside the `ssh` relay's key
/// directory, or `None` when this deployment has not configured that relay —
/// break-glass keys still record fine in the flat file either way; there is
/// simply nowhere to mirror them to yet.
fn mirror_path(config: &Config, data_dir: &Path, label: &str) -> Option<PathBuf> {
    let relay = config.vpn.iter().find(|relay| relay.name == RELAY_NAME)?;
    let dir = key_dir(relay, data_dir);
    Some(dir.join(format!("{MIRROR_PREFIX}{label}{PEER_KEY_SUFFIX}")))
}

/// Writes the mirrored `.pub` file, in the exact three-field format
/// `key_manager.py` writes, best-effort: a deployment with no `ssh` relay
/// configured yet is not an error, only a note.
fn mirror_install(config: &Config, data_dir: &Path, label: &str, key: &str) -> Result<(), String> {
    let Some(mirror) = mirror_path(config, data_dir, label) else {
        println!(
            "  note: no [[vpn]] relay named \"{RELAY_NAME}\" is configured yet, so this key is \
             recorded in {} only; it will be mirrored into that relay's key directory the next \
             time this command runs after \"ssh\" is configured",
            path(data_dir).display()
        );
        return Ok(());
    };
    if let Some(parent) = mirror.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    // Normalise to the tagged, three-field shape regardless of which shape was
    // typed in, so every file this relay's key directory holds — ordinary
    // roster peer or break-glass label alike — looks the same on disk.
    let normalised = if let Some(base64) = key.strip_prefix(&format!("{PEER_KEY_TAG} ")) {
        let base64 = base64.split_whitespace().next().unwrap_or(base64);
        format!("{PEER_KEY_TAG} {base64} {MIRROR_PREFIX}{label}")
    } else {
        format!("{PEER_KEY_TAG} {key} {MIRROR_PREFIX}{label}")
    };
    std::fs::write(&mirror, format!("{normalised}\n"))
        .map_err(|error| format!("cannot write {}: {error}", mirror.display()))?;
    println!("  mirrored into {}", mirror.display());
    Ok(())
}

/// Removes the mirrored file, tolerating one that was never written (no `ssh`
/// relay configured when `add` ran, or none configured now).
fn mirror_remove(config: &Config, data_dir: &Path, label: &str) -> Result<(), String> {
    let Some(mirror) = mirror_path(config, data_dir, label) else {
        return Ok(());
    };
    match std::fs::remove_file(&mirror) {
        Ok(()) => println!("  removed {}", mirror.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(format!("cannot remove {}: {error}", mirror.display())),
    }
    Ok(())
}

/// The CLI entry point: `selfhost breakglass list|add|remove`.
pub fn run(arguments: &[String], config: &Config, data_dir: &Path) -> Result<(), String> {
    match arguments.get(1).map(String::as_str) {
        Some("list") => {
            let entries = load(data_dir)?;
            if entries.is_empty() {
                println!("No break-glass devices pinned yet. See:\n\n{USAGE}");
                return Ok(());
            }
            println!("Pinned break-glass devices ({}):\n", path(data_dir).display());
            for entry in entries {
                println!("  {:<20} {}", entry.label, entry.key);
            }
            Ok(())
        }
        Some("add") => {
            let label = arguments
                .get(2)
                .ok_or_else(|| format!("breakglass add needs a label and a key\n\n{USAGE}"))?;
            let key = arguments
                .get(3)
                .ok_or_else(|| format!("breakglass add needs a key after the label\n\n{USAGE}"))?;
            add(config, data_dir, label, key)?;
            println!("✓ pinned \"{label}\"");
            Ok(())
        }
        Some("remove") => {
            let label = arguments
                .get(2)
                .ok_or_else(|| format!("breakglass remove needs a label\n\n{USAGE}"))?;
            remove(config, data_dir, label)?;
            println!("✓ un-pinned \"{label}\"");
            Ok(())
        }
        Some(other) => Err(format!("unknown breakglass subcommand \"{other}\"\n\n{USAGE}")),
        None => Err(format!("breakglass needs a subcommand: list, add, or remove\n\n{USAGE}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "selfhost-breakglass-test-{label}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// The smallest config that parses, with no VPN relays declared — the
    /// same shape `health.rs`'s own tests build, so a break-glass entry can be
    /// recorded before any relay exists at all.
    fn config_without_ssh_relay() -> Config {
        use selfhost_config::{AcmeEnvironment, Firewall, Node, Role, Server};
        Config {
            version: 1,
            server: Server {
                http_bind: "127.0.0.1:0".into(),
                https_bind: "127.0.0.1:0".into(),
                acme_email: "a@b.com".into(),
                acme: AcmeEnvironment::SelfSigned,
                data_dir: std::path::PathBuf::from("./data"),
                admin_bind: "127.0.0.1:0".into(),
                firewall: Firewall::default(),
            },
            nodes: vec![Node { name: "home".into(), role: Role::Owner, mesh_ip: None }],
            sites: Vec::new(),
            dns: None,
            mail: None,
            self_update: None,
            github_app: None,
            shares: Vec::new(),
            desktop: None,
            mesh: None,
            home: None,
            vpn: Vec::new(),
            maintenance: None,
        }
    }

    fn config_with_ssh_relay(data_dir: &Path) -> Config {
        let mut config = config_without_ssh_relay();
        let mut relay = selfhost_config::vpn::Relay::new("ssh", "0.0.0.0:8444", "127.0.0.1:22");
        relay.enabled = true;
        relay.public = true;
        // `key_dir` is joined onto `data_dir` by `keys::key_dir`; naming it
        // explicitly here just keeps this test independent of the relay's own
        // `vpn/<name>` default.
        relay.key_dir = Some(data_dir.join("vpn-ssh-keys"));
        config.vpn.push(relay);
        config
    }

    #[test]
    fn an_empty_directory_has_no_entries() {
        let dir = temp_dir("empty");
        assert_eq!(load(&dir).unwrap(), Vec::new());
    }

    #[test]
    fn a_pinned_bare_base64_key_round_trips() {
        let dir = temp_dir("roundtrip-bare");
        let config = config_without_ssh_relay();
        add(&config, &dir, "laptop", &"A".repeat(43)).unwrap();
        let entries = load(&dir).unwrap();
        assert_eq!(entries, vec![Entry { label: "laptop".into(), key: "A".repeat(43) }]);
    }

    #[test]
    fn a_pinned_tagged_key_round_trips() {
        let dir = temp_dir("roundtrip-tagged");
        let config = config_without_ssh_relay();
        let key = format!("{PEER_KEY_TAG} {} phone", "B".repeat(43));
        add(&config, &dir, "phone", &key).unwrap();
        let entries = load(&dir).unwrap();
        assert_eq!(entries, vec![Entry { label: "phone".into(), key }]);
    }

    #[test]
    fn a_bad_label_is_refused_before_anything_is_written() {
        let dir = temp_dir("bad-label");
        let config = config_without_ssh_relay();
        let error = add(&config, &dir, "Not Legal", &"A".repeat(43)).unwrap_err();
        assert!(error.contains("Not Legal"), "{error}");
        assert!(load(&dir).unwrap().is_empty());
    }

    #[test]
    fn a_key_parse_public_key_rejects_is_refused() {
        let dir = temp_dir("bad-key");
        let config = config_without_ssh_relay();
        let error = add(&config, &dir, "laptop", "this is not a key at all").unwrap_err();
        assert!(error.contains("not a key"), "{error}");
    }

    #[test]
    fn a_duplicate_label_is_refused() {
        let dir = temp_dir("duplicate");
        let config = config_without_ssh_relay();
        add(&config, &dir, "laptop", &"A".repeat(43)).unwrap();
        let error = add(&config, &dir, "laptop", &"B".repeat(43)).unwrap_err();
        assert!(error.contains("already pinned"), "{error}");
    }

    #[test]
    fn removing_an_unknown_label_is_refused() {
        let dir = temp_dir("remove-unknown");
        let config = config_without_ssh_relay();
        let error = remove(&config, &dir, "ghost").unwrap_err();
        assert!(error.contains("is not pinned"), "{error}");
    }

    #[test]
    fn adding_then_removing_leaves_the_file_empty() {
        let dir = temp_dir("add-then-remove");
        let config = config_without_ssh_relay();
        add(&config, &dir, "laptop", &"A".repeat(43)).unwrap();
        remove(&config, &dir, "laptop").unwrap();
        assert!(load(&dir).unwrap().is_empty());
    }

    #[test]
    fn with_no_ssh_relay_configured_nothing_is_mirrored() {
        let dir = temp_dir("no-mirror");
        let config = config_without_ssh_relay();
        add(&config, &dir, "laptop", &"A".repeat(43)).unwrap();
        assert!(mirror_path(&config, &dir, "laptop").is_none());
    }

    #[test]
    fn with_an_ssh_relay_configured_the_key_is_mirrored_in_key_manager_format() {
        let dir = temp_dir("mirror");
        let config = config_with_ssh_relay(&dir);
        let base64 = "C".repeat(43);
        add(&config, &dir, "laptop", &base64).unwrap();
        let mirror = mirror_path(&config, &dir, "laptop").unwrap();
        let text = std::fs::read_to_string(&mirror).unwrap();
        assert_eq!(text, format!("{PEER_KEY_TAG} {base64} {MIRROR_PREFIX}laptop\n"));
    }

    #[test]
    fn removing_a_mirrored_key_deletes_its_file() {
        let dir = temp_dir("mirror-remove");
        let config = config_with_ssh_relay(&dir);
        add(&config, &dir, "laptop", &"D".repeat(43)).unwrap();
        let mirror = mirror_path(&config, &dir, "laptop").unwrap();
        assert!(mirror.exists());
        remove(&config, &dir, "laptop").unwrap();
        assert!(!mirror.exists());
    }

    #[test]
    fn a_corrupt_line_is_reported_with_its_line_number() {
        let dir = temp_dir("corrupt");
        std::fs::write(path(&dir), "laptop\n").unwrap(); // missing key half
        let error = load(&dir).unwrap_err();
        assert!(error.contains(":1:"), "{error}");
    }
}
