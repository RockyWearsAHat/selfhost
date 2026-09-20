//! Which Person each Peer belongs to.
//!
//! A Peer is one device's roster entry on a relay. Enrolment names it
//! `<person>-<device>` and binds it here to the Person who signed it in, so a
//! roster name is never shared between two people.
//!
//! The record is `<data_dir>/vpn.peers`, one `peer person` pair a line, written
//! as the roster file is. It holds no secret; it is private because who owns
//! which device is nobody else's business.

use crate::enrol::write_private_file;
use selfhost_config::vpn::{MAX_PEER_NAME_LEN, RESERVED_PEER_NAMES};
use std::path::{Path, PathBuf};

/// The Peer name for `person`'s device: `<person>-<device>` in roster grammar.
///
/// Decided by the server at enrolment, never by the device, so a roster name
/// always reads as somebody's device and never as a second account. `device`
/// is the label the device sent; a label that already carries the prefix (a
/// device signing in again under the name it was given) is not prefixed twice.
pub fn peer_name(person: &str, device: &str) -> String {
    let person = slug(person);
    let device = slug(device);
    let device = device.strip_prefix(&format!("{person}-")).unwrap_or(&device);
    let device = if device.is_empty() { "device" } else { device };
    let name: String = format!("{person}-{device}").chars().take(MAX_PEER_NAME_LEN).collect();
    name.trim_matches('-').to_owned()
}

/// `text` lowercased, with every run outside `[a-z0-9]` as one hyphen.
fn slug(text: &str) -> String {
    let mut out = String::new();
    for c in text.chars().map(|c| c.to_ascii_lowercase()) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_end_matches('-').to_owned()
}

/// Forgets `person`'s device `peer`: its key file and roster line on every
/// relay, then its binding. Refuses a Peer that is not theirs.
pub fn forget(
    relays: &[selfhost_config::vpn::Relay],
    data_dir: &Path,
    person: &str,
    peer: &str,
) -> Result<(), String> {
    if owner_of(data_dir, peer).as_deref() != Some(person) {
        return Err(format!("\"{peer}\" is not one of {person}'s devices"));
    }
    for relay in relays {
        crate::revoke(&crate::keys::key_dir(relay, data_dir), peer).map_err(|error| error.to_string())?;
    }
    unbind(data_dir, peer)
}

/// Where the bindings live under `data_dir`.
pub fn path_in(data_dir: &Path) -> PathBuf {
    data_dir.join("vpn.peers")
}

/// Binds `peer` to `person`, or confirms it already is.
///
/// Refuses a shared role name, and a Peer that already belongs to somebody
/// else. A Person re-enrolling their own Peer (a rotated key) is allowed.
pub fn bind(data_dir: &Path, peer: &str, person: &str) -> Result<(), String> {
    if RESERVED_PEER_NAMES.contains(&peer) {
        return Err(format!("\"{peer}\" is a shared role name, not a device; a Peer needs its own name"));
    }
    let path = path_in(data_dir);
    let mut text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };
    match owner_in(&text, peer) {
        Some(owner) if owner == person => return Ok(()),
        Some(_) => return Err(format!("the Peer \"{peer}\" already belongs to somebody else")),
        None => {}
    }
    text.push_str(&format!("{peer} {person}\n"));
    write_private_file(&path, text).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// The Person `peer` is bound to, if any.
pub fn owner_of(data_dir: &Path, peer: &str) -> Option<String> {
    let text = std::fs::read_to_string(path_in(data_dir)).ok()?;
    owner_in(&text, peer).map(str::to_owned)
}

/// Every Peer bound to `person`, in the order they were enrolled.
pub fn peers_of(data_dir: &Path, person: &str) -> Vec<String> {
    let text = std::fs::read_to_string(path_in(data_dir)).unwrap_or_default();
    text.lines()
        .filter_map(|line| line.split_once(' '))
        .filter(|(_, owner)| *owner == person)
        .map(|(peer, _)| peer.to_owned())
        .collect()
}

/// Forgets `peer`. A Peer that was never bound is not an error.
pub fn unbind(data_dir: &Path, peer: &str) -> Result<(), String> {
    let path = path_in(data_dir);
    let Ok(text) = std::fs::read_to_string(&path) else {
        return Ok(());
    };
    let kept: String = text
        .lines()
        .filter(|line| line.split_once(' ').is_none_or(|(name, _)| name != peer))
        .map(|line| format!("{line}\n"))
        .collect();
    write_private_file(&path, kept).map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn owner_in<'a>(text: &'a str, peer: &str) -> Option<&'a str> {
    text.lines().find_map(|line| {
        let (name, person) = line.split_once(' ')?;
        (name == peer).then_some(person)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("selfhost-peer-binding-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_peer_belongs_to_the_person_who_enrolled_it_and_nobody_else() {
        let dir = scratch("bind");
        bind(&dir, "laptop-4f2a", "mom").expect("first binding");
        bind(&dir, "laptop-4f2a", "mom").expect("the same Person may re-enrol");
        assert!(bind(&dir, "laptop-4f2a", "dad").is_err());
        assert_eq!(owner_of(&dir, "laptop-4f2a").as_deref(), Some("mom"));
        assert_eq!(owner_of(&dir, "phone-1"), None);
    }

    #[test]
    fn a_peer_is_named_for_its_person_and_device() {
        assert_eq!(peer_name("Mom", "Dad's MacBook Pro"), "mom-dad-s-macbook-pro");
        assert_eq!(peer_name("Alex", "studio-4f2a1c"), "alex-studio-4f2a1c");
        assert_eq!(peer_name("Alex", "alex-studio-4f2a1c"), "alex-studio-4f2a1c", "signing in again");
        assert_eq!(peer_name("Alex", ""), "alex-device");
        let long = peer_name("Alex", &"x".repeat(80));
        assert_eq!(long.len(), MAX_PEER_NAME_LEN);
        assert_eq!(selfhost_config::vpn::peer_name_problem(&long), None);
    }

    #[test]
    fn a_forgotten_peer_belongs_to_nobody() {
        let dir = scratch("unbind");
        bind(&dir, "mom-laptop", "mom").unwrap();
        bind(&dir, "mom-phone", "mom").unwrap();
        assert_eq!(peers_of(&dir, "mom"), ["mom-laptop", "mom-phone"]);
        unbind(&dir, "mom-laptop").unwrap();
        assert_eq!(owner_of(&dir, "mom-laptop"), None);
        assert_eq!(peers_of(&dir, "mom"), ["mom-phone"]);
    }

    #[test]
    fn the_shared_role_names_are_never_a_peer() {
        let dir = scratch("shared");
        assert!(bind(&dir, "client", "mom").is_err());
        assert!(bind(&dir, "server", "mom").is_err());
        assert!(!path_in(&dir).exists());
    }

    #[cfg(unix)]
    #[test]
    fn the_record_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("mode");
        bind(&dir, "phone-1", "mom").unwrap();
        let mode = std::fs::metadata(path_in(&dir)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}
