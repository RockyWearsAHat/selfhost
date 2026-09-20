//! Which Person each Peer belongs to.
//!
//! A Peer is one device's roster entry on a relay. It is named by the device
//! and bound here to the Person who signed it in, so that a roster name is
//! never shared between two people: the name "laptop-4f2a" means one Person's
//! laptop for as long as it exists.
//!
//! The record is `<data_dir>/vpn.peers`, owner-only, one `peer person` pair a
//! line. It holds no secret; it is private because who owns which device is
//! nobody else's business.

use selfhost_config::vpn::RESERVED_PEER_NAMES;
use selfhost_identity::registry::write_owner_only;
use std::path::{Path, PathBuf};

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
    write_owner_only(&path, &text).map_err(|error| format!("cannot write {}: {error}", path.display()))
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
    write_owner_only(&path, &kept).map_err(|error| format!("cannot write {}: {error}", path.display()))
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
