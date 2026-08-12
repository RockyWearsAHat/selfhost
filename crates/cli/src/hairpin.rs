//! Reaching this machine's own public address from inside its own network.
//!
//! The router does destination NAT: a packet arriving from the internet for
//! `<public>:443` is rewritten to `<lan>:443`. It only does that for packets
//! arriving on the *outside* interface. A packet sent from the LAN to the public
//! address reaches the router on the inside and is dropped, because this router
//! does not hairpin. So from in here, the box's own public address is a black
//! hole — and every check aimed at it either has to be re-pointed at the LAN
//! address, which tests something else, or cannot be run at all.
//!
//! # What this does instead
//!
//! Two changes, on two different machines, that between them make the public
//! address behave normally on the LAN:
//!
//! 1. **On the box** — add the public address to the loopback interface as a
//!    `/32`. The box then *holds* that address, so packets addressed to it and
//!    delivered here are accepted, and the listeners already bound to `0.0.0.0`
//!    answer on it.
//! 2. **On each client** — a host route sending that one `/32` to the box's LAN
//!    address, so those packets are delivered here rather than to the router
//!    that would drop them.
//!
//! # What it tests, and the one thing it does not
//!
//! A client with this in place resolves the name through *public* DNS, connects
//! to the *public* address, sends the real SNI and gets the real certificate.
//! That is the whole client-visible path, and it is what makes it possible to
//! set up Apple Mail against `imap.<domain>` and have it exercise the same
//! address a stranger would.
//!
//! It does **not** test the router's port forward, because it deliberately
//! bypasses the router. That half is what [`crate::outside`] proves, using a
//! third party as the witness. The two are complements and neither replaces the
//! other: this one makes the box testable from here, that one proves the edge
//! is open.
//!
//! # Why the plan is printed and applied separately
//!
//! Both changes need administrator rights and both alter the routing table,
//! which is the fastest way to make a machine unreachable. So this follows the
//! same shape as [`crate::service_install`] and `teardown`: compute the exact
//! commands, show them, and run them only when asked.

use std::net::Ipv4Addr;

/// One command a hairpin plan runs, with the reason it is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Action {
    /// The program and its arguments, program first.
    pub argv: Vec<String>,
    /// What this achieves, in one line, for the printed plan.
    pub because: String,
}

/// Which side of the arrangement a plan is for.
///
/// The two halves are separate because they run on different machines: nobody
/// can apply both from one place, and a plan that pretended otherwise would
/// half-work and look applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    /// The machine holding the LAN address — it takes the loopback alias.
    Box,
    /// Any other machine on the LAN — it takes the host route.
    Client,
}

/// The commands that put the hairpin in place on this platform.
///
/// `public` is the address the world reaches this deployment on; `lan` is the
/// address it actually holds on the local network. Returns an error on a
/// platform whose routing commands are not known here, rather than guessing at
/// syntax that would half-apply.
pub fn plan(side: Side, public: Ipv4Addr, lan: Ipv4Addr) -> Result<Vec<Action>, String> {
    match side {
        Side::Box => box_plan(public),
        Side::Client => client_plan(public, lan),
    }
}

/// Adding the public address to the box's own loopback, as a `/32`.
///
/// A `/32` and loopback specifically: any wider mask would claim addresses that
/// are not ours, and any real interface would make the box answer ARP for the
/// public address on the LAN — announcing itself as the router. Loopback is
/// accepted locally and advertised nowhere.
fn box_plan(public: Ipv4Addr) -> Result<Vec<Action>, String> {
    let because = format!(
        "the box then holds {public} itself, so packets addressed to it are accepted here \
         and the existing listeners answer on it"
    );
    if cfg!(target_os = "macos") {
        Ok(vec![Action {
            argv: vec!["ifconfig".into(), "lo0".into(), "alias".into(), public.to_string(), "255.255.255.255".into()],
            because,
        }])
    } else if cfg!(target_os = "linux") {
        Ok(vec![Action {
            argv: vec![
                "ip".into(),
                "addr".into(),
                "add".into(),
                format!("{public}/32"),
                "dev".into(),
                "lo".into(),
            ],
            because,
        }])
    } else if cfg!(windows) {
        // The Windows loopback pseudo-interface is not present by default, so
        // the alias goes on the interface that already carries the LAN address.
        // That is safe here for the reason the /32 is: `skipassource` keeps
        // Windows from ever choosing it as the source address for outbound
        // connections, which would otherwise make this machine appear to come
        // from its public address on the LAN.
        Ok(vec![Action {
            argv: vec![
                "netsh".into(),
                "interface".into(),
                "ipv4".into(),
                "add".into(),
                "address".into(),
                "Ethernet".into(),
                public.to_string(),
                "255.255.255.255".into(),
                "skipassource=true".into(),
            ],
            because,
        }])
    } else {
        Err(unsupported())
    }
}

/// The host route a LAN client needs so the `/32` is delivered to the box.
fn client_plan(public: Ipv4Addr, lan: Ipv4Addr) -> Result<Vec<Action>, String> {
    let because = format!(
        "packets for {public} then go straight to {lan} instead of to the router, which \
         would drop them"
    );
    if cfg!(target_os = "macos") {
        Ok(vec![Action {
            argv: vec!["route".into(), "-n".into(), "add".into(), "-host".into(), public.to_string(), lan.to_string()],
            because,
        }])
    } else if cfg!(target_os = "linux") {
        Ok(vec![Action {
            argv: vec![
                "ip".into(),
                "route".into(),
                "add".into(),
                format!("{public}/32"),
                "via".into(),
                lan.to_string(),
            ],
            because,
        }])
    } else if cfg!(windows) {
        Ok(vec![Action {
            argv: vec![
                "route".into(),
                "-p".into(),
                "add".into(),
                public.to_string(),
                "mask".into(),
                "255.255.255.255".into(),
                lan.to_string(),
            ],
            because,
        }])
    } else {
        Err(unsupported())
    }
}

/// The commands that undo [`plan`].
///
/// Every route change needs a way back, and it must be computable without the
/// plan that made it: an operator undoing this at 2am has a broken machine, not
/// a saved plan.
pub fn undo_plan(side: Side, public: Ipv4Addr, lan: Ipv4Addr) -> Result<Vec<Action>, String> {
    let actions = plan(side, public, lan)?;
    Ok(actions
        .into_iter()
        .map(|action| {
            let argv = action
                .argv
                .into_iter()
                .map(|word| match word.as_str() {
                    // Each platform's own word for the inverse. `alias` and
                    // `add` are the only verbs the plans above use.
                    "alias" => "-alias".to_owned(),
                    "add" => "delete".to_owned(),
                    other => other.to_owned(),
                })
                .collect();
            Action { argv, because: "removes the hairpin entry".to_owned() }
        })
        .collect())
}

/// The message for a platform whose routing commands are not known here.
fn unsupported() -> String {
    "hairpin is only implemented for macOS, Linux and Windows; on anything else, add the \
     public address to loopback as a /32 and a host route to the box by hand"
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public() -> Ipv4Addr {
        Ipv4Addr::new(172, 83, 6, 109)
    }

    fn lan() -> Ipv4Addr {
        Ipv4Addr::new(192, 168, 1, 8)
    }

    #[test]
    fn the_box_claims_the_public_address_as_a_single_host() {
        let actions = plan(Side::Box, public(), lan()).expect("a supported platform");
        let line = actions[0].argv.join(" ");
        assert!(line.contains("172.83.6.109"), "{line}");
        // A wider mask would claim addresses that are not ours. This is the
        // assertion that would catch a /24 slipping in.
        assert!(
            line.contains("255.255.255.255") || line.contains("/32"),
            "the alias must be a single host: {line}"
        );
    }

    #[test]
    fn a_client_route_points_at_the_box_rather_than_the_router() {
        let actions = plan(Side::Client, public(), lan()).expect("a supported platform");
        let line = actions[0].argv.join(" ");
        assert!(line.contains("172.83.6.109"), "{line}");
        // The whole point: the next hop is the box, because the router is what
        // drops these packets.
        assert!(line.contains("192.168.1.8"), "the next hop must be the box: {line}");
    }

    #[test]
    fn every_action_explains_why_it_is_there() {
        // These commands edit the routing table, which is how a machine is made
        // unreachable. An operator must be able to read the plan and know what
        // each line buys before approving it.
        for side in [Side::Box, Side::Client] {
            for action in plan(side, public(), lan()).expect("a supported platform") {
                assert!(!action.because.trim().is_empty(), "{action:?}");
                assert!(!action.argv.is_empty(), "{action:?}");
            }
        }
    }

    #[test]
    fn undoing_inverts_every_verb_and_keeps_the_addresses() {
        for side in [Side::Box, Side::Client] {
            let forward = plan(side, public(), lan()).expect("a supported platform");
            let back = undo_plan(side, public(), lan()).expect("a supported platform");
            assert_eq!(forward.len(), back.len(), "undo must cover every step");

            for (did, undo) in forward.iter().zip(&back) {
                let undone = undo.argv.join(" ");
                assert!(undone.contains("172.83.6.109"), "the address survives: {undone}");
                // The inverse must not still say "add", or "undo" would
                // reapply the very thing it claims to remove.
                assert!(
                    !undo.argv.iter().any(|word| word == "add" || word == "alias"),
                    "still an apply: {did:?} → {undone}"
                );
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn the_windows_alias_never_becomes_an_outbound_source_address() {
        // Without skipassource, Windows may pick the public address as the
        // source for outbound connections, and this machine would then appear
        // on the LAN as if it were the router.
        let actions = plan(Side::Box, public(), lan()).expect("windows is supported");
        assert!(
            actions[0].argv.iter().any(|word| word == "skipassource=true"),
            "{:?}",
            actions[0].argv
        );
    }
}
