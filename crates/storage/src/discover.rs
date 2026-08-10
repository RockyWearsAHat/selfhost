//! Telling the network a share exists, without becoming a responder.
//!
//! **Not built yet** — Phase 10. The pure half derives the DNS-SD record set for
//! a browsable share (`_smb._tcp` and `_webdav._tcp` PTR / SRV / TXT plus the
//! address records), mirroring `Mail::dns_records` so that the service that is
//! advertised and the path that is served cannot disagree — a mismatch there is
//! a mount that resolves and then fails, which is far harder to diagnose than no
//! advertisement at all.
//!
//! # Publication is delegated, and we bind nothing
//!
//! This is the part that has to be said out loud, because writing an mDNS
//! responder is the obvious implementation and it is wrong:
//!
//! `mDNSResponder` (macOS) and Avahi (Linux) already own `224.0.0.251:5353`.
//! `std` sets `SO_REUSEADDR` but not `SO_REUSEPORT` on Darwin, so the bind
//! simply fails; and where it can be forced, the result is a *second* responder
//! that Bonjour treats as a conflicting peer and renames around — the operator's
//! share appears as "Vault (2)" and the original stops resolving. A second
//! responder on the LAN is also a new listening socket on a box whose entire
//! security posture is "one intended public surface", which `docs/SECURITY.md`
//! would have to be amended to permit.
//!
//! So publication is delegated: `DNSServiceRegister` from libSystem on macOS (an
//! FFI declaration, no crate) — or simply `sharing -a`, which publishes
//! `_smb._tcp` for us; an Avahi service file on Linux; and `New-SmbShare` on
//! Windows, which lets the OS advertise the machine.
//!
//! The cost is that discovery behaves differently per platform and is simply
//! absent on some. That is an honest gap rather than a subtle one, and it is
//! preferable to a subtle one. Windows Explorer's *Network* node in particular
//! is populated by WSD, a SOAP-over-UDP device stack that is weeks of work for
//! one icon; we get it from `New-SmbShare` or we do not get it.
