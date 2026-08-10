//! Basic-over-TLS for WebDAV clients, and the verified-credential cache that
//! makes it usable.
//!
//! **Not built yet** — Phase 3, alongside the WebDAV read verbs. Recorded here
//! because two of its properties are load-bearing rather than optimisations, and
//! discovering them during implementation would mean discovering them as bugs.
//!
//! # Why Basic, and why not Digest
//!
//! WebDAV clients do not do cookie logins: Finder, the Windows Mini-Redirector
//! and every CLI client speak HTTP authentication or nothing. Digest is not
//! available to us — it requires the server to hold a reversible derivation of
//! the password, and the console credential is PBKDF2-SHA256, which is the whole
//! point of it. So Basic, over TLS, on a site that validation already forces to
//! carry a non-empty `allowed_cidrs`.
//!
//! # The cache is mandatory, not an optimisation
//!
//! `ConsolePassword::verify` runs 600,000 PBKDF2 iterations — roughly 70 ms of
//! blocking CPU, deliberately. WebDAV re-authenticates on essentially every
//! request, so a 500-file copy from Finder is 500 verifications: about 35
//! seconds of a core spent proving the same password 500 times, during which the
//! daemon is not serving the console. The cache is keyed by a **salted hash of
//! the presented credential**, never the plaintext; holds a short TTL; lives in
//! memory only; has a non-revealing `Debug` (`admin/src/token.rs:82-86` is the
//! precedent); is cleared when the password is rotated; and does its cold
//! verifies on `spawn_blocking`.
//!
//! # WebDAV 401s must never reach the console's failure gate
//!
//! `admin/src/session.rs:169-182` locks out *all* console logins after five
//! failures in sixty seconds. That gate is deliberately global and it is right
//! for a login form. It is catastrophic here: **every WebDAV client's first
//! request is unauthenticated by protocol design** — the client sends the
//! request, collects the `401` and the realm, and only then authenticates. So
//! mounting a single share would trip the gate and lock the operator out of the
//! console they would use to unmount it.
//!
//! WebDAV therefore gets its own per-credential counter, which must never be
//! able to lock a console login and must never be reachable from a console
//! path. This is the kind of coupling that is invisible until the day somebody
//! mounts a share, so it is written down before the code exists.
