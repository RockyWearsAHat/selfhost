//! The worker side of a link: dialling out, and keeping the link up.
//!
//! **Not implemented yet.** This module is a documented placeholder for phase 9
//! of the build plan; the pure halves it will drive — [`crate::mux`],
//! [`crate::credit`], [`crate::channel`], [`crate::enroll`] and
//! [`crate::registry`] — are complete and tested, and this is the I/O that will
//! sit on top of them. It is empty rather than sketched because a half-written
//! dialler that compiles is a thing a future reader has to decide whether to
//! trust.
//!
//! # What it will do, and the one decision that shapes all of it
//!
//! **The worker dials the owner. Nothing listens, on either side.**
//!
//! ```text
//! worker daemon ──wss://<owner console host>/api/mesh/link──► owner proxy :443 ──► owner admin
//! ```
//!
//! That direction is not an implementation convenience; it is the security
//! property. The worker binds no socket at all, so there is no worker-side
//! surface to attack, to firewall, or to forget to firewall — `lsof -nP -iTCP
//! -sTCP:LISTEN` on the worker shows nothing new, which is a claim the plan
//! verifies rather than asserts. The owner binds nothing new either: the dial
//! lands on the console site's existing 443, so it passes the *same*
//! `allowed_cidrs` gate as every other console request, which means the mesh works
//! only over the tunnel and no exemption anywhere is widened. NAT becomes
//! irrelevant, which is what makes a worker behind a domestic router work at all.
//!
//! Immediately after the 101 the worker sends, on channel 0, an `OPEN` for the
//! link-control service carrying `{ node, version, proof }`, where the proof comes
//! from [`crate::enroll::Binding::prove`] over that handshake's own
//! `Sec-WebSocket-Key` and `Sec-WebSocket-Accept`.
//!
//! # What it must get right, recorded now so it is not rediscovered
//!
//! - **Backoff** shaped on `crates/console/src/tunnel.rs`'s supervised long-lived
//!   connection: capped, reset only after the link has been healthy for a real
//!   stretch, and cancellable — the same discipline `supervisor::policy` states
//!   for processes, for the same reason.
//! - **Liveness is this layer's job.** Nothing above a WebSocket notices a
//!   half-open tunnel: server ping every 15 s, close on a missing pong after 45 s,
//!   plus the end-to-end `ECHO`/`ECHOED` that proves the whole path rather than
//!   the first hop.
//! - **Failures are counted per node** in [`crate::registry`] and never reach the
//!   console's global login gate. A flapping worker must not be able to lock the
//!   operator out of their own console.
//! - **A token is read from a file, never from `argv`** — `docs/SECURITY.md`
//!   VPN-03 states the rule and it applies here identically.
