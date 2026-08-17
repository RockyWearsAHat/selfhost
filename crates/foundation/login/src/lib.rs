//! Login primitives shared by more than one door in this workspace: password hashing
//! ([`password`]) and session-cookie mechanics ([`session`]).
//!
//! # Why this crate exists
//!
//! `crates/admin/src/passwd.rs` and `crates/reports/src/accounts.rs` each carried an identical,
//! hand-written copy of PBKDF2-HMAC-SHA256 hashing plus its base64 codec — deliberately mirrored
//! rather than shared, because the "whole crate" either would have pulled in was `selfhost-admin`
//! (console, DACL-writing Windows FFI, the peer mesh) or `selfhost-mail` (SMTP, TLS, queues), and
//! neither app should need to link the other's world to verify one password. This crate is what
//! removes that tradeoff: it is only ever password hashing and session cookies, so a door that
//! needs one no longer has to choose between a dependency it doesn't want and a copy it has to
//! keep in sync by hand.
//!
//! # What stays out, on purpose
//!
//! WebAuthn ceremonies and OAuth are **not** here. `crates/admin/src/webauthn.rs` (the owner's
//! console, `SameSite=Strict`) and `crates/reports/src/webauthn.rs` (a public door reached by
//! verification-email links and OAuth redirects, `SameSite=Lax`) encode different, deliberate
//! threat models; merging their ceremony code is a real risk for marginal benefit and is left as
//! a question for a future pass, not answered here.
#![forbid(unsafe_code)]

pub mod password;
pub mod session;
