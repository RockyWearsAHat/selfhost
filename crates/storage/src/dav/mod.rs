//! WebDAV, so a share mounts as a drive rather than only opening in a browser.
//!
//! # What is here, and what is not
//!
//! The **read half** is built: [`method`] holds the verb table and the
//! `OPTIONS` answer, [`propfind`] reads a `PROPFIND` request and decides what
//! each resource answers, and [`multistatus`] writes the `207` body. `GET` and
//! `HEAD` are [`method::blob`], which is [`crate::respond::blob`] with the
//! disposition pinned to a download.
//!
//! The **write half** — `PROPPATCH`, `MKCOL`, `PUT`, `DELETE`, `COPY`, `MOVE`,
//! `LOCK` and `UNLOCK` — is Phase 5 and is deliberately absent rather than
//! stubbed. It is not absent silently: [`method::IMPLEMENTED`] is the one list
//! of verbs this build answers, both the `Allow` and the `DAV` headers are
//! derived from it, and every other verb is a `405` carrying that list. A
//! client is therefore never invited to attempt something that will fail.
//!
//! There is no `lock` module yet for the same reason there is no empty
//! `write.rs`: an empty module is scaffolding that reads as progress.
//!
//! | Verb | Answer today | Answer after Phase 5 |
//! |---|---|---|
//! | `OPTIONS` (share root **and** `/`) | 200, `DAV: 1`, `MS-Author-Via: DAV`, `Allow:`, `Accept-Ranges: bytes` | `DAV: 1, 2` |
//! | `PROPFIND` | Depth 0/1 → 207; Depth infinity → 403 `<D:propfind-finite-depth/>` | unchanged |
//! | `GET`, `HEAD` | [`method::blob`] | unchanged |
//! | `PROPPATCH` | 405 | 207 per property; dead properties may be 403 |
//! | `MKCOL` | 405 | 201 / 405 / 409 |
//! | `PUT` | 405 | 201 new / 204 overwrite; refused on a collection |
//! | `DELETE` | 405 | 204 |
//! | `COPY`, `MOVE` | 405 | `Destination` + `Overwrite: T\|F` → 201 / 204 / 412 |
//! | `LOCK`, `UNLOCK` | 405 | 200 with lockdiscovery + `Lock-Token` / 204 |
//!
//! # Four things that look optional and are not
//!
//! 1. **`DAV: 1, 2` with a working `LOCK`.** The Windows Mini-Redirector locks
//!    before every `PUT` and mounts the share read-only if level 2 is missing.
//!    Which is why [`method::dav_header`] derives the claim from
//!    [`method::IMPLEMENTED`] rather than stating it: a `2` that arrives before
//!    `LOCK` does is a mount that fails on its first write.
//! 2. **RFC 4331 `quota-available-bytes` / `quota-used-bytes`.** Without them
//!    Finder reports zero free space and refuses every copy. The numbers come
//!    from [`crate::quota::available`] and [`crate::quota::used`] by way of
//!    [`propfind::Quota::measure`], so the property and the enforcement cannot
//!    disagree.
//! 3. **Every `href` is percent-encoded, with no exceptions.** A `multistatus`
//!    body is a list of URLs built out of names that callers chose, and `%` is a
//!    legal character in a name: a directory holding `a%2fb` produces an `href`
//!    that Finder resolves to `a/b`, one level down, so the client copies,
//!    overwrites or deletes a different file than the one it was shown. This is
//!    enforced by [`multistatus::Href`], which has no constructor from a
//!    `String` — the only way to make one is [`multistatus::Mount::href`], which
//!    encodes every segment. XML escaping is a *second*, separate step on top;
//!    [`multistatus::escape`] is that one, and neither substitutes for the
//!    other.
//! 4. **`Destination:` is a second attacker-controlled path.** It gets the
//!    identical treatment as the request line — the same [`crate::path`]
//!    resolver, confined to a root, checked against the *target* share's
//!    read-only flag and the caller's grants for the target share, with a
//!    cross-share move refused unless both are permitted. A `MOVE` whose
//!    destination escapes the root is a write-anywhere primitive as complete as
//!    a traversal, and `Overwrite: T` compounds it. Nothing here reads that
//!    header yet, because nothing here answers a verb that carries one; the rule
//!    is recorded where the first `COPY` handler will be written.
//!
//! # The request body is attacker-controlled XML
//!
//! [`propfind::parse`] is the only parser in this crate fed by a stranger, and
//! its two hazards — entity expansion and unbounded nesting — cost the whole
//! process rather than one request under `panic = "abort"`. What it does about
//! them is stated in that module, and it is the reason a general-purpose XML
//! parser is not used here.
//!
//! Authentication is [`crate::auth`]'s, and its two constraints — a mandatory
//! verified-credential cache, and a failure counter that can never reach the
//! console's login gate — are stated there.

pub mod method;
pub mod multistatus;
pub mod propfind;
