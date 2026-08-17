//! WebDAV, so a share mounts as a drive rather than only opening in a browser.
//!
//! # What is here
//!
//! [`method`] holds the verb table, the `OPTIONS` answer, and the parsing of
//! the two headers the write verbs bring — `Destination` and `Overwrite`.
//! [`propfind`] reads a `PROPFIND` request and decides what each resource
//! answers, [`multistatus`] writes the `207` body, and [`lock`] is `LOCK` and
//! `UNLOCK` and the exclusion they actually perform. `GET` and `HEAD` are
//! [`method::blob`], which is [`crate::respond::blob`] with the disposition
//! pinned to a download.
//!
//! The verbs are executed by [`crate::api`], which is the same engine the
//! browser file manager's JSON API runs on: one set of rules about what a write
//! is allowed to do, reached by two protocols, rather than two implementations
//! that will eventually disagree about what `Overwrite` means.
//!
//! [`method::IMPLEMENTED`] is the one list of verbs this build answers; both
//! the `Allow` and the `DAV` headers are derived from it, and every other verb
//! is a `405` carrying that list. A client is therefore never invited to
//! attempt something that will fail.
//!
//! | Verb | Answer |
//! |---|---|
//! | `OPTIONS` (share root **and** `/`) | 200, `DAV: 1, 2`, `MS-Author-Via: DAV`, `Allow:`, `Accept-Ranges: bytes` |
//! | `PROPFIND` | Depth 0/1 → 207; Depth infinity → 403 `<D:propfind-finite-depth/>` |
//! | `PROPPATCH` | 207, each property answered on its own |
//! | `MKCOL` | 201 / 405 / 409 / 415 |
//! | `GET`, `HEAD` | [`method::blob`] |
//! | `PUT` | 201 new / 204 overwrite; refused on a collection |
//! | `DELETE` | 204, depth-infinity on a collection |
//! | `COPY`, `MOVE` | `Destination` + `Overwrite: T\|F` → 201 / 204 / 412 |
//! | `LOCK`, `UNLOCK` | 200 with `lockdiscovery` + `Lock-Token` / 204 |
//!
//! # Four things that look optional and are not
//!
//! 1. **`DAV: 1, 2` with a working `LOCK`.** The Windows Mini-Redirector and
//!    macOS WebDAVFS both mount the share read-only without level 2, and both
//!    lock before writing — so locking is what makes the mount writable at all.
//!    [`method::dav_header`] derives the claim from [`method::IMPLEMENTED`]
//!    rather than stating it, and [`lock`] explains at length why the lock it
//!    grants is a real one rather than the twenty-line fake that would also
//!    have satisfied both clients, right up until two of them edited one file.
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
//!    a traversal, and `Overwrite: T` compounds it. [`method::destination`] is
//!    where that funnelling happens, and its documentation lists each step as a
//!    refusal somebody has exploited on some other server.
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

pub mod lock;
pub mod method;
pub mod multistatus;
pub mod propfind;
