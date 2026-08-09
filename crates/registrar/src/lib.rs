//! The deployment's DNS records, pushed to whatever registrar hosts the zone.
//!
//! `selfhost.config.toml` already describes everything a domain must publish —
//! its sites, its mail — and `dns::Zone::from_config` serves exactly that when
//! this box is the domain's own authority. This crate covers the other posture:
//! the domain's DNS stays with a registrar (Namecheap, Cloudflare, GoDaddy,
//! Porkbun), and the records the config implies are pushed *to* it over the
//! registrar's API. One derivation ([`plan::desired_records`]), one pure
//! reconcile engine ([`plan::plan`]), and one thin [`DnsProvider`] per
//! registrar, so the served zone, the printed instructions, and the pushed
//! records can never disagree about what a deployment publishes.
//!
//! # The first law: never touch what the config does not claim
//!
//! A registrar account holds records this deployment knows nothing about — the
//! operator's own TXT verifications, a CNAME to a service hosted elsewhere. A
//! record whose `(host, type)` pair is not claimed by the desired set is
//! **never deleted or modified**: it lands in [`plan::Plan::untouched`] and
//! survives verbatim, even through registrars whose API replaces the whole
//! record set at once. Every provider upholds this by receiving
//! [`plan::Plan::final_set`] — the untouched records plus the desired ones —
//! never a bare desired set.
//!
//! # Layout
//!
//! - [`plan`] — the domain model glue and the pure engine: derivation, diffing,
//!   rendering. Fully unit-tested, no I/O.
//! - [`namecheap`], [`cloudflare`], [`godaddy`], [`porkbun`] — one provider
//!   each, implementing [`DnsProvider`] over an injected [`Transport`] so its
//!   protocol logic is tested against canned responses, never the network.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod cloudflare;
pub mod godaddy;
pub mod namecheap;
pub mod plan;
pub mod porkbun;

use std::fmt;
use std::future::Future;

/// One DNS record, in the registrar-neutral shape the whole crate speaks.
///
/// `host` is always *relative* to the domain being reconciled: `"@"` is the
/// apex, `"*"` a wildcard, `"www"` the `www` label, `"_imaps._tcp"` a service
/// name. Providers translate to and from their own conventions (absolute
/// names, empty-string apexes) at their edge, so the engine compares one
/// spelling only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Relative owner name: `"@"` apex, `"*"` wildcard, otherwise a label path.
    pub host: String,
    /// The record type, carrying any type-specific fields (MX preference,
    /// SRV priority/weight/port) so a record is one value, not a row plus
    /// side-channel columns.
    pub rtype: RecordType,
    /// The record data: an address for `A`/`AAAA`, a target name for
    /// `CNAME`/`MX`/`SRV`, the text for `TXT`, the full tag-and-value for `CAA`.
    pub value: String,
    /// Time-to-live in seconds. `None` means "no opinion": the provider's
    /// default on create, and any observed TTL matches it when diffing.
    pub ttl: Option<u32>,
}

impl fmt::Display for Record {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{} {} -> {}", self.rtype, self.host, self.value)?;
        match &self.rtype {
            RecordType::Mx { preference } => write!(out, " (pref {preference})")?,
            RecordType::Srv { priority, weight, port } => {
                write!(out, " (prio {priority} weight {weight} port {port})")?;
            }
            _ => {}
        }
        if let Some(ttl) = self.ttl {
            write!(out, " [ttl {ttl}]")?;
        }
        Ok(())
    }
}

/// The record types the engine understands, plus an escape hatch.
///
/// Type-specific integers live *inside* the variant so an MX or SRV record is
/// self-contained. `Other` carries any type the engine has no schema for —
/// such records are still matched, kept, and passed through by their type
/// name, so an unrecognised observed record is preserved rather than dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordType {
    /// An IPv4 address record.
    A,
    /// An IPv6 address record.
    Aaaa,
    /// An alias to another name.
    Cname,
    /// A mail exchanger; lower preference is tried first.
    Mx {
        /// Relative ordering among the domain's MX records.
        preference: u16,
    },
    /// Free-form text: SPF, DMARC, DKIM, verifications.
    Txt,
    /// A service locator (RFC 2782); `value` is the target host.
    Srv {
        /// Lower priority targets are tried first.
        priority: u16,
        /// Weight among targets of equal priority.
        weight: u16,
        /// Port the service listens on at the target.
        port: u16,
    },
    /// Certification Authority Authorization.
    Caa,
    /// Any type this crate has no schema for, by its wire name (e.g. `"NS"`).
    Other(String),
}

impl RecordType {
    /// The type's wire name, uppercased — the identity used for claim matching.
    ///
    /// Variant fields (MX preference, SRV numbers) are deliberately *not* part
    /// of the kind: a desired MX claims the observed MX at the same host even
    /// when the preference changed, so the change becomes an update rather
    /// than a create beside a stale survivor.
    pub fn kind(&self) -> String {
        match self {
            Self::A => "A".into(),
            Self::Aaaa => "AAAA".into(),
            Self::Cname => "CNAME".into(),
            Self::Mx { .. } => "MX".into(),
            Self::Txt => "TXT".into(),
            Self::Srv { .. } => "SRV".into(),
            Self::Caa => "CAA".into(),
            Self::Other(name) => name.to_ascii_uppercase(),
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(out, "{}", self.kind())
    }
}

/// Why a registrar operation failed, worded for the operator who must fix it.
///
/// Every variant carries the upstream detail verbatim — a truncated API error
/// is an error the operator debugs blind. `Display` renders one line suitable
/// for the CLI.
#[derive(Debug)]
pub enum ProviderError {
    /// The API could not be reached at all: DNS, TCP, or TLS failure.
    Transport(String),
    /// The API answered with a failure. `detail` is the response's own words
    /// (its error body or status line), never a paraphrase.
    Api {
        /// The HTTP status the API answered with.
        status: u16,
        /// The API's own description of what went wrong.
        detail: String,
    },
    /// The API answered success but the response did not parse as documented.
    Protocol(String),
}

impl fmt::Display for ProviderError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(detail) => write!(out, "could not reach the registrar API: {detail}"),
            Self::Api { status, detail } => {
                write!(out, "the registrar API refused (HTTP {status}): {detail}")
            }
            Self::Protocol(detail) => {
                write!(out, "the registrar API answered something unexpected: {detail}")
            }
        }
    }
}

impl std::error::Error for ProviderError {}

/// A registrar's DNS API, reduced to the two operations reconciliation needs.
///
/// # The `apply` contract
///
/// `apply` receives the **full final record set** for the domain — always
/// [`plan::Plan::final_set`], never a bare desired set — and makes the zone
/// equal to it. Both registrar styles implement that one meaning:
///
/// - a *replace-everything* API (Namecheap's `setHosts`) pushes the set
///   verbatim in one call;
/// - a *per-record CRUD* API (Cloudflare, GoDaddy, Porkbun) diffs the set
///   against its own fresh listing and issues only the creates, updates, and
///   deletes that close the gap.
///
/// The first law holds because the caller built the set from a [`plan::Plan`]:
/// unclaimed records are already inside it, so a correct `apply` — either
/// style — carries them through unchanged.
///
/// Methods return `impl Future + Send` (desugared `async fn`) so callers may
/// spawn them on a multi-threaded runtime; implement them with plain
/// `async fn`.
pub trait DnsProvider {
    /// Every record the registrar currently serves for `domain`, in the
    /// crate's relative-host shape. This is the "observed" input to
    /// [`plan::plan`].
    fn list(
        &self,
        domain: &str,
    ) -> impl Future<Output = Result<Vec<Record>, ProviderError>> + Send;

    /// Makes `domain`'s zone equal to `records` — see the trait docs for the
    /// full-set contract.
    fn apply(
        &self,
        domain: &str,
        records: &[Record],
    ) -> impl Future<Output = Result<(), ProviderError>> + Send;
}

/// One HTTPS exchange with a registrar API, described without performing it.
///
/// Providers build these; a [`Transport`] sends them. Keeping the description
/// inert is what lets a provider's whole protocol be unit-tested against
/// canned [`ApiResponse`]s with no socket in sight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiRequest {
    /// The HTTP method, uppercase: `"GET"`, `"POST"`, `"PUT"`, `"DELETE"`.
    pub method: String,
    /// The full `https://` URL, query string included.
    pub url: String,
    /// Extra headers beyond what the transport itself supplies (Host,
    /// Content-Length): API keys, `Content-Type`, and the like.
    pub headers: Vec<(String, String)>,
    /// The request body; empty for bodiless methods.
    pub body: Vec<u8>,
}

/// What the registrar API answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The response body, unparsed — the provider owns interpretation.
    pub body: Vec<u8>,
}

impl ApiResponse {
    /// The body as text, lossily — registrar APIs speak ASCII JSON/XML, and a
    /// stray byte should corrupt one character of an error message, not turn
    /// the whole response into a second error.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// `text` percent-encoded per RFC 3986's unreserved set — strict enough for a
/// query value, a form field, or a path segment, so every provider that needs
/// general-purpose escaping builds URLs through this one encoder instead of
/// growing a private copy that can drift. (GoDaddy's path segments deliberately
/// widen the set — see `godaddy::encode_segment` for why.)
pub(crate) fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// A provider's fully-qualified record name folded to the crate's relative
/// spelling: the domain itself becomes `"@"`, a name under it loses the
/// suffix, and a name outside the domain stays verbatim — such a record can
/// only ever be unclaimed, so leaving it recognisable keeps it safely
/// untouched. ASCII-case-insensitive, tolerating a trailing dot, and safe for
/// non-ASCII names (a split that would land mid-character simply fails to
/// match, it never panics).
pub(crate) fn relative_host(name: &str, domain: &str) -> String {
    let name = name.trim_end_matches('.');
    if name.eq_ignore_ascii_case(domain) {
        return "@".to_owned();
    }
    if let Some(host_len) = name.len().checked_sub(domain.len() + 1) {
        if host_len > 0 && name.is_char_boundary(host_len) {
            let (host, suffix) = name.split_at(host_len);
            if suffix.starts_with('.') && suffix[1..].eq_ignore_ascii_case(domain) {
                return host.to_owned();
            }
        }
    }
    name.to_owned()
}

/// The seam between provider logic and the network.
///
/// The real implementation (an HTTPS client in the style of
/// `selfhost-acme`'s transport, extended with per-request headers) is injected
/// by the binary; tests inject a double that returns canned [`ApiResponse`]s
/// and records what was asked. A transport reports only *transport* failures —
/// an HTTP error status is a successful exchange the provider interprets.
pub trait Transport {
    /// Performs one exchange. Errors are [`ProviderError::Transport`] only.
    fn send(
        &self,
        request: ApiRequest,
    ) -> impl Future<Output = Result<ApiResponse, ProviderError>> + Send;
}

#[cfg(test)]
pub(crate) mod testing {
    //! Shared provider-test scaffolding: one canned transport double and one
    //! bounded canned-future executor, so the four provider suites exercise
    //! their protocols through identical machinery instead of divergent
    //! copies that can rot apart.

    use std::collections::VecDeque;
    use std::future::Future;
    use std::pin::pin;
    use std::sync::Mutex;
    use std::task::{Context, Poll, Waker};

    use crate::{ApiRequest, ApiResponse, ProviderError, Transport};

    /// Drives a future built purely from canned exchanges to completion.
    /// Bounded: a future still pending after 64 polls means a test double is
    /// broken (or a real yield point crept in), and the test must say so
    /// loudly rather than busy-loop the suite forever.
    pub fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
        panic!("a canned exchange must resolve without real waiting");
    }

    /// The transport double: hands out scripted replies in order and records
    /// every request verbatim, so tests assert the exact protocol spoken.
    pub struct Canned {
        replies: Mutex<VecDeque<ApiResponse>>,
        seen: Mutex<Vec<ApiRequest>>,
    }

    impl Canned {
        /// A double that answers with `replies`, in order; running past the
        /// script is a [`ProviderError::Transport`] naming the test's fault.
        pub fn scripted(replies: impl IntoIterator<Item = ApiResponse>) -> Self {
            Self {
                replies: Mutex::new(replies.into_iter().collect()),
                seen: Mutex::new(Vec::new()),
            }
        }

        /// Replaces the remaining script — for tests that reuse one double
        /// across separate provider calls (a `list`, then an `apply`).
        pub fn rescript(&self, replies: impl IntoIterator<Item = ApiResponse>) {
            *self.replies.lock().unwrap() = replies.into_iter().collect();
        }

        /// Every request sent so far, verbatim, in order.
        pub fn requests(&self) -> Vec<ApiRequest> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Transport for Canned {
        async fn send(&self, request: ApiRequest) -> Result<ApiResponse, ProviderError> {
            self.seen.lock().unwrap().push(request);
            self.replies
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| ProviderError::Transport("the test scripted no more replies".into()))
        }
    }

    impl Transport for &Canned {
        async fn send(&self, request: ApiRequest) -> Result<ApiResponse, ProviderError> {
            Transport::send(*self, request).await
        }
    }

    /// A 200 response carrying `body`.
    pub fn ok(body: &str) -> ApiResponse {
        response(200, body)
    }

    /// A `status` response carrying `body`.
    pub fn response(status: u16, body: &str) -> ApiResponse {
        ApiResponse { status, body: body.as_bytes().to_vec() }
    }
}
