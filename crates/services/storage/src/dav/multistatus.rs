//! The `207 Multi-Status` body, written by hand.
//!
//! Pure: everything here is a value in and a `String` out, so the awkward parts
//! — a filename holding `&`, one holding `%`, one holding a quote — are tested
//! without a socket or a disk.
//!
//! # Why the XML is written rather than generated
//!
//! A WebDAV body is a fixed shape with a handful of elements in it. A generic
//! serialiser would be a second parser to keep correct, in a process where a
//! parser that panics is a whole-box outage, and it would still need every
//! escaping rule below stated explicitly. What is here is a printer with no
//! branches an attacker can reach: the element names are compile-time constants,
//! and the only attacker-controlled text is the two places [`escape`] and
//! [`Mount::href`] guard.
//!
//! # The two escapings are different, and both are mandatory
//!
//! This is the single most dangerous confusion in the file, so it is named
//! before anything else. A stored filename reaches the body twice, and it needs
//! a **different** treatment each time:
//!
//! 1. **In an `href` it is percent-encoded.** `%` is a legal character in a
//!    filename, so a directory can hold `a%2fb` — a name whose own text, put in
//!    a URL, asks for `a/b` one directory down. A client shown that `href`
//!    copies, overwrites or deletes a different file than the one it was shown.
//!    [`crate::path::encode_segment`] is the encoder and it is not optional; the
//!    round-trip invariant it keeps is stated in [`crate::path`].
//! 2. **Everywhere else it is XML-escaped.** `displayname` carries the name as a
//!    person reads it, so a file called `Q&A <draft>.txt` would otherwise close
//!    the element and make the body unparseable — or, with a little more care
//!    from whoever named the file, would inject elements of the attacker's
//!    choosing into a document the client trusts.
//!
//! Neither substitutes for the other. Percent-encoding is not XML-escaping: it
//! leaves `<` alone if `<` is in the unreserved set, and the only reason the two
//! do not collide here is that our encoder is deliberately broad enough that
//! `&` and `<` cannot survive it. XML-escaping is not percent-encoding: it turns
//! `&` into `&amp;`, which a URL parser reads as `&amp;`, not as `&`.
//!
//! The types are shaped so neither can be forgotten. An [`Href`] cannot be built
//! from a `String`; it comes from [`Mount::href`], which takes a
//! [`crate::path::RelativePath`] — a value whose segments are already validated
//! — and encodes every one of them. A [`Property`] carrying free text renders
//! through [`escape`] and there is no variant that renders raw.

use crate::listing::Kind;
use crate::path::{self, RelativePath};
use crate::share::ShareId;
use selfhost_http::{date, HeaderError, Response, Status};
use std::fmt;
use std::time::SystemTime;

/// The status a `207` carries.
///
/// Spelled here because `selfhost_http::Status` has no constant for it: its
/// table covers the codes the proxy and the console use, and `207` belongs to
/// WebDAV alone. The wire consequence is that the reason phrase reads `Unknown`
/// rather than `Multi-Status`; no client parses it — RFC 9110 §15 makes the
/// phrase advisory and every WebDAV implementation switches on the number — but
/// the honest fix is a `Status::MULTI_STATUS` in `crates/http`, which is
/// recorded as owed rather than worked around a second time.
pub const MULTI_STATUS: Status = Status(207);

/// The media type of every body in this module.
///
/// `application/xml` rather than `text/xml`: the latter defaults to US-ASCII
/// when the charset parameter is dropped by an intermediary, which would mangle
/// exactly the non-ASCII filenames this project takes care to keep intact.
pub const XML_TYPE: &str = "application/xml; charset=\"utf-8\"";

/// The namespace every live property in this module belongs to.
pub const DAV_NAMESPACE: &str = "DAV:";

/// The URL prefix WebDAV is mounted at, above the share segment.
pub const DAV_ROOT: &str = "/dav";

/// The content type reported for a directory.
///
/// A convention rather than a standard, and the one Finder, Windows Explorer and
/// every Linux client already recognise. It is not `application/octet-stream`,
/// because a collection is not a stream of bytes and a client that tried to
/// download one would get an error instead of a listing.
pub const COLLECTION_TYPE: &str = "httpd/unix-directory";

/// Where one share is mounted in the URL space, and the only place an `href` is
/// built.
///
/// The share id is percent-encoded on its way in even though
/// [`ShareId::parse`] already restricts it to `[a-z0-9-]`, so that this type is
/// not the one exception to "every path segment in an `href` goes through the
/// encoder" — a rule with an exception is a rule somebody will copy without the
/// exception.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// `/dav/<id>`, with no trailing slash.
    prefix: String,
    /// The share's own name, which is the `displayname` of its root.
    name: String,
}

impl Mount {
    /// The mount for one share: `/dav/<id>`.
    pub fn for_share(share: &ShareId) -> Self {
        Self {
            prefix: format!("{DAV_ROOT}/{}", path::encode_segment(share.as_str())),
            name: share.as_str().to_string(),
        }
    }

    /// The URL prefix, with no trailing slash.
    pub fn prefix(&self) -> &str {
        &self.prefix
    }

    /// The share's name, used as the `displayname` of its root.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `href` for one resource inside this share.
    ///
    /// A collection's `href` ends in a slash and a file's does not. That is not
    /// cosmetic: RFC 4918 §8.3 makes the trailing slash how a client tells the
    /// two apart when it caches the response, and Finder builds the URL of a
    /// child by appending to the parent's `href` — so a collection served
    /// without the slash produces children one directory too high.
    pub fn href(&self, path: &RelativePath, kind: Kind) -> Href {
        let mut url = self.prefix.clone();
        let encoded = path.to_url_path();
        if !encoded.is_empty() {
            url.push('/');
            url.push_str(&encoded);
        }
        if kind == Kind::Directory {
            url.push('/');
        }
        Href(url)
    }
}

/// A URL that is safe to put in an `href`, because it was built by encoding
/// every segment.
///
/// There is deliberately no way to make one from a `String`. The rule that
/// stored names must be percent-encoded before they become links cannot be
/// enforced by writing it down — this project has already had it forgotten once
/// — so it is enforced by there being no other constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Href(String);

impl Href {
    /// The URL as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Href {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of a property, namespace and all.
///
/// Both halves are kept because a WebDAV client may ask for a property in any
/// namespace, and a `404` for one must echo it back *in its own namespace* —
/// answering `<D:coolness/>` to a request for `<x:coolness xmlns:x="urn:x"/>`
/// is answering about a different property.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyName {
    namespace: String,
    local: String,
}

impl PropertyName {
    /// A property in an arbitrary namespace.
    ///
    /// The local name is checked here rather than at render time, because the
    /// renderer writes it as an element name: a "name" holding `>` would end the
    /// element early and let a client's own request dictate the shape of our
    /// answer. The permitted set is deliberately narrower than XML's `NCName`
    /// — ASCII letters, digits, `-`, `_` and `.`, starting with a letter or `_`
    /// — because every property any real client asks for is inside it, and a
    /// narrow rule needs no Unicode tables to be sure of.
    pub fn new(namespace: &str, local: &str) -> Option<Self> {
        let mut characters = local.chars();
        let first_is_legal =
            matches!(characters.next(), Some(c) if c.is_ascii_alphabetic() || c == '_');
        let rest_are_legal = characters
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.');
        if !first_is_legal || !rest_are_legal {
            return None;
        }
        Some(Self { namespace: namespace.to_string(), local: local.to_string() })
    }

    /// A property in the `DAV:` namespace, which is where every live property
    /// this server answers lives.
    pub fn dav(local: &str) -> Option<Self> {
        Self::new(DAV_NAMESPACE, local)
    }

    /// The namespace URI, empty when the request declared none.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// The local name.
    pub fn local(&self) -> &str {
        &self.local
    }

    /// Whether this names a property in the `DAV:` namespace.
    pub fn is_dav(&self) -> bool {
        self.namespace == DAV_NAMESPACE
    }

    /// Writes this name as an empty element, carrying its own namespace.
    ///
    /// Used only for the `404` half of a response, where the point is to hand
    /// back exactly what was asked for. A name with no namespace is written
    /// bare; one with a namespace declares it inline rather than inventing a
    /// prefix, which keeps the document readable and cannot collide with `D`.
    fn write_empty(&self, out: &mut String) {
        out.push('<');
        out.push_str(&self.local);
        if !self.namespace.is_empty() {
            out.push_str(" xmlns=\"");
            out.push_str(&escape(&self.namespace));
            out.push('"');
        }
        out.push_str("/>\n");
    }
}

/// One live property, with its value.
///
/// Every variant is a property this server can actually answer. There is no
/// `Other(String, String)`: a property we do not know is a `404` in its own
/// `propstat`, not a value we invent.
///
/// `creationdate` is deliberately absent. It wants an ISO 8601 timestamp, this
/// workspace's only date formatter produces the HTTP-date form, and adding a
/// second one here would put two civil-calendar implementations in the
/// repository. It belongs in `http::date` next to the first, and is recorded as
/// owed. Clients degrade by showing no creation date, which is visible and
/// harmless.
///
/// `supportedlock` and `lockdiscovery` carry pre-rendered XML rather than a
/// structured value, and that is the one place in this module where a variant
/// holds markup. It is deliberate and it is narrow: both strings come from
/// [`crate::dav::lock`], which builds them from compile-time element names and
/// runs every piece of caller text — an owner, a token — through [`escape`]
/// first. There is still no variant that takes markup from anywhere else, and
/// there must not be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Property {
    /// Whether this is a collection. Empty for a file — the empty element is the
    /// answer, not a missing one.
    ResourceType(Kind),
    /// Size in bytes. Files only; a collection that reported one would be
    /// claiming its listing is its content.
    ContentLength(u64),
    /// The media type.
    ContentType(String),
    /// Last modification, as an HTTP-date.
    LastModified(SystemTime),
    /// The name a person reads, XML-escaped on the way out.
    DisplayName(String),
    /// The same validator `GET` sends, so a client that compares them agrees
    /// with itself.
    ETag(String),
    /// RFC 4331: bytes this share will still accept.
    QuotaAvailableBytes(u64),
    /// RFC 4331: bytes this share holds.
    QuotaUsedBytes(u64),
    /// What kinds of lock this server grants, from
    /// [`crate::dav::lock::supportedlock`].
    ///
    /// Not optional on a class-2 server: a client reads it to learn that only
    /// exclusive write locks exist here, and so never asks for a shared one and
    /// never has to handle the refusal.
    SupportedLock(&'static str),
    /// The locks currently held on this resource, from
    /// [`crate::dav::lock::lockdiscovery`].
    LockDiscovery(String),
}

impl Property {
    /// The local name, in the `DAV:` namespace.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ResourceType(_) => "resourcetype",
            Self::ContentLength(_) => "getcontentlength",
            Self::ContentType(_) => "getcontenttype",
            Self::LastModified(_) => "getlastmodified",
            Self::DisplayName(_) => "displayname",
            Self::ETag(_) => "getetag",
            Self::QuotaAvailableBytes(_) => "quota-available-bytes",
            Self::QuotaUsedBytes(_) => "quota-used-bytes",
            Self::SupportedLock(_) => "supportedlock",
            Self::LockDiscovery(_) => "lockdiscovery",
        }
    }

    /// Writes the element and its value.
    fn write(&self, out: &mut String) {
        let name = self.name();
        match self {
            Self::ResourceType(Kind::Directory) => {
                out.push_str("<D:resourcetype><D:collection/></D:resourcetype>\n");
            }
            // An **empty** `resourcetype` is how a file says it is not a
            // collection. Omitting the property entirely is a different claim —
            // "I do not know" — and Finder reads it as a directory.
            Self::ResourceType(Kind::File) => out.push_str("<D:resourcetype/>\n"),
            Self::ContentLength(bytes)
            | Self::QuotaAvailableBytes(bytes)
            | Self::QuotaUsedBytes(bytes) => {
                write_element(out, name, &bytes.to_string());
            }
            Self::ContentType(text) | Self::DisplayName(text) | Self::ETag(text) => {
                write_element(out, name, text);
            }
            Self::LastModified(time) => write_element(out, name, &date::format(*time)),
            // The one pair whose value is already an element tree. Both are
            // built by `crate::dav::lock` out of compile-time names with every
            // piece of caller text escaped on the way in, which is why they are
            // written rather than escaped again — escaping here would render
            // the elements as text and a client would read no locks at all.
            Self::SupportedLock(markup) => out.push_str(markup),
            Self::LockDiscovery(markup) => out.push_str(markup),
        }
    }
}

/// One `<D:response>`: a resource, what was answered about it, and what was
/// asked for and is not there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceResponse {
    /// The resource's URL, which can only have come from [`Mount::href`].
    pub href: Href,
    /// The properties that exist here.
    pub answered: Answered,
    /// The properties that were asked for and do not, each echoed back in its
    /// own namespace under a `404`.
    pub missing: Vec<PropertyName>,
}

/// What a response says about the properties it does have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answered {
    /// Names and values — the answer to `allprop` and to a named `prop`.
    Values(Vec<Property>),
    /// Names only, with empty elements — the answer to `propname`.
    Names(Vec<&'static str>),
}

impl Answered {
    /// Whether there is anything to put in a `200` `propstat` at all.
    fn is_empty(&self) -> bool {
        match self {
            Self::Values(values) => values.is_empty(),
            Self::Names(names) => names.is_empty(),
        }
    }

    /// Writes the properties into an open `<D:prop>`.
    fn write(&self, out: &mut String) {
        match self {
            Self::Values(values) => {
                for value in values {
                    value.write(out);
                }
            }
            Self::Names(names) => {
                for name in names {
                    out.push_str("<D:");
                    out.push_str(name);
                    out.push_str("/>\n");
                }
            }
        }
    }
}

/// A whole `207` body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultiStatus {
    responses: Vec<ResourceResponse>,
}

impl MultiStatus {
    /// Collects the responses, in the order the client will read them.
    ///
    /// The order is the caller's: RFC 4918 wants the requested resource itself
    /// first and its children after, and only the caller knows which was
    /// requested. Sorting here would quietly break that.
    pub fn new(responses: Vec<ResourceResponse>) -> Self {
        Self { responses }
    }

    /// The body as text.
    pub fn to_xml(&self) -> String {
        let mut out = String::from(
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<D:multistatus xmlns:D=\"DAV:\">\n",
        );
        for response in &self.responses {
            out.push_str("<D:response>\n<D:href>");
            // The href is already percent-encoded, so it holds no `&` or `<` and
            // this escape is a no-op on every legal value. It is here anyway,
            // because "this input happens to be safe" is how the next author
            // learns that escaping is optional.
            out.push_str(&escape(response.href.as_str()));
            out.push_str("</D:href>\n");

            if !response.answered.is_empty() {
                out.push_str("<D:propstat>\n<D:prop>\n");
                response.answered.write(&mut out);
                out.push_str("</D:prop>\n<D:status>HTTP/1.1 ");
                out.push_str(&Status::OK.to_string());
                out.push_str("</D:status>\n</D:propstat>\n");
            }

            if !response.missing.is_empty() {
                out.push_str("<D:propstat>\n<D:prop>\n");
                for name in &response.missing {
                    name.write_empty(&mut out);
                }
                out.push_str("</D:prop>\n<D:status>HTTP/1.1 ");
                out.push_str(&Status::NOT_FOUND.to_string());
                out.push_str("</D:status>\n</D:propstat>\n");
            }

            out.push_str("</D:response>\n");
        }
        out.push_str("</D:multistatus>\n");
        out
    }

    /// The body as a `207` response.
    pub fn into_response(self) -> Result<Response, HeaderError> {
        Response::bytes(MULTI_STATUS, XML_TYPE, self.to_xml().into_bytes())
    }
}

/// An `<D:error>` body, which is how WebDAV says *why* rather than only *no*.
///
/// The condition is a compile-time element name from the specification, never
/// caller text, so this cannot become an injection point by growing a parameter
/// later — a caller with something to say has to add a constant here.
pub fn error_body(status: Status, condition: &'static str) -> Result<Response, HeaderError> {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n\
         <D:error xmlns:D=\"DAV:\">\n<D:{condition}/>\n</D:error>\n"
    );
    Response::bytes(status, XML_TYPE, body.into_bytes())
}

/// Turns any response into one whose framing a client can read.
///
/// Every builder in this module can fail only by way of [`HeaderError`], which
/// is raised for a CR, an LF or a NUL in a header value — and every value these
/// builders set is a compile-time constant. Answering `500` rather than
/// unwrapping keeps that reasoning from becoming a panic if it is ever wrong,
/// which under `panic = "abort"` would take the whole box down over a filename.
pub fn or_internal_error(built: Result<Response, HeaderError>) -> Response {
    built.unwrap_or_else(|_| Response::error_page(Status::INTERNAL_SERVER_ERROR))
}

/// Escapes text for an XML element body or an attribute value.
///
/// All five of the predefined entities, in both places, deliberately. Only
/// `&` and `<` are strictly required inside an element and only `&`, `<` and
/// the delimiting quote inside an attribute — but a function whose correctness
/// depends on knowing which of the two contexts it is being called from is a
/// function that will eventually be called from the other one. One rule, no
/// exceptions, at the cost of a few bytes in a body nobody reads by hand; this
/// is the same trade [`crate::path::encode_segment`] makes, for the same reason.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

/// Writes one `DAV:` element with escaped text in it.
fn write_element(out: &mut String, name: &str, value: &str) {
    out.push_str("<D:");
    out.push_str(name);
    out.push('>');
    out.push_str(&escape(value));
    out.push_str("</D:");
    out.push_str(name);
    out.push_str(">\n");
}

/// The body of a response as text, so a test can assert against the bytes a
/// client will receive rather than against the builder's input.
#[cfg(test)]
fn body_text(response: &Response) -> String {
    match &response.body {
        selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, UNIX_EPOCH};

    fn share() -> ShareId {
        ShareId::parse("vault").expect("a legal id")
    }

    fn path(segments: &[&str]) -> RelativePath {
        let mut path = RelativePath::default();
        for segment in segments {
            path = path.join(segment).expect("a legal segment");
        }
        path
    }

    /// The golden body for a file: an **empty** `resourcetype`, a length, and a
    /// validator that matches the one `GET` would send.
    #[test]
    fn a_file_answers_with_an_empty_resourcetype() {
        let mount = Mount::for_share(&share());
        let modified = UNIX_EPOCH + Duration::from_secs(1_770_000_000);
        let response = ResourceResponse {
            href: mount.href(&path(&["notes.txt"]), Kind::File),
            answered: Answered::Values(vec![
                Property::ResourceType(Kind::File),
                Property::DisplayName("notes.txt".to_string()),
                Property::ContentLength(42),
                Property::ContentType("application/octet-stream".to_string()),
                Property::LastModified(modified),
                Property::ETag(date::entity_tag(42, Some(modified))),
            ]),
            missing: Vec::new(),
        };
        assert_eq!(
            MultiStatus::new(vec![response]).to_xml(),
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
                "<D:multistatus xmlns:D=\"DAV:\">\n",
                "<D:response>\n",
                "<D:href>/dav/vault/notes.txt</D:href>\n",
                "<D:propstat>\n<D:prop>\n",
                "<D:resourcetype/>\n",
                "<D:displayname>notes.txt</D:displayname>\n",
                "<D:getcontentlength>42</D:getcontentlength>\n",
                "<D:getcontenttype>application/octet-stream</D:getcontenttype>\n",
                "<D:getlastmodified>Mon, 02 Feb 2026 02:40:00 GMT</D:getlastmodified>\n",
                "<D:getetag>W/&quot;2a-69800e80&quot;</D:getetag>\n",
                "</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n",
                "</D:response>\n",
                "</D:multistatus>\n",
            )
        );
    }

    /// The golden body for a collection: a trailing slash on the `href`, a
    /// `<D:collection/>` inside `resourcetype`, no length, and the RFC 4331
    /// quota pair without which Finder reports no free space and refuses every
    /// copy.
    #[test]
    fn a_collection_answers_with_a_trailing_slash_and_the_quota_pair() {
        let mount = Mount::for_share(&share());
        let response = ResourceResponse {
            href: mount.href(&path(&["photos"]), Kind::Directory),
            answered: Answered::Values(vec![
                Property::ResourceType(Kind::Directory),
                Property::DisplayName("photos".to_string()),
                Property::ContentType(COLLECTION_TYPE.to_string()),
                Property::QuotaAvailableBytes(1024),
                Property::QuotaUsedBytes(2048),
            ]),
            missing: Vec::new(),
        };
        assert_eq!(
            MultiStatus::new(vec![response]).to_xml(),
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
                "<D:multistatus xmlns:D=\"DAV:\">\n",
                "<D:response>\n",
                "<D:href>/dav/vault/photos/</D:href>\n",
                "<D:propstat>\n<D:prop>\n",
                "<D:resourcetype><D:collection/></D:resourcetype>\n",
                "<D:displayname>photos</D:displayname>\n",
                "<D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n",
                "<D:quota-available-bytes>1024</D:quota-available-bytes>\n",
                "<D:quota-used-bytes>2048</D:quota-used-bytes>\n",
                "</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n",
                "</D:response>\n",
                "</D:multistatus>\n",
            )
        );

        // The share root is a collection too, and its href is the mount with a
        // slash — not the mount, which would make every child one level high.
        assert_eq!(mount.href(&RelativePath::default(), Kind::Directory).as_str(), "/dav/vault/");
    }

    /// The load-bearing test: a name that could break the XML, or change what
    /// the `href` means, does neither.
    ///
    /// Both halves matter and they are different repairs. In the `href` the name
    /// is percent-encoded, so `a%2fb` stays one segment instead of becoming two
    /// and naming a file one directory down. In `displayname` it is XML-escaped,
    /// so `&` and `'` cannot close an element or an attribute.
    ///
    /// The names here are hostile *and legal*, which is the only interesting
    /// kind. `<`, `>` and `"` never reach a `displayname` at all, because
    /// [`crate::path::validate_segment`] refuses them in a filename — but the
    /// escape covers them anyway, tested directly, because the day a name
    /// arrives from somewhere that has not been past the resolver is not a day
    /// to discover that this function trusted one.
    #[test]
    fn a_hostile_filename_can_neither_break_the_xml_nor_move_the_href() {
        let mount = Mount::for_share(&share());
        let hostile = "Q&A 100% 'draft'.txt";
        let relative = path(&["work"]).join(hostile).expect("a legal filename");
        let xml = MultiStatus::new(vec![ResourceResponse {
            href: mount.href(&relative, Kind::File),
            answered: Answered::Values(vec![
                Property::ResourceType(Kind::File),
                Property::DisplayName(hostile.to_string()),
            ]),
            missing: Vec::new(),
        }])
        .to_xml();

        assert_eq!(
            xml,
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
                "<D:multistatus xmlns:D=\"DAV:\">\n",
                "<D:response>\n",
                "<D:href>/dav/vault/work/Q%26A%20100%25%20%27draft%27.txt</D:href>\n",
                "<D:propstat>\n<D:prop>\n",
                "<D:resourcetype/>\n",
                "<D:displayname>Q&amp;A 100% &apos;draft&apos;.txt</D:displayname>\n",
                "</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n",
                "</D:response>\n",
                "</D:multistatus>\n",
            )
        );

        // The href a client follows resolves back to the file it was shown.
        for name in [hostile, "a%2fb", "caf\u{e9}.txt", "a#b.txt"] {
            let relative = path(&["work"]).join(name).expect("a legal filename");
            let href = mount.href(&relative, Kind::File);
            let target = href
                .as_str()
                .strip_prefix(mount.prefix())
                .expect("an href starts at its own mount");
            let resolved = path::resolve(std::path::Path::new("/srv/vault"), target)
                .expect("the encoded href resolves");
            assert_eq!(resolved.relative().segments(), ["work", name], "round trip of {name:?}");
        }
    }

    /// A property nobody here implements comes back as a `404` in its own
    /// namespace, next to the ones that were answered.
    #[test]
    fn an_unknown_property_is_a_404_in_the_namespace_it_was_asked_in() {
        let mount = Mount::for_share(&share());
        let response = ResourceResponse {
            href: mount.href(&path(&["notes.txt"]), Kind::File),
            answered: Answered::Values(vec![Property::ResourceType(Kind::File)]),
            missing: vec![
                PropertyName::new("urn:example:\"quoted\"", "coolness").expect("a legal name"),
                PropertyName::dav("creationdate").expect("a legal name"),
                PropertyName::new("", "bare").expect("a legal name"),
            ],
        };
        let xml = MultiStatus::new(vec![response]).to_xml();
        assert!(xml.contains("<coolness xmlns=\"urn:example:&quot;quoted&quot;\"/>"), "{xml}");
        assert!(xml.contains("<creationdate xmlns=\"DAV:\"/>"), "{xml}");
        assert!(xml.contains("<bare/>"), "{xml}");
        assert!(xml.contains("<D:status>HTTP/1.1 404 Not Found</D:status>"), "{xml}");
        assert!(xml.contains("<D:status>HTTP/1.1 200 OK</D:status>"), "{xml}");
    }

    /// A property name that would end its own element is not a property name.
    #[test]
    fn a_property_name_that_could_break_out_is_refused_at_construction() {
        for hostile in ["a>b", "a b", "a/b", "", "1st", "a<b", "-lead", "a\"b", "a&b"] {
            assert!(PropertyName::new("urn:x", hostile).is_none(), "{hostile:?}");
        }
        for legal in ["resourcetype", "quota-available-bytes", "_x", "a.b", "A1"] {
            assert!(PropertyName::dav(legal).is_some(), "{legal:?}");
        }
    }

    /// `propname` answers with the shape of the properties and none of their
    /// values, which is the whole difference between it and `allprop`.
    #[test]
    fn propname_answers_names_with_no_values() {
        let mount = Mount::for_share(&share());
        let response = ResourceResponse {
            href: mount.href(&path(&["notes.txt"]), Kind::File),
            answered: Answered::Names(vec!["resourcetype", "getcontentlength"]),
            missing: Vec::new(),
        };
        let xml = MultiStatus::new(vec![response]).to_xml();
        assert!(xml.contains("<D:resourcetype/>\n<D:getcontentlength/>"), "{xml}");
        assert!(!xml.contains("</D:getcontentlength>"), "{xml}");
    }

    /// A response about a resource with nothing to say still names the resource,
    /// rather than emitting an empty `propstat` that clients read as malformed.
    #[test]
    fn a_response_with_no_properties_is_still_a_well_formed_response() {
        let mount = Mount::for_share(&share());
        let xml = MultiStatus::new(vec![ResourceResponse {
            href: mount.href(&RelativePath::default(), Kind::Directory),
            answered: Answered::Values(Vec::new()),
            missing: Vec::new(),
        }])
        .to_xml();
        assert_eq!(
            xml,
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
                "<D:multistatus xmlns:D=\"DAV:\">\n",
                "<D:response>\n<D:href>/dav/vault/</D:href>\n</D:response>\n",
                "</D:multistatus>\n",
            )
        );
        assert!(MultiStatus::new(Vec::new()).to_xml().contains("<D:multistatus"));
    }

    #[test]
    fn the_response_carries_the_status_and_the_media_type_a_client_expects() {
        let mount = Mount::for_share(&share());
        let response = MultiStatus::new(vec![ResourceResponse {
            href: mount.href(&RelativePath::default(), Kind::Directory),
            answered: Answered::Values(vec![Property::ResourceType(Kind::Directory)]),
            missing: Vec::new(),
        }])
        .into_response()
        .expect("a body with no header hazards");
        assert_eq!(response.status, MULTI_STATUS);
        assert_eq!(response.status.code(), 207);
        assert_eq!(response.headers.get_str("content-type"), Some(XML_TYPE));
        assert!(body_text(&response).contains("<D:collection/>"));
    }

    #[test]
    fn an_error_body_names_the_condition_the_specification_gives() {
        let response = error_body(Status::FORBIDDEN, "propfind-finite-depth")
            .expect("a body with no header hazards");
        assert_eq!(response.status, Status::FORBIDDEN);
        assert_eq!(
            body_text(&response),
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
                "<D:error xmlns:D=\"DAV:\">\n<D:propfind-finite-depth/>\n</D:error>\n",
            )
        );
    }

    #[test]
    fn escaping_covers_every_predefined_entity_and_leaves_the_rest_alone() {
        assert_eq!(escape("a&b<c>d\"e'f"), "a&amp;b&lt;c&gt;d&quot;e&apos;f");
        assert_eq!(escape("caf\u{e9} \u{1f600}"), "caf\u{e9} \u{1f600}");
        assert_eq!(escape(""), "");
    }

    /// The share id is encoded on its way into the mount, so the mount is not
    /// the one exception to the rule the rest of the module keeps.
    #[test]
    fn the_mount_encodes_the_share_id_like_every_other_segment() {
        let mount = Mount::for_share(&ShareId::parse("photos-2026").expect("a legal id"));
        assert_eq!(mount.prefix(), "/dav/photos-2026");
        assert_eq!(mount.name(), "photos-2026");
        assert_eq!(mount.href(&path(&["a"]), Kind::File).to_string(), "/dav/photos-2026/a");
    }
}
