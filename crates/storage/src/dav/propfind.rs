//! `PROPFIND`: reading the request, and deciding what each resource answers.
//!
//! Pure. The directory read that produces the resources belongs to
//! [`crate::fs`]; everything here is values in and a [`Response`] out, which is
//! what lets the hostile half — a body with a billion-laughs entity, a `Depth`
//! nobody should send, a property name that would break out of its own element
//! — be driven without a socket.
//!
//! # The request body is attacker-controlled XML, and that is the danger
//!
//! Every general-purpose XML parser has had to grow defences against the same
//! two attacks, and both of them cost a process rather than a request:
//!
//! - **Entity expansion.** `<!ENTITY lol "lolololol">` nested ten deep expands
//!   to gigabytes from a kilobyte of input. Under `panic = "abort"` an
//!   allocation failure here is not a `500`, it is the console, the mail server
//!   and the reverse proxy going down together.
//! - **Unbounded nesting.** A recursive-descent parser fed ten thousand open
//!   tags overflows the stack, which is likewise not a recoverable error.
//!
//! So this reader does neither. It **refuses** any body containing a document
//! type declaration ([`BodyError::ProhibitedDoctype`]) rather than parsing one,
//! which is the only entity defence that cannot be got subtly wrong; it never
//! recurses, keeping a bounded element stack and refusing past
//! [`MAX_ELEMENT_DEPTH`]; and it caps the whole body at [`MAX_BODY_BYTES`]. What
//! it understands is exactly the handful of elements RFC 4918 §14.20 defines for
//! this request and nothing else — a `PROPFIND` body is a fixed shape, and a
//! general parser would be a much larger attack surface for no gain.
//!
//! # What this build answers, and what it will not pretend to
//!
//! `allprop`, `propname` and a named `prop` are all understood. `include` is
//! parsed and ignored, which is correct rather than lazy: it asks for named
//! properties *in addition to* `allprop`, and `allprop` here already returns
//! every property this server has.
//!
//! `Depth: infinity` is refused with `403` and `<D:propfind-finite-depth/>`,
//! the exact condition RFC 4918 §9.1 defines for it. That is not a limitation to
//! apologise for: an infinite-depth `PROPFIND` on a share is a whole-tree walk
//! that one request can start and no client is waiting for, and every serious
//! server refuses it.

use super::multistatus::{
    error_body, or_internal_error, Answered, Href, Mount, MultiStatus, Property, PropertyName,
    ResourceResponse, COLLECTION_TYPE,
};
use crate::listing::{Entry, Kind};
use crate::path::RelativePath;
use crate::quota::{self, Limits, Usage};
use crate::respond::OPAQUE_TYPE;
use selfhost_http::{date, Response, Status};
use std::fmt;
use std::time::SystemTime;

/// The largest `PROPFIND` body this server will read.
///
/// 64 KiB, which is the relay's own forwarded-body cap — so the limit a client
/// meets is the same one wherever it meets it, rather than two limits that
/// drift apart. A real body is a few hundred bytes; anything near this is a
/// client with a bug or a caller with a plan.
pub const MAX_BODY_BYTES: usize = 64 * 1024;

/// How deeply elements may nest before the body is refused.
///
/// A `PROPFIND` body is three elements deep. Sixty-four is room for every
/// namespace-wrapping oddity a real client has ever produced and far below
/// anything that could exhaust memory — and because the reader keeps its own
/// stack rather than recursing, the limit is about memory rather than about the
/// call stack.
pub const MAX_ELEMENT_DEPTH: usize = 64;

/// How far down the tree a `PROPFIND` reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    /// The named resource alone.
    Zero,
    /// The named resource and its immediate children.
    One,
    /// The whole subtree — which this server refuses.
    Infinity,
}

/// A `Depth` header this server does not understand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadDepth;

impl fmt::Display for BadDepth {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Depth must be 0, 1 or infinity")
    }
}

impl std::error::Error for BadDepth {}

/// Reads the `Depth` header.
///
/// **An absent header means infinity**, which is what RFC 4918 §9.1 requires and
/// is worth stating because it is the opposite of the safe-looking default. The
/// consequence is that a bare `curl -X PROPFIND` gets a `403` rather than a
/// listing; every real client — Finder, the Windows Mini-Redirector, `cadaver`,
/// `rclone` — sends the header on every request, so the surprise falls on the
/// person exploring by hand, who can read the error.
pub fn depth(header: Option<&str>) -> Result<Depth, BadDepth> {
    match header.map(str::trim) {
        None => Ok(Depth::Infinity),
        Some("0") => Ok(Depth::Zero),
        Some("1") => Ok(Depth::One),
        // The token is case-insensitive in the specification, and clients have
        // been seen sending both spellings.
        Some(other) if other.eq_ignore_ascii_case("infinity") => Ok(Depth::Infinity),
        Some(_) => Err(BadDepth),
    }
}

/// The `403` a `Depth: infinity` gets, carrying the condition that names why.
///
/// A bare `403` tells a client it may not; the condition element tells it that
/// retrying at depth 1 will work, which is the difference between a client that
/// recovers and one that reports a broken server.
pub fn depth_infinity_refused() -> Response {
    or_internal_error(error_body(Status::FORBIDDEN, "propfind-finite-depth"))
}

/// What the client asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Requested {
    /// Every live property, with values. Also what an empty body means.
    AllProp,
    /// The names of every live property, with no values.
    PropName,
    /// Exactly these, each answered or reported missing.
    Named(Vec<PropertyName>),
}

/// Why a `PROPFIND` body could not be read.
///
/// Typed because three of them are a `400` with quite different causes and one
/// — [`BodyError::ProhibitedDoctype`] — is worth logging as an attempt rather
/// than as a client bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyError {
    /// Longer than [`MAX_BODY_BYTES`].
    TooLarge,
    /// Not valid UTF-8. Every WebDAV client sends UTF-8; a body that is not is
    /// not going to become readable by guessing at an encoding.
    NotUtf8,
    /// The XML did not parse as the small shape this reader understands.
    Malformed,
    /// The body carried a document type declaration. Refused rather than
    /// ignored — see this module's documentation.
    ProhibitedDoctype,
    /// Elements nested past [`MAX_ELEMENT_DEPTH`].
    TooDeep,
    /// The body parsed and asked for nothing: no `allprop`, no `propname`, no
    /// `prop`.
    NoRequest,
}

impl fmt::Display for BodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::TooLarge => "the request body is too large",
            Self::NotUtf8 => "the request body is not valid UTF-8",
            Self::Malformed => "the request body is not a PROPFIND document",
            Self::ProhibitedDoctype => "a document type declaration is not accepted here",
            Self::TooDeep => "the request body nests too deeply",
            Self::NoRequest => "the request body asks for no properties",
        };
        f.write_str(reason)
    }
}

impl std::error::Error for BodyError {}

/// Reads a `PROPFIND` body.
///
/// An empty body is [`Requested::AllProp`], which RFC 4918 §9.1 requires:
/// "an empty PROPFIND request body MUST be treated as if it were an `allprop`
/// request". Several clients rely on it.
pub fn parse(body: &[u8]) -> Result<Requested, BodyError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(BodyError::TooLarge);
    }
    let text = std::str::from_utf8(body).map_err(|_| BodyError::NotUtf8)?;
    if text.trim().is_empty() {
        return Ok(Requested::AllProp);
    }
    read_document(text)
}

/// One resource a `PROPFIND` answers about.
///
/// Deliberately not [`crate::listing::Entry`]: an `Entry` is a name in a
/// directory and may be one that cannot be served, while every `Resource` has an
/// `href`. [`Resource::from_entry`] is the one-way door between them, and it
/// returns `None` for exactly the entries a listing marks unreachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    /// Where it is, relative to the share root.
    pub path: RelativePath,
    /// File or collection.
    pub kind: Kind,
    /// Size in bytes; ignored for a collection.
    pub size: u64,
    /// Last modification, when the filesystem reported one.
    pub modified: Option<SystemTime>,
}

impl Resource {
    /// The resource at a path.
    pub fn new(path: RelativePath, kind: Kind, size: u64, modified: Option<SystemTime>) -> Self {
        Self { path, kind, size, modified }
    }

    /// One child of a directory being listed, or `None` if it has no URL.
    ///
    /// An unreachable entry — a name that is not UTF-8, or one this share's
    /// rules refuse — is skipped rather than given an `href`, for the reason
    /// [`crate::listing::Entry::to_json`] gives for omitting its `path`: a URL
    /// that resolves to something *else* is worse than no URL. The console
    /// shows those names greyed; WebDAV has no way to say "here but not
    /// fetchable", so it says nothing, and the file remains reachable over SMB
    /// and at the console.
    pub fn from_entry(parent: &RelativePath, entry: &Entry) -> Option<Self> {
        if !entry.reachable() {
            return None;
        }
        let path = parent.join(&entry.name).ok()?;
        Some(Self::new(path, entry.kind, entry.size, entry.modified))
    }

    /// The name a person reads. The share root borrows the share's own name,
    /// because a root has no last segment and an empty `displayname` shows as a
    /// blank row in Finder.
    fn display_name<'a>(&'a self, mount: &'a Mount) -> &'a str {
        self.path.file_name().unwrap_or_else(|| mount.name())
    }

    /// This resource's URL.
    fn href(&self, mount: &Mount) -> Href {
        mount.href(&self.path, self.kind)
    }
}

/// The RFC 4331 numbers, measured once so the property and the enforcement
/// cannot disagree.
///
/// They are not optional. Finder reads `quota-available-bytes` before it copies
/// anything and refuses the copy when it reads zero — so a share that omits the
/// pair looks full, and a share that hard-codes zero *is* full as far as every
/// client is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    /// Bytes this share will still accept.
    pub available: u64,
    /// Bytes it holds.
    pub used: u64,
}

impl Quota {
    /// Measures a share, through the same functions the write path enforces
    /// with.
    pub fn measure(limits: Limits, usage: Usage) -> Self {
        Self { available: quota::available(limits, usage), used: quota::used(usage) }
    }
}

/// Builds the `207` for a set of resources.
///
/// The order of `resources` is preserved and it matters: RFC 4918 expects the
/// requested resource first and its children after, and only the caller knows
/// which one was requested. A `Depth: 0` answer is a slice of length one; a
/// `Depth: 1` answer is the collection followed by its children.
///
/// `quota` is `None` for a share whose limits are not known here; when it is
/// `Some`, the pair is reported on collections only, which is where RFC 4331
/// puts it and where every client looks for it.
pub fn respond(
    mount: &Mount,
    resources: &[Resource],
    requested: &Requested,
    quota: Option<Quota>,
) -> Response {
    let responses = resources
        .iter()
        .map(|resource| answer(mount, resource, requested, quota))
        .collect();
    or_internal_error(MultiStatus::new(responses).into_response())
}

/// What one resource says in reply to one request.
fn answer(
    mount: &Mount,
    resource: &Resource,
    requested: &Requested,
    quota: Option<Quota>,
) -> ResourceResponse {
    let live = live_properties(mount, resource, quota);
    let (answered, missing) = match requested {
        Requested::AllProp => (Answered::Values(live), Vec::new()),
        // Derived from the same list rather than written out again, so the two
        // answers cannot come to disagree about what this server has.
        Requested::PropName => {
            (Answered::Names(live.iter().map(Property::name).collect()), Vec::new())
        }
        Requested::Named(wanted) => {
            let mut found = Vec::new();
            let mut absent = Vec::new();
            for name in wanted {
                match live.iter().find(|property| {
                    name.is_dav() && property.name() == name.local()
                }) {
                    Some(property) => found.push(property.clone()),
                    None => absent.push(name.clone()),
                }
            }
            (Answered::Values(found), absent)
        }
    };
    ResourceResponse { href: resource.href(mount), answered, missing }
}

/// Every property this server has about one resource.
///
/// The single source of truth for all three request forms: `allprop` returns
/// this, `propname` returns its names, and a named request looks its entries up
/// here. A property that is not in this list is a `404` — which is the honest
/// answer, and the reason there is no fallback branch that invents a value.
fn live_properties(mount: &Mount, resource: &Resource, quota: Option<Quota>) -> Vec<Property> {
    let mut properties = vec![
        Property::ResourceType(resource.kind),
        Property::DisplayName(resource.display_name(mount).to_string()),
    ];
    match resource.kind {
        Kind::File => {
            properties.push(Property::ContentLength(resource.size));
            // The same opaque type `GET` serves, from the same place, because a
            // client told one type and served another is a client that has been
            // lied to about what it is allowed to render.
            properties.push(Property::ContentType(OPAQUE_TYPE.to_string()));
            properties.push(Property::ETag(date::entity_tag(resource.size, resource.modified)));
        }
        Kind::Directory => {
            properties.push(Property::ContentType(COLLECTION_TYPE.to_string()));
            if let Some(quota) = quota {
                properties.push(Property::QuotaAvailableBytes(quota.available));
                properties.push(Property::QuotaUsedBytes(quota.used));
            }
        }
    }
    if let Some(modified) = resource.modified {
        properties.push(Property::LastModified(modified));
    }
    properties
}

// ---------------------------------------------------------------------------
// The reader.
//
// A scanner over the bytes, with an explicit stack. Nothing below recurses and
// nothing below allocates in proportion to anything but the input, which is
// capped before the first byte is looked at.
// ---------------------------------------------------------------------------

/// One thing the scanner found.
#[derive(Debug)]
enum Token<'a> {
    /// An element opened; `attributes` is the raw text after the name.
    Open { name: &'a str, attributes: &'a str, self_closing: bool },
    /// An element closed, carrying the name it claims to close.
    Close { name: &'a str },
    /// A declaration, a comment or a CDATA section — nothing this reader needs.
    Ignorable,
}

/// Reads the whole document and decides what was asked for.
///
/// Well-formedness is checked rather than assumed: every close must match the
/// open it closes, and the document must end with nothing left open. A reader
/// that skipped that would answer a truncated body as though it were a complete
/// one — `<propfind><prop>` with nothing after it would become "you asked for no
/// properties", which is a different request from the one that was cut off.
fn read_document(text: &str) -> Result<Requested, BodyError> {
    let mut namespaces: Vec<(String, String)> = Vec::new();
    let mut stack: Vec<&str> = Vec::new();
    let mut names: Vec<PropertyName> = Vec::new();

    // `Some(depth)` while inside a `DAV:prop`, holding the depth its children
    // sit at. A stack position rather than a boolean, so a `<prop>` nested
    // inside another element cannot leave the flag set forever.
    let mut inside_prop: Option<usize> = None;
    let (mut saw_prop, mut saw_allprop, mut saw_propname) = (false, false, false);

    let mut at = 0;
    while let Some(token) = next_token(text, &mut at)? {
        match token {
            Token::Ignorable => {}
            Token::Close { name } => {
                if stack.pop() != Some(name) {
                    return Err(BodyError::Malformed);
                }
                if inside_prop.is_some_and(|depth| stack.len() < depth) {
                    inside_prop = None;
                }
            }
            Token::Open { name, attributes, self_closing } => {
                declare_namespaces(attributes, &mut namespaces)?;
                let (namespace, local) = resolve(name, &namespaces);

                if inside_prop.is_some_and(|depth| stack.len() == depth) {
                    let Some(property) = PropertyName::new(namespace, local) else {
                        return Err(BodyError::Malformed);
                    };
                    names.push(property);
                } else if namespace == super::multistatus::DAV_NAMESPACE {
                    match local {
                        // A self-closing `<D:prop/>` opens and closes at once,
                        // so it asks for no properties and must not arm the
                        // collector — otherwise the next element to reach that
                        // depth, anywhere later in the document, would be read
                        // as a property name.
                        "prop" => {
                            saw_prop = true;
                            if !self_closing {
                                inside_prop = Some(stack.len() + 1);
                            }
                        }
                        "allprop" => saw_allprop = true,
                        "propname" => saw_propname = true,
                        // `include` names properties to add to `allprop`, and
                        // `allprop` here is already everything, so its children
                        // are read and discarded rather than mistaken for a
                        // `prop` list.
                        _ => {}
                    }
                }

                if !self_closing {
                    if stack.len() >= MAX_ELEMENT_DEPTH {
                        return Err(BodyError::TooDeep);
                    }
                    stack.push(name);
                }
            }
        }
    }

    if !stack.is_empty() {
        return Err(BodyError::Malformed);
    }

    // Exactly one of the three is a request. More than one is a document no
    // client sends and this reader will not guess at.
    match (saw_prop, saw_allprop, saw_propname) {
        (true, false, false) => Ok(Requested::Named(names)),
        (false, true, false) => Ok(Requested::AllProp),
        (false, false, true) => Ok(Requested::PropName),
        (false, false, false) => Err(BodyError::NoRequest),
        _ => Err(BodyError::Malformed),
    }
}

/// Pulls the next token, advancing `at`.
///
/// Returns `None` at the end of the input. Text between elements is skipped:
/// a `PROPFIND` body has no meaningful character data, and reading it would only
/// create somewhere for an entity reference to hide.
fn next_token<'a>(text: &'a str, at: &mut usize) -> Result<Option<Token<'a>>, BodyError> {
    let bytes = text.as_bytes();
    let Some(offset) = bytes.get(*at..).and_then(|rest| rest.iter().position(|b| *b == b'<'))
    else {
        *at = text.len();
        return Ok(None);
    };
    let start = *at + offset;
    let rest = &text[start + 1..];

    if let Some(body) = rest.strip_prefix('?') {
        return skip_to(at, start + 2, body, "?>");
    }
    if let Some(body) = rest.strip_prefix("!--") {
        return skip_to(at, start + 4, body, "-->");
    }
    if let Some(body) = rest.strip_prefix("![CDATA[") {
        return skip_to(at, start + 9, body, "]]>");
    }
    if rest.starts_with('!') {
        // `<!DOCTYPE` and `<!ENTITY`. Refused rather than skipped: skipping one
        // would mean a body could declare entities this reader then failed to
        // expand, and *silently reading something different from what the
        // client wrote* is worse than refusing.
        return Err(BodyError::ProhibitedDoctype);
    }

    let Some(length) = tag_length(rest) else {
        return Err(BodyError::Malformed);
    };
    let tag = &rest[..length];
    *at = start + 1 + length + 1;

    if let Some(closing) = tag.strip_prefix('/') {
        let name = closing.trim();
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(BodyError::Malformed);
        }
        return Ok(Some(Token::Close { name }));
    }

    let (tag, self_closing) = match tag.strip_suffix('/') {
        Some(without) => (without, true),
        None => (tag, false),
    };
    let split = tag.find(|c: char| c.is_ascii_whitespace()).unwrap_or(tag.len());
    let (name, attributes) = tag.split_at(split);
    if name.is_empty() {
        return Err(BodyError::Malformed);
    }
    Ok(Some(Token::Open { name, attributes, self_closing }))
}

/// Skips a construct that ends with a fixed terminator.
///
/// An unterminated one is [`BodyError::Malformed`] rather than "everything from
/// here is a comment": a body that opens `<!--` and never closes it would
/// otherwise hide the rest of the request, and the request that was read would
/// not be the request that was sent.
fn skip_to<'a>(
    at: &mut usize,
    body_start: usize,
    body: &str,
    terminator: &str,
) -> Result<Option<Token<'a>>, BodyError> {
    let Some(end) = body.find(terminator) else {
        return Err(BodyError::Malformed);
    };
    *at = body_start + end + terminator.len();
    Ok(Some(Token::Ignorable))
}

/// The length of a tag's text, from just after `<` up to its `>`.
///
/// Quoted attribute values are honoured, so a `>` inside one does not end the
/// tag early — which is the difference between reading the document the client
/// sent and reading one an attacker shaped.
fn tag_length(rest: &str) -> Option<usize> {
    let mut quote: Option<u8> = None;
    for (index, byte) in rest.as_bytes().iter().enumerate() {
        match (quote, byte) {
            (Some(open), b) if *b == open => quote = None,
            (Some(_), _) => {}
            (None, b'"') => quote = Some(b'"'),
            (None, b'\'') => quote = Some(b'\''),
            (None, b'>') => return Some(index),
            (None, b'<') => return None,
            (None, _) => {}
        }
    }
    None
}

/// Records every `xmlns` declaration on one element.
///
/// The map is flat rather than scoped: a prefix declared anywhere is treated as
/// declared everywhere after it. That is a simplification and it is stated
/// rather than hidden — real `PROPFIND` bodies declare their namespaces on the
/// root element, and the only thing a scoped map would buy is correctness for a
/// document that re-binds a prefix mid-body, which no client sends and which
/// could at worst mislabel the namespace echoed back in a `404`.
fn declare_namespaces(
    attributes: &str,
    namespaces: &mut Vec<(String, String)>,
) -> Result<(), BodyError> {
    for (name, value) in parse_attributes(attributes)? {
        let prefix = if name == "xmlns" {
            ""
        } else if let Some(prefix) = name.strip_prefix("xmlns:") {
            prefix
        } else {
            continue;
        };
        namespaces.retain(|(declared, _)| declared != prefix);
        namespaces.push((prefix.to_string(), value.to_string()));
    }
    Ok(())
}

/// Splits an attribute region into name/value pairs.
///
/// Strict: anything it cannot read is [`BodyError::Malformed`] rather than
/// skipped, because the one thing being read out of here is which namespace a
/// property belongs to, and quietly ignoring a declaration would answer about a
/// different property than the one asked for.
///
/// Entity references in a value are **not** expanded — this reader expands
/// nothing, which is its defence — so a value containing `&` is refused rather
/// than read as its literal text. No client puts one in a namespace URI.
fn parse_attributes(attributes: &str) -> Result<Vec<(&str, &str)>, BodyError> {
    let mut pairs = Vec::new();
    let mut rest = attributes.trim_start();
    while !rest.is_empty() {
        let Some(equals) = rest.find('=') else {
            return Err(BodyError::Malformed);
        };
        let name = rest[..equals].trim_end();
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err(BodyError::Malformed);
        }
        let after = rest[equals + 1..].trim_start();
        let mut characters = after.chars();
        let quote = match characters.next() {
            Some(quote @ ('"' | '\'')) => quote,
            _ => return Err(BodyError::Malformed),
        };
        let value_start = quote.len_utf8();
        let Some(end) = after[value_start..].find(quote) else {
            return Err(BodyError::Malformed);
        };
        let value = &after[value_start..value_start + end];
        if value.contains('&') {
            return Err(BodyError::Malformed);
        }
        pairs.push((name, value));
        rest = after[value_start + end + quote.len_utf8()..].trim_start();
    }
    Ok(pairs)
}

/// Splits a qualified name and resolves its prefix.
///
/// An unprefixed name takes the default namespace, which is empty when none was
/// declared — and an empty namespace is a real answer, not a missing one: it is
/// how a property in no namespace is echoed back.
fn resolve<'a>(name: &'a str, namespaces: &'a [(String, String)]) -> (&'a str, &'a str) {
    let (prefix, local) = match name.split_once(':') {
        Some((prefix, local)) => (prefix, local),
        None => ("", name),
    };
    let namespace = namespaces
        .iter()
        .find(|(declared, _)| declared == prefix)
        .map(|(_, uri)| uri.as_str())
        .unwrap_or("");
    (namespace, local)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::share::ShareId;
    use std::ffi::OsStr;
    use std::time::{Duration, UNIX_EPOCH};

    fn mount() -> Mount {
        Mount::for_share(&ShareId::parse("vault").expect("a legal id"))
    }

    fn path(segments: &[&str]) -> RelativePath {
        let mut path = RelativePath::default();
        for segment in segments {
            path = path.join(segment).expect("a legal segment");
        }
        path
    }

    fn names(requested: &Requested) -> Vec<(String, String)> {
        match requested {
            Requested::Named(names) => names
                .iter()
                .map(|name| (name.namespace().to_string(), name.local().to_string()))
                .collect(),
            other => panic!("expected a named request, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_depth_is_infinity_and_infinity_is_refused_by_name() {
        assert_eq!(depth(None), Ok(Depth::Infinity));
        assert_eq!(depth(Some("0")), Ok(Depth::Zero));
        assert_eq!(depth(Some(" 1 ")), Ok(Depth::One));
        assert_eq!(depth(Some("infinity")), Ok(Depth::Infinity));
        assert_eq!(depth(Some("Infinity")), Ok(Depth::Infinity));
        assert_eq!(depth(Some("2")), Err(BadDepth));
        assert_eq!(depth(Some("")), Err(BadDepth));

        let refused = depth_infinity_refused();
        assert_eq!(refused.status, Status::FORBIDDEN);
        let body = match &refused.body {
            selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            other => panic!("expected an in-memory body, got {other:?}"),
        };
        assert!(body.contains("<D:propfind-finite-depth/>"), "{body}");
    }

    #[test]
    fn an_empty_body_is_allprop_because_the_specification_says_so() {
        assert_eq!(parse(b""), Ok(Requested::AllProp));
        assert_eq!(parse(b"   \r\n  "), Ok(Requested::AllProp));
    }

    #[test]
    fn the_three_request_shapes_are_read() {
        assert_eq!(
            parse(br#"<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:allprop/></D:propfind>"#),
            Ok(Requested::AllProp)
        );
        assert_eq!(
            parse(br#"<propfind xmlns="DAV:"><propname/></propfind>"#),
            Ok(Requested::PropName)
        );
        let named = parse(
            br#"<D:propfind xmlns:D="DAV:"><D:prop><D:resourcetype/><D:getcontentlength/>
                </D:prop></D:propfind>"#,
        )
        .expect("a named request");
        assert_eq!(
            names(&named),
            vec![
                ("DAV:".to_string(), "resourcetype".to_string()),
                ("DAV:".to_string(), "getcontentlength".to_string()),
            ]
        );
    }

    /// Finder's own body, near enough: a default namespace, mixed prefixes, and
    /// a property in a vendor namespace beside the standard ones.
    #[test]
    fn a_property_keeps_the_namespace_it_was_asked_in() {
        let named = parse(
            br#"<?xml version="1.0" encoding="utf-8"?>
                <propfind xmlns="DAV:" xmlns:apple="http://apple.com/ns/">
                  <prop>
                    <resourcetype/>
                    <apple:quota-available-bytes/>
                    <novel xmlns="urn:example"/>
                  </prop>
                </propfind>"#,
        )
        .expect("a named request");
        assert_eq!(
            names(&named),
            vec![
                ("DAV:".to_string(), "resourcetype".to_string()),
                ("http://apple.com/ns/".to_string(), "quota-available-bytes".to_string()),
                ("urn:example".to_string(), "novel".to_string()),
            ]
        );
    }

    /// The attacks that cost a process rather than a request.
    #[test]
    fn the_reader_refuses_the_bodies_that_would_end_the_daemon() {
        // Billion laughs. Refused at the declaration, never expanded.
        assert_eq!(
            parse(
                br#"<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]>
                    <propfind xmlns="DAV:"><allprop/></propfind>"#
            ),
            Err(BodyError::ProhibitedDoctype)
        );
        // An external entity, which is the same refusal for the same reason.
        assert_eq!(
            parse(br#"<!DOCTYPE p [<!ENTITY x SYSTEM "file:///etc/passwd">]><p/>"#),
            Err(BodyError::ProhibitedDoctype)
        );

        // Unbounded nesting. The reader keeps its own stack, so this is a
        // refusal rather than an overflow.
        let deep = "<a>".repeat(MAX_ELEMENT_DEPTH + 10);
        assert_eq!(parse(deep.as_bytes()), Err(BodyError::TooDeep));

        // Oversized bodies never reach the scanner at all.
        assert_eq!(parse(&vec![b'a'; MAX_BODY_BYTES + 1]), Err(BodyError::TooLarge));

        // And a body that is not text is not repaired into text.
        assert_eq!(parse(&[0xff, 0xfe, 0x00]), Err(BodyError::NotUtf8));
    }

    #[test]
    fn a_body_that_does_not_parse_is_refused_rather_than_half_read() {
        for body in [
            "<propfind xmlns=\"DAV:\"><prop>",           // never closed
            "<propfind xmlns=\"DAV:\" bare><allprop/>",  // attribute with no value
            "<propfind xmlns=DAV:><allprop/></propfind>", // unquoted value
            "</>",                                        // empty close
            "<propfind xmlns=\"DAV:\"><allprop/><propname/></propfind>", // two requests
            "<propfind xmlns=\"DAV:\"><prop><a b/></prop></propfind>",   // broken attribute
            "<propfind xmlns=\"a&amp;b\"><allprop/></propfind>", // an entity we will not expand
            "<propfind xmlns=\"DAV:\"><allprop/></prop></propfind>", // close does not match
            "</propfind>",                                         // a close with nothing open
            "<propfind xmlns=\"DAV:\"><allprop/>",                 // truncated mid-document
        ] {
            assert!(
                matches!(parse(body.as_bytes()), Err(BodyError::Malformed)),
                "{body:?} parsed as {:?}",
                parse(body.as_bytes())
            );
        }
        assert_eq!(parse(b"<propfind xmlns=\"DAV:\"></propfind>"), Err(BodyError::NoRequest));
    }

    /// A `>` inside a quoted attribute does not end the tag, so a client cannot
    /// shape the document by hiding one there.
    #[test]
    fn a_quoted_angle_bracket_does_not_end_a_tag() {
        let named = parse(
            br#"<propfind xmlns="DAV:" xmlns:x="urn:a>b"><prop><x:thing/></prop></propfind>"#,
        )
        .expect("a named request");
        assert_eq!(names(&named), vec![("urn:a>b".to_string(), "thing".to_string())]);
    }

    /// Comments, declarations and CDATA are stepped over rather than read.
    #[test]
    fn the_reader_steps_over_what_it_does_not_need() {
        assert_eq!(
            parse(
                br#"<?xml version="1.0"?><!-- a <prop> in a comment --><propfind xmlns="DAV:">
                    <![CDATA[<allprop/>]]><propname/></propfind>"#
            ),
            Ok(Requested::PropName)
        );
    }

    /// An empty `<D:prop/>` asks for nothing, and — this is the part worth a
    /// test — it must not leave the reader treating later elements as property
    /// names because they happen to sit at the depth its children would have.
    #[test]
    fn a_self_closing_prop_asks_for_nothing_and_arms_nothing() {
        let named = parse(br#"<propfind xmlns="DAV:"><prop/><a><b/></a></propfind>"#)
            .expect("a named request");
        assert_eq!(named, Requested::Named(Vec::new()));

        // And the ordinary nested form still collects, so the fix did not close
        // the door it was meant to leave open.
        let named = parse(br#"<propfind xmlns="DAV:"><prop><resourcetype/></prop></propfind>"#)
            .expect("a named request");
        assert_eq!(names(&named), vec![("DAV:".to_string(), "resourcetype".to_string())]);
    }

    /// A property name that would break out of its own element is refused at
    /// the door, not rendered and hoped about.
    #[test]
    fn a_property_name_that_is_not_a_name_is_refused() {
        assert_eq!(
            parse(br#"<propfind xmlns="DAV:"><prop><1bad/></prop></propfind>"#),
            Err(BodyError::Malformed)
        );
    }

    #[test]
    fn a_listing_entry_becomes_a_resource_only_when_it_has_a_url() {
        let parent = path(&["work"]);
        let good = Entry::new(OsStr::new("notes.txt"), Kind::File, 42, None);
        let resource = Resource::from_entry(&parent, &good).expect("a reachable entry");
        assert_eq!(resource.path.segments(), ["work", "notes.txt"]);
        assert_eq!(resource.kind, Kind::File);
        assert_eq!(resource.size, 42);

        // The names a listing shows greyed have no href, so they are not here.
        for name in ["CON.txt", "readme.txt:evil", "a\\b.txt", "trailing."] {
            let blocked = Entry::new(OsStr::new(name), Kind::File, 1, None);
            assert!(Resource::from_entry(&parent, &blocked).is_none(), "{name}");
        }
    }

    /// The whole `Depth: 1` answer, as a client receives it: the collection
    /// first with its quota pair, then each child.
    #[test]
    fn a_depth_one_listing_answers_the_collection_and_then_its_children() {
        let modified = UNIX_EPOCH + Duration::from_secs(1_770_000_000);
        let resources = vec![
            Resource::new(RelativePath::default(), Kind::Directory, 0, None),
            Resource::new(path(&["photos"]), Kind::Directory, 0, None),
            Resource::new(path(&["notes.txt"]), Kind::File, 42, Some(modified)),
        ];
        let quota = Quota { available: 1_000, used: 2_000 };
        let response = respond(&mount(), &resources, &Requested::AllProp, Some(quota));
        assert_eq!(response.status.code(), 207);
        let body = match &response.body {
            selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            other => panic!("expected an in-memory body, got {other:?}"),
        };
        assert_eq!(
            body,
            concat!(
                "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n",
                "<D:multistatus xmlns:D=\"DAV:\">\n",
                "<D:response>\n",
                "<D:href>/dav/vault/</D:href>\n",
                "<D:propstat>\n<D:prop>\n",
                "<D:resourcetype><D:collection/></D:resourcetype>\n",
                "<D:displayname>vault</D:displayname>\n",
                "<D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n",
                "<D:quota-available-bytes>1000</D:quota-available-bytes>\n",
                "<D:quota-used-bytes>2000</D:quota-used-bytes>\n",
                "</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n",
                "</D:response>\n",
                "<D:response>\n",
                "<D:href>/dav/vault/photos/</D:href>\n",
                "<D:propstat>\n<D:prop>\n",
                "<D:resourcetype><D:collection/></D:resourcetype>\n",
                "<D:displayname>photos</D:displayname>\n",
                "<D:getcontenttype>httpd/unix-directory</D:getcontenttype>\n",
                "<D:quota-available-bytes>1000</D:quota-available-bytes>\n",
                "<D:quota-used-bytes>2000</D:quota-used-bytes>\n",
                "</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n",
                "</D:response>\n",
                "<D:response>\n",
                "<D:href>/dav/vault/notes.txt</D:href>\n",
                "<D:propstat>\n<D:prop>\n",
                "<D:resourcetype/>\n",
                "<D:displayname>notes.txt</D:displayname>\n",
                "<D:getcontentlength>42</D:getcontentlength>\n",
                "<D:getcontenttype>application/octet-stream</D:getcontenttype>\n",
                "<D:getetag>W/&quot;2a-69800e80&quot;</D:getetag>\n",
                "<D:getlastmodified>Mon, 02 Feb 2026 02:40:00 GMT</D:getlastmodified>\n",
                "</D:prop>\n<D:status>HTTP/1.1 200 OK</D:status>\n</D:propstat>\n",
                "</D:response>\n",
                "</D:multistatus>\n",
            )
        );
    }

    /// A named request answers what it has and reports what it does not, in the
    /// namespace it was asked in.
    #[test]
    fn a_named_request_separates_what_exists_from_what_does_not() {
        let resources = vec![Resource::new(path(&["notes.txt"]), Kind::File, 7, None)];
        let requested = Requested::Named(vec![
            PropertyName::dav("resourcetype").expect("a legal name"),
            PropertyName::dav("creationdate").expect("a legal name"),
            PropertyName::new("urn:example", "coolness").expect("a legal name"),
        ]);
        let response = respond(&mount(), &resources, &requested, None);
        let body = match &response.body {
            selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            other => panic!("expected an in-memory body, got {other:?}"),
        };
        assert!(body.contains("<D:resourcetype/>"), "{body}");
        assert!(body.contains("<creationdate xmlns=\"DAV:\"/>"), "{body}");
        assert!(body.contains("<coolness xmlns=\"urn:example\"/>"), "{body}");
        assert!(body.contains("<D:status>HTTP/1.1 404 Not Found</D:status>"), "{body}");
    }

    /// `propname` and `allprop` describe the same set, which is only true
    /// because one is derived from the other.
    #[test]
    fn propname_and_allprop_cannot_disagree_about_what_this_server_has() {
        let resources = vec![Resource::new(path(&["notes.txt"]), Kind::File, 7, None)];
        let all = respond(&mount(), &resources, &Requested::AllProp, None);
        let names = respond(&mount(), &resources, &Requested::PropName, None);
        let text = |response: &Response| match &response.body {
            selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
            _ => String::new(),
        };
        for property in ["resourcetype", "displayname", "getcontentlength", "getetag"] {
            assert!(text(&all).contains(&format!("<D:{property}")), "{property} in allprop");
            assert!(
                text(&names).contains(&format!("<D:{property}/>")),
                "{property} in propname"
            );
        }
        // A file has no quota pair, so neither answer claims one.
        assert!(!text(&all).contains("quota-"));
        assert!(!text(&names).contains("quota-"));
    }

    /// The quota pair comes from the same functions the write path enforces
    /// with, so the number a client is shown is the number it will be held to.
    #[test]
    fn the_quota_pair_is_measured_and_not_invented() {
        let limits = Limits::for_quota(Some(10_000));
        let usage = Usage {
            used_bytes: 4_000,
            free_bytes: 100 * 1024 * 1024 * 1024,
            uploads_running: 0,
            in_flight_bytes: 0,
        };
        let measured = Quota::measure(limits, usage);
        assert_eq!(measured.used, quota::used(usage));
        assert_eq!(measured.available, quota::available(limits, usage));
        assert_eq!(measured.available, 6_000);
    }
}
