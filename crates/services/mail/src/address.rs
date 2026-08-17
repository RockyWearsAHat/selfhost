//! Email addresses and the envelope paths that carry them.
//!
//! An address is parsed once, here, and every later decision — which mailbox a
//! message lands in, whether a domain is one of ours, whether relaying is being
//! attempted — is made against the parsed form. Comparing raw strings instead is
//! how open relays are built: `user@EXAMPLE.com` and `user@example.com` are the
//! same recipient, and a check that only matches one of them is not a check.

use std::fmt;

/// The maximum length of a full address (RFC 5321 §4.5.3.1.3).
pub const MAX_ADDRESS: usize = 254;
/// The maximum length of the part before the `@`.
pub const MAX_LOCAL: usize = 64;
/// The maximum length of the domain.
pub const MAX_DOMAIN: usize = 255;

/// A parsed email address.
///
/// The domain is stored lowercased because domains are case-insensitive. The
/// local part keeps its original case — the standard says only the receiving
/// server may interpret it, and lowercasing it would silently merge two
/// different mailboxes on servers that treat case as significant. Our own
/// matching is case-insensitive regardless, via [`Address::matches`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Address {
    local: String,
    domain: String,
}

/// Why an address could not be parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressError {
    /// No `@`, or more than one outside quotes.
    MissingAt,
    /// The local part was empty, too long, or contained an illegal byte.
    BadLocal,
    /// The domain was empty, too long, or not a valid hostname.
    BadDomain,
    /// The whole address exceeded [`MAX_ADDRESS`].
    TooLong,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingAt => write!(f, "address must contain exactly one @"),
            Self::BadLocal => write!(f, "invalid local part"),
            Self::BadDomain => write!(f, "invalid domain"),
            Self::TooLong => write!(f, "address exceeds {MAX_ADDRESS} characters"),
        }
    }
}

impl std::error::Error for AddressError {}

impl Address {
    /// Parses an address of the form `local@domain`.
    pub fn parse(input: &str) -> Result<Self, AddressError> {
        let text = input.trim();
        if text.len() > MAX_ADDRESS {
            return Err(AddressError::TooLong);
        }

        // Split on the *last* @, since a quoted local part may contain one.
        let (local, domain) = text.rsplit_once('@').ok_or(AddressError::MissingAt)?;

        if local.is_empty() || local.len() > MAX_LOCAL {
            return Err(AddressError::BadLocal);
        }
        if !is_valid_local(local) {
            return Err(AddressError::BadLocal);
        }
        if domain.is_empty() || domain.len() > MAX_DOMAIN || !is_valid_domain(domain) {
            return Err(AddressError::BadDomain);
        }

        Ok(Self { local: local.to_owned(), domain: domain.to_ascii_lowercase() })
    }

    /// The part before the `@`, in its original case.
    pub fn local(&self) -> &str {
        &self.local
    }

    /// The part after the `@`, lowercased.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    /// Whether two addresses refer to the same mailbox.
    ///
    /// Case-insensitive on both halves. This is the comparison every routing and
    /// relay decision must use.
    pub fn matches(&self, other: &Address) -> bool {
        self.domain == other.domain && self.local.eq_ignore_ascii_case(&other.local)
    }

    /// Whether this address belongs to one of the given domains.
    pub fn is_local_to(&self, domains: &[String]) -> bool {
        domains.iter().any(|d| d.eq_ignore_ascii_case(&self.domain))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.local, self.domain)
    }
}

/// Whether a local part contains only permitted characters.
///
/// Quoted forms are deliberately refused rather than half-supported. A quoted
/// local part may contain `@`, spaces, and escapes, and every layer that later
/// re-parses it must agree on the unquoting — a disagreement is a routing bug.
/// Refusing them costs a form almost nobody uses.
fn is_valid_local(local: &str) -> bool {
    if local.starts_with('"') || local.contains('"') {
        return false;
    }
    // A leading, trailing, or doubled dot is illegal.
    if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return false;
    }
    local.bytes().all(|b| {
        b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'.' | b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-'
                    | b'/' | b'=' | b'?' | b'^' | b'_' | b'`' | b'{' | b'|' | b'}' | b'~'
            )
    })
}

/// Whether a domain is a syntactically valid hostname.
fn is_valid_domain(domain: &str) -> bool {
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return false;
    }
    // A bare hostname with no dot cannot receive internet mail.
    if !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// An envelope path as it appears in `MAIL FROM` and `RCPT TO`.
///
/// The empty path `<>` is legal and meaningful in `MAIL FROM`: it marks a bounce
/// notification. A bounce must never itself be bounced, or two servers can
/// generate mail at each other indefinitely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Path {
    /// `<>` — the null sender, used by bounces.
    Null,
    /// An ordinary address.
    Mailbox(Address),
}

impl Path {
    /// Parses the `<...>` form used in SMTP commands.
    pub fn parse(input: &str) -> Result<Self, AddressError> {
        let text = input.trim();
        let inner = text
            .strip_prefix('<')
            .and_then(|rest| rest.strip_suffix('>'))
            .unwrap_or(text)
            .trim();

        if inner.is_empty() {
            return Ok(Self::Null);
        }

        // Source routes (`@a,@b:user@c`) are an obsolete relaying feature that
        // was removed from the standard precisely because it enabled abuse. The
        // route is discarded and only the final mailbox is honoured.
        let without_route = match inner.rsplit_once(':') {
            Some((route, mailbox)) if route.starts_with('@') => mailbox,
            _ => inner,
        };

        Address::parse(without_route).map(Self::Mailbox)
    }

    /// The address, or `None` for the null sender.
    pub fn address(&self) -> Option<&Address> {
        match self {
            Self::Null => None,
            Self::Mailbox(address) => Some(address),
        }
    }

    /// Whether this is the null sender.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => write!(f, "<>"),
            Self::Mailbox(address) => write!(f, "<{address}>"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_ordinary_address() {
        let address = Address::parse("dave@leveluplongboarding.surf").unwrap();
        assert_eq!(address.local(), "dave");
        assert_eq!(address.domain(), "leveluplongboarding.surf");
        assert_eq!(address.to_string(), "dave@leveluplongboarding.surf");
    }

    #[test]
    fn domains_are_lowercased_but_local_parts_are_not() {
        let address = Address::parse("Dave.Rider@Example.COM").unwrap();
        assert_eq!(address.domain(), "example.com");
        // Only the receiving server may interpret the local part, so its case
        // is preserved rather than silently folded.
        assert_eq!(address.local(), "Dave.Rider");
    }

    #[test]
    fn matching_is_case_insensitive_on_both_halves() {
        // The comparison every relay decision depends on. Matching raw strings
        // instead is how an open relay gets built.
        let a = Address::parse("dave@example.com").unwrap();
        let b = Address::parse("DAVE@EXAMPLE.COM").unwrap();
        assert!(a.matches(&b));
        assert!(b.matches(&a));

        let other = Address::parse("dave@other.com").unwrap();
        assert!(!a.matches(&other));
    }

    #[test]
    fn recognises_our_own_domains_regardless_of_case() {
        let address = Address::parse("dave@Example.com").unwrap();
        let ours = vec!["EXAMPLE.COM".to_owned()];
        assert!(address.is_local_to(&ours));
        assert!(!address.is_local_to(&["other.com".to_owned()]));
    }

    #[test]
    fn rejects_malformed_addresses() {
        for input in ["", "no-at-sign", "@example.com", "user@", "user@nodot", "user@-bad.com", "user@bad-.com"] {
            assert!(Address::parse(input).is_err(), "accepted {input:?}");
        }
    }

    #[test]
    fn rejects_dot_abuse_in_the_local_part() {
        for input in [".user@example.com", "user.@example.com", "us..er@example.com"] {
            assert_eq!(Address::parse(input).unwrap_err(), AddressError::BadLocal, "accepted {input:?}");
        }
    }

    #[test]
    fn rejects_quoted_local_parts() {
        // A quoted local part may contain @ and spaces; every layer that
        // re-parses it must agree on the unquoting, and a disagreement is a
        // routing bug. Refusing is safer than half-supporting.
        assert_eq!(Address::parse("\"odd@name\"@example.com").unwrap_err(), AddressError::BadLocal);
    }

    #[test]
    fn enforces_length_limits() {
        let long_local = "a".repeat(MAX_LOCAL + 1);
        assert!(Address::parse(&format!("{long_local}@example.com")).is_err());

        let long = format!("{}@{}.com", "a".repeat(60), "b".repeat(200));
        assert_eq!(Address::parse(&long).unwrap_err(), AddressError::TooLong);
    }

    #[test]
    fn parses_the_smtp_path_form() {
        let path = Path::parse("<dave@example.com>").unwrap();
        assert_eq!(path.address().unwrap().local(), "dave");
        assert_eq!(path.to_string(), "<dave@example.com>");
    }

    #[test]
    fn the_null_sender_marks_a_bounce() {
        // A bounce must never be bounced, or two servers generate mail at each
        // other forever.
        let path = Path::parse("<>").unwrap();
        assert!(path.is_null());
        assert!(path.address().is_none());
        assert_eq!(path.to_string(), "<>");
    }

    #[test]
    fn obsolete_source_routes_are_stripped_to_the_final_mailbox() {
        // Source routing was removed from the standard because it enabled
        // relaying through unwitting third parties.
        let path = Path::parse("<@relay1.com,@relay2.com:dave@example.com>").unwrap();
        assert_eq!(path.address().unwrap().to_string(), "dave@example.com");
    }

    #[test]
    fn tolerates_a_path_without_angle_brackets() {
        // Some clients omit them; the address is unambiguous either way.
        assert_eq!(Path::parse("dave@example.com").unwrap().address().unwrap().local(), "dave");
    }
}
