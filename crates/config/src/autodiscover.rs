//! Naming for Exchange Autodiscover, EWS, and ActiveSync — the paths and host
//! macOS/iOS Mail actually drive an account through, once configured.
//!
//! This module is naming only, the same split [`crate::pacc`] uses: a single
//! host and a fixed set of paths, defined once here so [`crate::mail::Mail::client_hosts`]
//! (which needs the host, for DNS and certificates), the proxy (which needs
//! the host and paths, to route requests), and `selfhost-mail`'s protocol
//! logic (which needs the paths, to build URLs into its own responses) read
//! the same constants rather than three copies of the same three strings.
//!
//! One host carries all three protocols — Autodiscover, EWS, and
//! ActiveSync — rather than one apiece, so a mail domain gains exactly one
//! extra `A` record and one extra name on its certificate for the whole
//! zero-touch account-setup path, the same cost PACC's own host already is.

/// The label prefixed to the mail domain to reach Autodiscover, EWS, and
/// ActiveSync.
pub const HOST_PREFIX: &str = "autodiscover";

/// The hostname a client reaches Autodiscover, EWS, and ActiveSync at for
/// `domain`.
///
/// One name per mail domain — it joins [`crate::mail::Mail::client_hosts`],
/// so it gets an `A` record and a certificate for free rather than by a
/// second rule, exactly as [`crate::pacc::host`] does for its own host.
pub fn host(domain: &str) -> String {
    format!("{HOST_PREFIX}.{domain}")
}

/// The path Microsoft Autodiscover's XML request/response is served at.
///
/// Mail clients POST here on both `autodiscover.<domain>` and the bare mail
/// domain itself — Apple Mail tries both — so the proxy checks this path
/// against either host, not only [`host`]'s.
pub const XML_PATH: &str = "/autodiscover/autodiscover.xml";

/// The path Exchange Web Services is served at, on [`host`].
pub const EWS_PATH: &str = "/EWS/Exchange.asmx";

/// The path Exchange ActiveSync is served at, on [`host`].
pub const ACTIVESYNC_PATH: &str = "/Microsoft-Server-ActiveSync";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_is_one_label_under_the_mail_domain() {
        assert_eq!(host("example.com"), "autodiscover.example.com");
    }
}
