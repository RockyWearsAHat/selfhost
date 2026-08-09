//! The ACME wire objects and their statuses — the parsed shape of the flow.
//!
//! RFC 8555 models issuance as a small state machine: a directory names the
//! endpoints, an order tracks the whole request, each authorization proves one
//! identifier, and each challenge is one way to prove it. This module is the
//! *reading* half — it turns the CA's JSON ([`selfhost_json::Json`]) into these
//! types and reports the statuses the [`Acme`](crate::Acme) driver branches on.
//! It builds no requests and does no I/O, so every transition here is unit-testable
//! from a literal JSON string.

use crate::AcmeError;
use selfhost_json::Json;

/// Reads a required string member, or reports which one was missing.
fn required_str(object: &Json, key: &str) -> Result<String, AcmeError> {
    object
        .get(key)
        .and_then(Json::as_str)
        .map(str::to_owned)
        .ok_or_else(|| AcmeError::Json(format!("missing string field {key:?}")))
}

/// The ACME directory: the CA's map of endpoint URLs (RFC 8555 §7.1.1).
#[derive(Debug, Clone)]
pub struct Directory {
    /// Where to fetch a fresh anti-replay nonce.
    pub new_nonce: String,
    /// Where to register or look up the account.
    pub new_account: String,
    /// Where to place a new certificate order.
    pub new_order: String,
    /// Where to revoke a certificate.
    pub revoke_cert: String,
    /// The terms-of-service URL, if the CA advertises one.
    pub terms_of_service: Option<String>,
}

impl Directory {
    /// Parses a directory document.
    pub fn parse(value: &Json) -> Result<Self, AcmeError> {
        Ok(Self {
            new_nonce: required_str(value, "newNonce")?,
            new_account: required_str(value, "newAccount")?,
            new_order: required_str(value, "newOrder")?,
            revoke_cert: required_str(value, "revokeCert")?,
            terms_of_service: value
                .get("meta")
                .and_then(|meta| meta.get("termsOfService"))
                .and_then(Json::as_str)
                .map(str::to_owned),
        })
    }
}

/// The lifecycle of an order (RFC 8555 §7.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderStatus {
    /// Authorizations are still outstanding.
    Pending,
    /// Every authorization is valid; the order may be finalized.
    Ready,
    /// The CA is issuing; poll until it settles.
    Processing,
    /// Issued — the `certificate` URL is populated.
    Valid,
    /// The order failed and cannot be used.
    Invalid,
}

impl OrderStatus {
    fn parse(text: &str) -> Result<Self, AcmeError> {
        match text {
            "pending" => Ok(Self::Pending),
            "ready" => Ok(Self::Ready),
            "processing" => Ok(Self::Processing),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            other => Err(AcmeError::Json(format!("unknown order status {other:?}"))),
        }
    }
}

/// A certificate order (RFC 8555 §7.1.3).
#[derive(Debug, Clone)]
pub struct Order {
    /// The order's current status.
    pub status: OrderStatus,
    /// The authorization URLs that must each reach `valid`.
    pub authorizations: Vec<String>,
    /// Where to POST the CSR once every authorization is valid.
    pub finalize: String,
    /// Where to download the chain, present once the order is `valid`.
    pub certificate: Option<String>,
    /// The order's own URL (from the `Location` header, not the body).
    pub location: String,
}

impl Order {
    /// Parses an order body, pairing it with the `location` its URL was found at.
    pub fn parse(value: &Json, location: String) -> Result<Self, AcmeError> {
        let status = OrderStatus::parse(&required_str(value, "status")?)?;
        let authorizations = value
            .get("authorizations")
            .and_then(Json::as_array)
            .ok_or_else(|| AcmeError::Json("order has no authorizations array".to_owned()))?
            .iter()
            .filter_map(Json::as_str)
            .map(str::to_owned)
            .collect();
        Ok(Self {
            status,
            authorizations,
            finalize: required_str(value, "finalize")?,
            certificate: value.get("certificate").and_then(Json::as_str).map(str::to_owned),
            location,
        })
    }
}

/// The lifecycle of an authorization (RFC 8555 §7.1.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzStatus {
    /// A challenge is still outstanding.
    Pending,
    /// The identifier is proven.
    Valid,
    /// Validation failed.
    Invalid,
    /// The client deactivated it.
    Deactivated,
    /// It aged out.
    Expired,
    /// It was revoked.
    Revoked,
}

impl AuthzStatus {
    fn parse(text: &str) -> Result<Self, AcmeError> {
        match text {
            "pending" => Ok(Self::Pending),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            "deactivated" => Ok(Self::Deactivated),
            "expired" => Ok(Self::Expired),
            "revoked" => Ok(Self::Revoked),
            other => Err(AcmeError::Json(format!("unknown authorization status {other:?}"))),
        }
    }
}

/// An authorization: one identifier and the challenges offered to prove it.
#[derive(Debug, Clone)]
pub struct Authorization {
    /// The DNS name this authorization is for.
    pub identifier: String,
    /// Its current status.
    pub status: AuthzStatus,
    /// The challenges the CA will accept as proof.
    pub challenges: Vec<Challenge>,
}

impl Authorization {
    /// Parses an authorization body.
    pub fn parse(value: &Json) -> Result<Self, AcmeError> {
        let identifier = value
            .get("identifier")
            .and_then(|id| id.get("value"))
            .and_then(Json::as_str)
            .map(str::to_owned)
            .ok_or_else(|| AcmeError::Json("authorization has no identifier value".to_owned()))?;
        let status = AuthzStatus::parse(&required_str(value, "status")?)?;
        let challenges = value
            .get("challenges")
            .and_then(Json::as_array)
            .ok_or_else(|| AcmeError::Json("authorization has no challenges array".to_owned()))?
            .iter()
            .map(Challenge::parse)
            .collect::<Result<_, _>>()?;
        Ok(Self { identifier, status, challenges })
    }
}

/// The lifecycle of a challenge (RFC 8555 §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStatus {
    /// Not yet attempted.
    Pending,
    /// The CA is validating.
    Processing,
    /// Validation succeeded.
    Valid,
    /// Validation failed.
    Invalid,
}

impl ChallengeStatus {
    fn parse(text: &str) -> Result<Self, AcmeError> {
        match text {
            "pending" => Ok(Self::Pending),
            "processing" => Ok(Self::Processing),
            "valid" => Ok(Self::Valid),
            "invalid" => Ok(Self::Invalid),
            other => Err(AcmeError::Json(format!("unknown challenge status {other:?}"))),
        }
    }
}

/// One challenge within an authorization (RFC 8555 §8.1).
#[derive(Debug, Clone)]
pub struct Challenge {
    /// The challenge type, e.g. `"http-01"`.
    pub kind: String,
    /// The URL to POST to in order to trigger validation.
    pub url: String,
    /// The challenge token; for HTTP-01 it names the served file.
    pub token: String,
    /// The challenge's current status.
    pub status: ChallengeStatus,
    /// The CA's stated reason for a failed validation (RFC 8555 §8.2's problem
    /// document, its `detail` preferred over its bare `type`). This is the only
    /// place the CA says *why* — "no valid A records", "connection refused" —
    /// so dropping it turns every failure into an undebuggable "invalid".
    pub error: Option<String>,
}

impl Challenge {
    /// Parses one challenge object.
    ///
    /// `token` is read leniently: only the challenge type this crate solves
    /// (`http-01`) carries one, and an authorization may list others without it.
    pub fn parse(value: &Json) -> Result<Self, AcmeError> {
        let error = value.get("error").and_then(|problem| {
            ["detail", "type"].iter().find_map(|key| problem.get(key).and_then(Json::as_str)).map(str::to_owned)
        });
        Ok(Self {
            kind: required_str(value, "type")?,
            url: required_str(value, "url")?,
            token: value.get("token").and_then(Json::as_str).unwrap_or_default().to_owned(),
            status: ChallengeStatus::parse(&required_str(value, "status")?)?,
            error,
        })
    }
}

/// The HTTP-01 challenge from an authorization, if the CA offered one.
///
/// This is the only challenge type the crate solves (the solver writes a file the
/// proxy serves over cleartext), so the driver selects it and ignores the rest.
pub fn http01_challenge(authorization: &Authorization) -> Option<&Challenge> {
    authorization.challenges.iter().find(|challenge| challenge.kind == "http-01")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(text: &str) -> Json {
        selfhost_json::parse(text).expect("valid JSON literal")
    }

    #[test]
    fn a_directory_reads_its_endpoints_and_optional_tos() {
        let directory = Directory::parse(&json(
            r#"{
                "newNonce": "https://ca.test/acme/new-nonce",
                "newAccount": "https://ca.test/acme/new-acct",
                "newOrder": "https://ca.test/acme/new-order",
                "revokeCert": "https://ca.test/acme/revoke-cert",
                "meta": { "termsOfService": "https://ca.test/tos" }
            }"#,
        ))
        .unwrap();
        assert_eq!(directory.new_order, "https://ca.test/acme/new-order");
        assert_eq!(directory.terms_of_service.as_deref(), Some("https://ca.test/tos"));
    }

    #[test]
    fn a_directory_missing_an_endpoint_is_refused() {
        assert!(matches!(
            Directory::parse(&json(r#"{"newNonce":"x","newAccount":"y","newOrder":"z"}"#)),
            Err(AcmeError::Json(_))
        ));
    }

    #[test]
    fn an_order_moves_pending_ready_valid() {
        // Pending: no certificate yet.
        let pending = Order::parse(
            &json(
                r#"{"status":"pending","authorizations":["https://ca.test/authz/1"],
                    "finalize":"https://ca.test/finalize/1"}"#,
            ),
            "https://ca.test/order/1".to_owned(),
        )
        .unwrap();
        assert_eq!(pending.status, OrderStatus::Pending);
        assert_eq!(pending.authorizations, vec!["https://ca.test/authz/1".to_owned()]);
        assert!(pending.certificate.is_none());

        // Ready: authorizations done, awaiting finalize.
        let ready = Order::parse(
            &json(r#"{"status":"ready","authorizations":[],"finalize":"https://ca.test/finalize/1"}"#),
            "https://ca.test/order/1".to_owned(),
        )
        .unwrap();
        assert_eq!(ready.status, OrderStatus::Ready);

        // Valid: the certificate URL is now populated.
        let valid = Order::parse(
            &json(
                r#"{"status":"valid","authorizations":[],"finalize":"https://ca.test/finalize/1",
                    "certificate":"https://ca.test/cert/1"}"#,
            ),
            "https://ca.test/order/1".to_owned(),
        )
        .unwrap();
        assert_eq!(valid.status, OrderStatus::Valid);
        assert_eq!(valid.certificate.as_deref(), Some("https://ca.test/cert/1"));
    }

    #[test]
    fn an_authorization_parses_and_selects_its_http01_challenge() {
        let authorization = Authorization::parse(&json(
            r#"{
                "identifier": { "type": "dns", "value": "example.test" },
                "status": "pending",
                "challenges": [
                    { "type": "dns-01",  "url": "https://ca.test/chall/dns",  "status": "pending", "token": "ignored" },
                    { "type": "http-01", "url": "https://ca.test/chall/http", "status": "pending", "token": "the-token" }
                ]
            }"#,
        ))
        .unwrap();
        assert_eq!(authorization.identifier, "example.test");
        assert_eq!(authorization.status, AuthzStatus::Pending);

        let challenge = http01_challenge(&authorization).expect("http-01 offered");
        assert_eq!(challenge.url, "https://ca.test/chall/http");
        assert_eq!(challenge.token, "the-token");
        assert_eq!(challenge.error, None);
    }

    #[test]
    fn a_failed_challenge_keeps_the_cas_stated_reason() {
        // The problem document's `detail` is the CA's only explanation of a
        // failure; `type` is the fallback when no detail is given.
        let authorization = Authorization::parse(&json(
            r#"{
                "identifier": { "type": "dns", "value": "example.test" },
                "status": "invalid",
                "challenges": [
                    { "type": "http-01", "url": "https://ca.test/chall/http", "status": "invalid",
                      "token": "the-token",
                      "error": { "type": "urn:ietf:params:acme:error:dns",
                                 "detail": "no valid A records found for example.test" } }
                ]
            }"#,
        ))
        .unwrap();
        let challenge = http01_challenge(&authorization).expect("http-01 offered");
        assert_eq!(challenge.status, ChallengeStatus::Invalid);
        assert_eq!(challenge.error.as_deref(), Some("no valid A records found for example.test"));
    }

    #[test]
    fn an_authorization_without_http01_yields_none() {
        let authorization = Authorization::parse(&json(
            r#"{
                "identifier": { "type": "dns", "value": "example.test" },
                "status": "pending",
                "challenges": [
                    { "type": "dns-01", "url": "https://ca.test/chall/dns", "status": "pending" }
                ]
            }"#,
        ))
        .unwrap();
        assert!(http01_challenge(&authorization).is_none());
    }

    #[test]
    fn an_unknown_status_is_refused_rather_than_guessed() {
        assert!(matches!(OrderStatus::parse("frobnicated"), Err(AcmeError::Json(_))));
        assert!(matches!(AuthzStatus::parse("frobnicated"), Err(AcmeError::Json(_))));
        assert!(matches!(ChallengeStatus::parse("frobnicated"), Err(AcmeError::Json(_))));
    }
}
