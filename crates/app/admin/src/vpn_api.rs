//! VPN access control and location-based permission checking.
//!
//! Users can be granted access to specific VPN locations (e.g., "us-east-1").
//! The check-access endpoint verifies whether a user is permitted to connect to
//! a given location.

use selfhost_http::{Response, Status};
use selfhost_json::Json;
use selfhost_identity::{Capability, Credential, Identity, People, Policy, PersonName, VpnLocationId};

/// Checks if a user has access to a specific VPN location.
///
/// Returns a JSON response with `allowed` field and optional `reason` if denied.
pub fn check_access(
    people: Option<&People>,
    vpn: Option<&crate::people_api::VpnWiring>,
    body: &[u8],
) -> Response {
    // Parse request body
    let text = match std::str::from_utf8(body) {
        Ok(t) => t,
        Err(_) => return problem(Status(400), "invalid UTF-8 in body"),
    };

    let json = match selfhost_json::parse(text) {
        Ok(j) => j,
        Err(_) => return problem(Status(400), "invalid JSON body"),
    };

    let user_id = match json.get("user_id").and_then(|v| v.as_str()) {
        Some(uid) => uid,
        None => return problem(Status(400), "missing or invalid user_id"),
    };

    let location_id = match json.get("location_id").and_then(|v| v.as_str()) {
        Some(lid) => lid,
        None => return problem(Status(400), "missing or invalid location_id"),
    };

    // Check if people registry exists
    let Some(people) = people else {
        return json_response(Status(200), Json::object([
            ("allowed", Json::Bool(false)),
            ("reason", Json::String("no permission registry".to_string())),
        ]));
    };

    // A relay asks about whoever connected, and names them by their Peer —
    // the device. Access is a Person's, so the Peer is resolved to its Person
    // first. A Peer nobody enrolled, or one since forgotten, is nobody.
    let person = match vpn {
        Some(vpn) => match vpn.person_of_peer(user_id) {
            Some(person) => person,
            None => {
                return json_response(Status(200), Json::object([
                    ("allowed", Json::Bool(false)),
                    ("reason", Json::String("unknown device".to_string())),
                ]));
            }
        },
        None => user_id.to_owned(),
    };
    let user_id = person.as_str();

    // Look up the user
    let Ok(name) = PersonName::parse(user_id) else {
        return json_response(Status(200), Json::object([
            ("allowed", Json::Bool(false)),
            ("reason", Json::String("invalid user_id".to_string())),
        ]));
    };

    // Check if user exists
    if people.find(&name).is_none() {
        return json_response(Status(200), Json::object([
            ("allowed", Json::Bool(false)),
            ("reason", Json::String("user not found".to_string())),
        ]));
    }

    // A location that fails its own grammar can never have been granted —
    // same reasoning as an invalid user_id above.
    let Ok(location) = VpnLocationId::parse(location_id) else {
        return json_response(Status(200), Json::object([
            ("allowed", Json::Bool(false)),
            ("reason", Json::String("invalid location_id".to_string())),
        ]));
    };

    // Every access decision goes through `Policy::decide`, never a direct
    // `.grants.holds()` — the same seam `crates/app/proxy/src/pass_gate.rs`
    // uses, and the fix for the named bug: before this, an owner (no Person
    // entry at all) was refused here outright, because this function looked
    // only in the People registry. A Person who holds `Capability::Owner` is
    // now allowed any location through the ordinary grants rule (`Grants::holds`,
    // extended in `crate::policy::satisfies`), the same door as everyone else.
    let caller = people.caller(Identity::Person(name), Credential::Passkey);
    let has_access = Policy::locked_down().decide(&caller, &Capability::VpnAccess(location)).is_allowed();

    if has_access {
        json_response(
            Status(200),
            Json::object([("allowed", Json::Bool(true))]),
        )
    } else {
        json_response(
            Status(200),
            Json::object([
                ("allowed", Json::Bool(false)),
                ("reason", Json::String("access denied".to_string())),
            ]),
        )
    }
}

/// Returns a JSON error response with the given status and message.
fn problem(status: Status, message: &str) -> Response {
    json_response(
        status,
        Json::object([("error", Json::String(message.to_string()))]),
    )
}

/// Returns a JSON response with the given status and body.
fn json_response(status: Status, body: Json) -> Response {
    let bytes = body.to_text().into_bytes();
    Response::bytes(status, "application/json; charset=utf-8", bytes)
        .unwrap_or_else(|_| Response::empty(Status(500)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use selfhost_http::Body;
    use selfhost_identity::{Grants, People};
    use std::path::PathBuf;

    /// A scratch directory unique to one test.
    ///
    /// Named per test rather than per process: tests run concurrently, and a
    /// shared directory means one test deletes the file another is asserting on.
    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join(format!("selfhost-vpn-api-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    fn allowed(response: &Response) -> bool {
        let Body::Bytes(bytes) = &response.body else {
            panic!("expected a bytes body");
        };
        let json = selfhost_json::parse(std::str::from_utf8(bytes).unwrap()).unwrap();
        json.get("allowed").and_then(|v| v.as_bool()).expect("an allowed field")
    }

    #[test]
    fn test_check_access_missing_user_id() {
        let response = check_access(None, None, b"{}");
        assert_eq!(response.status.0, 400);
    }

    #[test]
    fn test_check_access_no_registry() {
        let response = check_access(None, None, b"{\"user_id\":\"test\",\"location_id\":\"us-east-1\"}");
        assert_eq!(response.status.0, 200);
        assert!(!allowed(&response), "no registry means nobody is allowed");
    }

    #[test]
    fn an_unknown_user_is_denied() {
        let people = People::load(&scratch("unknown-user"));
        let response =
            check_access(Some(&people), None, br#"{"user_id":"nobody","location_id":"console"}"#);
        assert!(!allowed(&response));
    }

    /// A relay names whoever connected by their Peer, never by their Person.
    #[test]
    fn a_peer_is_answered_as_the_person_it_belongs_to() {
        let dir = scratch("peer-to-person");
        let people = People::load(&dir);
        let grants = Grants::new([Capability::VpnAccess(
            selfhost_identity::VpnLocationId::parse("console").unwrap(),
        )])
        .unwrap();
        people.set_grants(&PersonName::parse("alex").unwrap(), grants).expect("register alex");
        selfhost_vpn::peer_binding::bind(&dir, "alex-laptop", "alex").expect("bind the peer");
        let vpn = crate::people_api::VpnWiring::new(Vec::new(), dir);

        let body = br#"{"user_id":"alex-laptop","location_id":"console"}"#;
        assert!(allowed(&check_access(Some(&people), Some(&vpn), body)));
        assert!(!allowed(&check_access(Some(&people), None, body)), "unresolved, a Peer is nobody");
    }

    #[test]
    fn a_forgotten_device_is_cut_off_and_a_person_name_is_not_a_device() {
        let dir = scratch("forgotten-device");
        let people = People::load(&dir);
        people
            .set_grants(&PersonName::parse("alex").unwrap(), Grants::new([Capability::Owner]).unwrap())
            .expect("register alex");
        selfhost_vpn::peer_binding::bind(&dir, "alex-laptop", "alex").expect("bind the peer");
        let vpn = crate::people_api::VpnWiring::new(Vec::new(), dir);

        let body = br#"{"user_id":"alex-laptop","location_id":"console"}"#;
        assert!(allowed(&check_access(Some(&people), Some(&vpn), body)));
        vpn.forget_device("mom", "alex-laptop").expect_err("not mom's to forget");
        vpn.forget_device("alex", "alex-laptop").expect("forget it");
        assert!(!allowed(&check_access(Some(&people), Some(&vpn), body)));
        let by_name = br#"{"user_id":"alex","location_id":"console"}"#;
        assert!(!allowed(&check_access(Some(&people), Some(&vpn), by_name)));
    }

    #[test]
    fn a_registered_user_with_no_vpn_grant_is_denied() {
        let people = People::load(&scratch("no-grant"));
        people
            .set_grants(&PersonName::parse("alex").unwrap(), Grants::none())
            .expect("register alex");
        let response =
            check_access(Some(&people), None, br#"{"user_id":"alex","location_id":"console"}"#);
        assert!(!allowed(&response), "no vpn.access grant must not open the door");
    }

    #[test]
    fn a_user_granted_a_different_location_is_still_denied() {
        let people = People::load(&scratch("wrong-location"));
        let grants = Grants::new([Capability::VpnAccess(
            selfhost_identity::VpnLocationId::parse("ai-studio").unwrap(),
        )])
        .unwrap();
        people.set_grants(&PersonName::parse("alex").unwrap(), grants).expect("register alex");
        let response =
            check_access(Some(&people), None, br#"{"user_id":"alex","location_id":"console"}"#);
        assert!(!allowed(&response), "a grant for one location must not open another");
    }

    #[test]
    fn a_user_granted_the_exact_location_is_allowed() {
        let people = People::load(&scratch("exact-location"));
        let grants = Grants::new([Capability::VpnAccess(
            selfhost_identity::VpnLocationId::parse("console").unwrap(),
        )])
        .unwrap();
        people.set_grants(&PersonName::parse("alex").unwrap(), grants).expect("register alex");
        let response =
            check_access(Some(&people), None, br#"{"user_id":"alex","location_id":"console"}"#);
        assert!(allowed(&response));
    }

    #[test]
    fn an_owner_is_allowed_any_vpn_location_with_no_explicit_vpn_grant() {
        // The named bug: an owner is a Person who holds `Capability::Owner`,
        // not `Capability::VpnAccess(..)` for any particular location. Before
        // routing this endpoint through `Policy::decide`, such a Person was
        // refused their own VPN because this function looked for the exact
        // location grant and found none.
        let people = People::load(&scratch("owner-any-location"));
        let owner_grants = Grants::new([Capability::Owner]).unwrap();
        people.set_grants(&PersonName::parse("alex").unwrap(), owner_grants).expect("register alex");
        let response =
            check_access(Some(&people), None, br#"{"user_id":"alex","location_id":"ai-studio"}"#);
        assert!(allowed(&response), "a holder of Capability::Owner is allowed any location");
    }
}
