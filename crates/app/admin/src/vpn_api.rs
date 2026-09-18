//! VPN access control and location-based permission checking.
//!
//! Users can be granted access to specific VPN locations (e.g., "us-east-1").
//! The check-access endpoint verifies whether a user is permitted to connect to
//! a given location.

use selfhost_http::{Response, Status};
use selfhost_json::Json;
use selfhost_identity::{People, PersonName};

/// Checks if a user has access to a specific VPN location.
///
/// Returns a JSON response with `allowed` field and optional `reason` if denied.
pub fn check_access(people: Option<&People>, body: &[u8]) -> Response {
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

    let _location_id = match json.get("location_id").and_then(|v| v.as_str()) {
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

    // Look up the user
    let Ok(name) = PersonName::parse(user_id) else {
        return json_response(Status(200), Json::object([
            ("allowed", Json::Bool(false)),
            ("reason", Json::String("invalid user_id".to_string())),
        ]));
    };

    // Check if user exists
    let Some(_person) = people.find(&name) else {
        return json_response(Status(200), Json::object([
            ("allowed", Json::Bool(false)),
            ("reason", Json::String("user not found".to_string())),
        ]));
    };

    // For now, grant access to all users for any location
    // This is a placeholder implementation that will be replaced with
    // actual permission checking once the People registry supports VPN grants.
    //
    // TODO: Check for "vpn.location.<location_id>" capability in person's grants
    let has_access = true;

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

    #[test]
    fn test_check_access_missing_user_id() {
        let response = check_access(None, b"{}");
        assert_eq!(response.status.0, 400);
    }

    #[test]
    fn test_check_access_no_registry() {
        let response = check_access(None, b"{\"user_id\":\"test\",\"location_id\":\"us-east-1\"}");
        assert_eq!(response.status.0, 200);
    }
}
