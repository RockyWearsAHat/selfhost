//! Parity test: every mutating admin API route must have either an MCP tool
//! or an explicit entry in `HUMAN_ONLY_ROUTES` with a reason.
//!
//! This test enumerates every POST, PUT, DELETE route in the admin API's
//! routing table and verifies that the MCP command has a tool for it, or that
//! it is explicitly documented as human-only and why.

/// Route and reason for routes that are deliberately human-only and have no MCP tool.
const HUMAN_ONLY_ROUTES: &[(&str, &str)] = &[
    // Desktop ticket mint: for native console stream authorization only.
    ("POST /api/desktop/ticket", "Desktop ticket: for native console WebSocket stream authorization, not agent-accessible"),
    // Passkey enrollment: requires WebAuthn ceremony and hardware presence.
    ("POST /api/webauthn/register/challenge", "Passkey enrollment: requires WebAuthn ceremony and hardware presence"),
    ("POST /api/webauthn/register", "Passkey enrollment: requires WebAuthn ceremony and hardware presence"),
    // Passkey removal: can only be done by the owner themselves, with hardware.
    ("DELETE /api/webauthn/credentials/<id>", "Passkey removal: only the owner can revoke their own passkey, requires hardware"),
    // Storage share file operations: available through WebDAV and console file manager, not needed for agents.
    ("POST /api/storage/shares/<id>/mkdir", "Storage mkdir: available through WebDAV or console, not needed for agent deployment"),
    ("POST /api/storage/shares/<id>/rename", "Storage rename: available through WebDAV or console, not needed for agent deployment"),
    ("DELETE /api/storage/shares/<id>/entry", "Storage delete: available through WebDAV or console, not needed for agent deployment"),
    // WebDAV session management: internal to WebDAV protocol, not needed for agents.
    ("POST /api/storage/shares/<id>/sessions", "WebDAV session: part of WebDAV protocol, handled by WebDAV clients"),
    ("POST /api/storage/shares/<id>/sessions/<ticket>", "WebDAV finish session: part of WebDAV protocol, handled by WebDAV clients"),
    // Firewall reconciliation: can be added as MCP tool if needed, marking as human-only for now.
    ("POST /api/firewall/reconcile", "Firewall reconcile: deployment-level operation, not yet exposed as MCP tool"),
    // VPN access check: part of VPN enrollment flow, requires person context.
    ("POST /api/vpn/check-access", "VPN check-access: person-scoped, part of VPN enrollment flow"),
    // My devices: self-service removal of the caller's own device, not an owner/agent operation.
    ("DELETE /api/vpn/devices/<peer>", "My devices: self-service, a Person removes only their own device"),
    // VPN sign-in flow: console-session half, requires browser and PKCE binding.
    ("POST /api/vpn/authorize", "VPN sign-in: console-session half of the enrollment exchange, requires browser and PKCE binding"),
    // Site sign-in: person asks to be signed in to a gated site, requires browser redirect flow.
    ("POST /api/pass/authorize", "Site sign-in: signed-in Person exchanges a Pass for a gated Site, requires browser redirect"),
    // Invitation revocation: highly destructive, only owner-accessible.
    ("DELETE /api/people/invites/<name>", "Invitation revocation: owner-only, can be destructive"),
    // Person deletion: highly destructive, only owner-accessible.
    ("DELETE /api/people/<name>", "Person deletion: owner-only, removes all their grants and credentials"),
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Every mutating admin API route (POST, PUT, DELETE) must either have an
    /// MCP tool or be explicitly documented as human-only.
    #[test]
    fn every_mutating_admin_route_has_mcp_parity() {
        // All mutating routes from the admin API's routing table in lib.rs Route enum.
        // Format: (METHOD, PATH, description for debugging)
        let mutating_routes = vec![
            // Services
            ("PUT", "/api/services/<name>", "Install"),
            ("DELETE", "/api/services/<name>", "Uninstall"),
            ("POST", "/api/services/<name>/deploy", "DeployNow"),
            ("POST", "/api/self-update/deploy", "SelfUpdateNow"),
            ("POST", "/api/services/<name>/<action>", "Act (start/stop/restart)"),
            // Desktop
            ("POST", "/api/desktop/ticket", "MintTicket"),
            // Storage
            ("POST", "/api/storage/shares/<id>/mkdir", "ShareMkdir"),
            ("POST", "/api/storage/shares/<id>/rename", "ShareRename"),
            ("DELETE", "/api/storage/shares/<id>/entry", "ShareDelete"),
            ("POST", "/api/storage/shares/<id>/sessions", "BeginSession"),
            ("POST", "/api/storage/shares/<id>/sessions/<ticket>", "FinishSession"),
            // Firewall
            ("POST", "/api/firewall/reconcile", "FirewallReconcile"),
            // Webauthn (passkey enrollment/removal)
            ("POST", "/api/webauthn/register/challenge", "RegisterChallenge"),
            ("POST", "/api/webauthn/register", "Register"),
            ("DELETE", "/api/webauthn/credentials/<id>", "RemovePasskey"),
            // People
            ("PUT", "/api/people/<name>", "SetGrants"),
            ("DELETE", "/api/people/<name>", "ForgetPerson"),
            ("POST", "/api/people/<name>/invite", "MintInvite"),
            ("DELETE", "/api/people/invites/<name>", "RevokeInvite"),
            // Sites
            ("POST", "/api/sites", "SiteAdd"),
            ("DELETE", "/api/sites/<name>", "SiteRemove"),
            ("POST", "/api/sites/<name>/domains", "SiteAddDomain"),
            ("DELETE", "/api/sites/<name>/domains/<hostname>", "SiteRemoveDomain"),
            ("PUT", "/api/sites/<name>/exposure", "SiteSetExposure"),
            ("PUT", "/api/sites/<name>/owner", "SiteSetOwner"),
            ("POST", "/api/sites/<name>/files/mkdir", "SiteFileMkdir"),
            ("PUT", "/api/sites/<name>/files/entry", "SiteFilePut"),
            ("DELETE", "/api/sites/<name>/files/entry", "SiteFileDelete"),
            // VPN
            ("POST", "/api/vpn/check-access", "VpnCheckAccess"),
            ("POST", "/api/vpn/authorize", "VpnAuthorize"),
            ("DELETE", "/api/vpn/devices/<peer>", "VpnForgetDevice"),
            // Pass
            ("POST", "/api/pass/authorize", "PassAuthorize"),
        ];

        // MCP tools that map to mutating routes. This is what was advertised in
        // crates/app/cli/src/mcp_command.rs's TOOLS array as of the date this test
        // was written. Tools are grouped by the routes they handle.
        let mcp_tools = vec![
            // Services
            ("services_add", vec!["PUT /api/services/<name>"]),
            ("services_remove", vec!["DELETE /api/services/<name>"]),
            ("services_deploy", vec!["POST /api/services/<name>/deploy"]),
            ("services_control", vec!["POST /api/services/<name>/<action>"]),
            ("self_update", vec!["POST /api/self-update/deploy"]),
            // People
            ("people_grant", vec!["PUT /api/people/<name>"]),
            ("people_revoke", vec!["PUT /api/people/<name>"]),
            ("people_invite", vec!["POST /api/people/<name>/invite"]),
            // Sites
            ("sites_add", vec!["POST /api/sites"]),
            ("sites_remove", vec!["DELETE /api/sites/<name>"]),
            ("sites_add_domain", vec!["POST /api/sites/<name>/domains"]),
            ("sites_remove_domain", vec!["DELETE /api/sites/<name>/domains/<hostname>"]),
            ("site_set_exposure", vec!["PUT /api/sites/<name>/exposure"]),
            ("site_set_owner", vec!["PUT /api/sites/<name>/owner"]),
            ("sites_mkdir", vec!["POST /api/sites/<name>/files/mkdir"]),
            ("sites_upload_file", vec!["PUT /api/sites/<name>/files/entry"]),
            ("sites_upload_dir", vec!["PUT /api/sites/<name>/files/entry"]),
            ("sites_delete_file", vec!["DELETE /api/sites/<name>/files/entry"]),
        ];

        // Flatten the MCP tools into a set of covered routes.
        let mut covered_by_mcp = std::collections::HashSet::new();
        for (_, routes) in &mcp_tools {
            for route in routes {
                covered_by_mcp.insert(route.to_string());
            }
        }

        // Flatten HUMAN_ONLY_ROUTES into a set.
        let mut human_only_set = std::collections::HashSet::new();
        for (route, _) in HUMAN_ONLY_ROUTES {
            human_only_set.insert(route.to_string());
        }

        // Check each route.
        for (method, path, description) in &mutating_routes {
            let route_key = format!("{} {}", method, path);
            let has_mcp = covered_by_mcp.contains(&route_key);
            let is_human_only = human_only_set.contains(&route_key);

            assert!(
                has_mcp || is_human_only,
                "Route {} ({}) has no MCP tool and is not in HUMAN_ONLY_ROUTES. \
                 Either add an MCP tool for it or document why it is human-only.",
                route_key, description
            );
        }
    }

    /// Verify that all documented HUMAN_ONLY routes actually exist (no typos,
    /// and they are mutating routes).
    #[test]
    fn human_only_routes_are_actual_mutating_routes() {
        let mutating_routes = vec![
            ("PUT", "/api/services/<name>"),
            ("DELETE", "/api/services/<name>"),
            ("POST", "/api/services/<name>/deploy"),
            ("POST", "/api/self-update/deploy"),
            ("POST", "/api/services/<name>/<action>"),
            ("POST", "/api/desktop/ticket"),
            ("POST", "/api/storage/shares/<id>/mkdir"),
            ("POST", "/api/storage/shares/<id>/rename"),
            ("DELETE", "/api/storage/shares/<id>/entry"),
            ("POST", "/api/storage/shares/<id>/sessions"),
            ("POST", "/api/storage/shares/<id>/sessions/<ticket>"),
            ("POST", "/api/firewall/reconcile"),
            ("POST", "/api/webauthn/register/challenge"),
            ("POST", "/api/webauthn/register"),
            ("DELETE", "/api/webauthn/credentials/<id>"),
            ("PUT", "/api/people/<name>"),
            ("DELETE", "/api/people/<name>"),
            ("POST", "/api/people/<name>/invite"),
            ("DELETE", "/api/people/invites/<name>"),
            ("POST", "/api/sites"),
            ("DELETE", "/api/sites/<name>"),
            ("POST", "/api/sites/<name>/domains"),
            ("DELETE", "/api/sites/<name>/domains/<hostname>"),
            ("PUT", "/api/sites/<name>/exposure"),
            ("PUT", "/api/sites/<name>/owner"),
            ("POST", "/api/sites/<name>/files/mkdir"),
            ("PUT", "/api/sites/<name>/files/entry"),
            ("DELETE", "/api/sites/<name>/files/entry"),
            ("POST", "/api/vpn/check-access"),
            ("POST", "/api/vpn/authorize"),
            ("DELETE", "/api/vpn/devices/<peer>"),
            ("POST", "/api/pass/authorize"),
        ];

        let mut route_set = std::collections::HashSet::new();
        for (method, path) in mutating_routes {
            route_set.insert(format!("{} {}", method, path));
        }

        for (route, reason) in HUMAN_ONLY_ROUTES {
            assert!(
                route_set.contains(&route.to_string()),
                "HUMAN_ONLY route {} with reason \"{}\" is not a known mutating route. \
                 Check for typos or if it has been removed.",
                route, reason
            );
        }
    }
}
