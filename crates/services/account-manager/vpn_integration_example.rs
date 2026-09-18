// Example: VPN Service Integration with Account Manager
// Add this to: crates/services/vpn/src/lib.rs or similar

use reqwest::Client;
use serde::{Deserialize, Serialize};

/// VPN Access Request to Account Manager
#[derive(Debug, Serialize)]
struct VpnAccessRequest {
    user_id: String,
    location_id: String,
    ip_address: Option<String>,
}

/// VPN Access Response from Account Manager
#[derive(Debug, Deserialize)]
struct VpnAccessResponse {
    allowed: bool,
    reason: String,
    user_name: Option<String>,
    session_timeout: Option<i64>, // seconds
}

/// VPN Permission Checker
pub struct VpnPermissionChecker {
    account_manager_url: String,
    http_client: Client,
}

impl VpnPermissionChecker {
    /// Create new permission checker
    pub fn new(account_manager_url: &str) -> Self {
        Self {
            account_manager_url: account_manager_url.to_string(),
            http_client: Client::new(),
        }
    }

    /// Check if user has access to VPN location
    /// This is called when a client initiates a VPN connection
    pub async fn check_access(
        &self,
        user_id: &str,
        location_id: &str,
        client_ip: Option<&str>,
    ) -> Result<VpnAccessDecision, Box<dyn std::error::Error>> {
        let request = VpnAccessRequest {
            user_id: user_id.to_string(),
            location_id: location_id.to_string(),
            ip_address: client_ip.map(String::from),
        };

        let response = self.http_client
            .post(&format!("{}/api/vpn/check-access", self.account_manager_url))
            .json(&request)
            .send()
            .await?;

        let access_response: VpnAccessResponse = response.json().await?;

        Ok(VpnAccessDecision {
            allowed: access_response.allowed,
            reason: access_response.reason,
            session_timeout: access_response.session_timeout.unwrap_or(86400),
        })
    }

    /// Check if user has permission to perform an action
    pub async fn check_permission(
        &self,
        user_id: &str,
        permission: &str,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let response = self.http_client
            .get(&format!(
                "{}/api/users/{}/permissions/{}",
                self.account_manager_url, user_id, permission
            ))
            .send()
            .await?;

        Ok(response.status().is_success())
    }
}

pub struct VpnAccessDecision {
    pub allowed: bool,
    pub reason: String,
    pub session_timeout: i64,
}

/// Example: VPN Server Integration
/// This shows how to integrate the permission check into your VPN server
pub mod server_example {
    use super::*;

    /// VPN Client Connection Handler
    pub struct VpnConnectionHandler {
        permissions: VpnPermissionChecker,
    }

    impl VpnConnectionHandler {
        pub fn new(account_manager_url: &str) -> Self {
            Self {
                permissions: VpnPermissionChecker::new(account_manager_url),
            }
        }

        /// Handle incoming VPN connection
        /// Called when a client connects to the VPN server
        pub async fn handle_connection(
            &self,
            client_id: &str,
            location_id: &str,
            client_ip: &str,
        ) -> Result<bool, Box<dyn std::error::Error>> {
            // Step 1: Check permissions
            let decision = self.permissions
                .check_access(client_id, location_id, Some(client_ip))
                .await?;

            // Step 2: Log the access attempt
            if decision.allowed {
                println!("✓ Access GRANTED for {} to {}", client_id, location_id);
                // Open tunnel
                self.open_tunnel(client_id, location_id, decision.session_timeout).await?;
            } else {
                println!("✗ Access DENIED for {} to {}: {}", client_id, location_id, decision.reason);
                // Reject connection
            }

            Ok(decision.allowed)
        }

        /// Open VPN tunnel (placeholder)
        async fn open_tunnel(
            &self,
            client_id: &str,
            location_id: &str,
            timeout_seconds: i64,
        ) -> Result<(), Box<dyn std::error::Error>> {
            // TODO: Implement actual tunnel opening
            println!(
                "Opening tunnel for {} to {} (timeout: {}s)",
                client_id, location_id, timeout_seconds
            );
            Ok(())
        }
    }
}

/// Example: Python/Async Integration (for server.py)
/// ```python
/// import asyncio
/// import httpx
///
/// class VpnAccessValidator:
///     def __init__(self, account_manager_url):
///         self.account_manager_url = account_manager_url
///         self.client = httpx.AsyncClient()
///
///     async def check_vpn_access(self, user_id, location_id, client_ip=None):
///         """Check if user can access VPN location"""
///         response = await self.client.post(
///             f"{self.account_manager_url}/api/vpn/check-access",
///             json={
///                 "user_id": user_id,
///                 "location_id": location_id,
///                 "ip_address": client_ip,
///             }
///         )
///         return response.json()
///
/// # Usage in VPN server
/// async def handle_vpn_connection(client_data):
///     validator = VpnAccessValidator("http://127.0.0.1:9000")
///
///     user_id = extract_user_from_cert(client_data.certificate)
///     location_id = extract_location_from_endpoint(client_data.endpoint)
///     client_ip = client_data.remote_ip
///
///     result = await validator.check_vpn_access(user_id, location_id, client_ip)
///
///     if result["allowed"]:
///         print(f"Allowing {user_id} to {location_id}")
///         await open_tunnel(client_data, timeout=result["session_timeout"])
///     else:
///         print(f"Denying {user_id}: {result['reason']}")
///         await close_connection(client_data)
/// ```

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_permission_checker_creation() {
        let checker = VpnPermissionChecker::new("http://localhost:9000");
        assert_eq!(checker.account_manager_url, "http://localhost:9000");
    }

    #[tokio::test]
    async fn test_connection_handler_creation() {
        let handler = VpnConnectionHandler::new("http://localhost:9000");
        // Handler created successfully
    }
}

/// Integration Points Summary
///
/// 1. VPN Server Startup:
///    - Initialize VpnPermissionChecker with account manager URL
///    - Verify account manager is reachable
///
/// 2. Client Connection (TLS/VPN handshake):
///    - Extract user_id from certificate CN or token
///    - Extract location_id from endpoint or SNI
///    - Call check_access()
///    - Allow/deny based on response
///
/// 3. Active Tunnels:
///    - Periodically re-check permissions (every 5 min)
///    - If permission revoked, close tunnel immediately
///    - Log all access decisions
///
/// 4. Error Handling:
///    - If account manager unreachable: deny access (fail-secure)
///    - If database error: deny access (fail-secure)
///    - Log all errors for debugging
///
/// 5. Session Management:
///    - Use session_timeout from response
///    - Close tunnel when session expires
///    - Allow re-connection after expiration
