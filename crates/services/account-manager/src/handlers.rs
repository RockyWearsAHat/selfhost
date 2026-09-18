// crates/services/account-manager/src/handlers.rs
// HTTP endpoint handlers

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use crate::{
    AccountManager, AccountError, RegisterRequest, RegisterResponse, LoginRequest, LoginResponse,
    UserResponse, ApproveUserRequest, GrantPermissionRequest, CreateLocationRequest,
    VpnAccessCheckRequest, VpnAccessCheckResponse, VpnPermissionValidator, LocationResponse,
};

// ============================================================================
// Authentication Endpoints
// ============================================================================

/// POST /api/auth/register
pub async fn register(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    req: web::Json<RegisterRequest>,
) -> impl Responder {
    // Decode credential ID from base64
    let credential_id = match base64::decode(&req.passkey_credential_id) {
        Ok(id) => id,
        Err(_) => return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid credential ID"})),
    };

    match manager.register_user(&req.username, &req.email, &credential_id).await {
        Ok(user) => {
            let response = RegisterResponse {
                user_id: user.id,
                username: user.username,
                email: user.email,
                status: user.status,
                created_at: user.created_at,
            };
            HttpResponse::Created().json(response)
        }
        Err(AccountError::UserAlreadyExists) => {
            HttpResponse::Conflict().json(serde_json::json!({"error": "User already exists"}))
        }
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// POST /api/auth/login
pub async fn login(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    req: web::Json<LoginRequest>,
) -> impl Responder {
    // Get user by username
    let user = match manager.get_user_by_username(&req.username).await {
        Ok(u) => u,
        Err(_) => return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"})),
    };

    // Check if user is approved
    if user.approved_at.is_none() {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "User registration not approved"}));
    }

    // Verify passkey assertion (simplified - real implementation uses webauthn crate)
    // TODO: Implement proper WebAuthn assertion verification

    // Create session
    let session = match manager.create_session(&user.id, None, None).await {
        Ok(s) => s,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    };

    // Get user roles and permissions
    let roles = manager.get_user_roles(&user.id).await.unwrap_or_default();

    let response = LoginResponse {
        session_token: session.token_hash,
        user: UserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
            status: user.status,
            created_at: user.created_at,
            approved_at: user.approved_at,
            roles: roles.clone(),
            permissions: vec![], // TODO: Load actual permissions
            locations: vec![], // TODO: Load user's locations
        },
        expires_in: 86400, // 24 hours
    };

    HttpResponse::Ok().json(response)
}

/// POST /api/auth/logout
pub async fn logout(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    req: HttpRequest,
) -> impl Responder {
    // Extract session token from Authorization header
    match req.headers().get("Authorization") {
        Some(header) => {
            match header.to_str() {
                Ok(auth) => {
                    // TODO: Revoke session
                    HttpResponse::Ok().json(serde_json::json!({"success": true}))
                }
                Err(_) => HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid header"}))
            }
        }
        None => HttpResponse::Unauthorized().json(serde_json::json!({"error": "Missing authorization"}))
    }
}

/// GET /api/auth/whoami
pub async fn whoami(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    req: HttpRequest,
) -> impl Responder {
    // Extract user ID from request context
    // TODO: Implement session validation middleware

    HttpResponse::Ok().json(serde_json::json!({"message": "whoami endpoint"}))
}

// ============================================================================
// User Management Endpoints (Admin Only)
// ============================================================================

/// GET /api/users
pub async fn list_users(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    req: HttpRequest,
) -> impl Responder {
    // TODO: Check admin permission
    // TODO: Implement pagination

    HttpResponse::Ok().json(serde_json::json!({"users": []}))
}

/// GET /api/users/{user_id}
pub async fn get_user(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    user_id: web::Path<String>,
) -> impl Responder {
    match manager.get_user(&user_id.into_inner()).await {
        Ok(user) => {
            let roles = manager.get_user_roles(&user.id).await.unwrap_or_default();
            let response = UserResponse {
                id: user.id,
                username: user.username,
                email: user.email,
                status: user.status,
                created_at: user.created_at,
                approved_at: user.approved_at,
                roles,
                permissions: vec![],
                locations: vec![],
            };
            HttpResponse::Ok().json(response)
        }
        Err(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}))
    }
}

/// POST /api/users/{user_id}/approve
pub async fn approve_user(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    user_id: web::Path<String>,
    _req: web::Json<ApproveUserRequest>,
    http_req: HttpRequest,
) -> impl Responder {
    // TODO: Check admin permission

    match manager.approve_user(&user_id.into_inner(), "admin").await {
        Ok(user) => {
            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "status": user.status,
                }
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
    }
}

// ============================================================================
// Permission Management Endpoints
// ============================================================================

/// POST /api/users/{user_id}/permissions
pub async fn grant_permission(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    user_id: web::Path<String>,
    req: web::Json<GrantPermissionRequest>,
) -> impl Responder {
    let uid = user_id.into_inner();

    match manager.grant_permission(&uid, req.location_id.as_deref(), "admin").await {
        Ok(_) => {
            HttpResponse::Created().json(serde_json::json!({
                "success": true,
                "message": "Permission granted"
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
    }
}

// ============================================================================
// VPN Access Check Endpoint
// ============================================================================

/// POST /api/vpn/check-access
/// Called by VPN server to verify user has access to a location
pub async fn check_vpn_access(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    req: web::Json<VpnAccessCheckRequest>,
) -> impl Responder {
    let validator = VpnPermissionValidator::new(manager.get_ref().clone());

    match validator.check_vpn_access(&req.user_id, &req.location_id, req.ip_address.as_deref()).await {
        Ok(decision) => {
            let response = VpnAccessCheckResponse {
                allowed: decision.allowed,
                reason: decision.reason,
                user_name: None,
                session_timeout: decision.session_timeout,
            };
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            let response = VpnAccessCheckResponse {
                allowed: false,
                reason: format!("Access check failed: {}", e),
                user_name: None,
                session_timeout: None,
            };
            HttpResponse::Ok().json(response)
        }
    }
}

// ============================================================================
// Location Management Endpoints
// ============================================================================

/// POST /api/vpn-locations
pub async fn create_location(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    req: web::Json<CreateLocationRequest>,
) -> impl Responder {
    match manager.create_location(&req.name, req.description.as_deref(), req.region.as_deref()).await {
        Ok(location) => {
            let response = LocationResponse {
                id: location.id,
                name: location.name,
                description: location.description,
                region: location.region,
                created_at: location.created_at,
                user_count: 0,
            };
            HttpResponse::Created().json(response)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
    }
}

/// GET /api/vpn-locations
pub async fn list_locations(
    manager: web::Data<std::sync::Arc<AccountManager>>,
) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"locations": []}))
}

/// GET /api/vpn-locations/{location_id}
pub async fn get_location(
    manager: web::Data<std::sync::Arc<AccountManager>>,
    location_id: web::Path<String>,
) -> impl Responder {
    match manager.get_location(&location_id.into_inner()).await {
        Ok(location) => {
            let response = LocationResponse {
                id: location.id,
                name: location.name,
                description: location.description,
                region: location.region,
                created_at: location.created_at,
                user_count: 0,
            };
            HttpResponse::Ok().json(response)
        }
        Err(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "Location not found"}))
    }
}

// ============================================================================
// Helper: Configure Routes
// ============================================================================

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // Auth endpoints
        .route("/api/auth/register", web::post().to(register))
        .route("/api/auth/login", web::post().to(login))
        .route("/api/auth/logout", web::post().to(logout))
        .route("/api/auth/whoami", web::get().to(whoami))

        // User management
        .route("/api/users", web::get().to(list_users))
        .route("/api/users/{user_id}", web::get().to(get_user))
        .route("/api/users/{user_id}/approve", web::post().to(approve_user))
        .route("/api/users/{user_id}/permissions", web::post().to(grant_permission))

        // VPN access check
        .route("/api/vpn/check-access", web::post().to(check_vpn_access))

        // Location management
        .route("/api/vpn-locations", web::post().to(create_location))
        .route("/api/vpn-locations", web::get().to(list_locations))
        .route("/api/vpn-locations/{location_id}", web::get().to(get_location));
}
