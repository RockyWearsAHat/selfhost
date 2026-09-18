use actix_web::{web, App, HttpServer, HttpResponse, middleware, HttpRequest};
use actix_cors::Cors;
use serde_json::json;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;
use chrono::{Duration, Utc};
use rand::Rng;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Serialize, Deserialize, Clone)]
struct User {
    id: String,
    email: String,
    username: String,
    status: String,
    is_admin: bool,
}

#[derive(Serialize, Deserialize)]
struct RegisterReq {
    email: String,
    password: String,
    username: String,
}

#[derive(Serialize, Deserialize)]
struct LoginReq {
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct PermReq {
    resource_type: String,
    resource_id: String,
    action: String,
}

#[derive(Serialize, Deserialize)]
struct VpnLoginReq {
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct VpnLoginResp {
    vpn_token: String,
    user_id: String,
    email: String,
    expires_in: i64,
}

#[derive(Serialize, Deserialize)]
struct VpnValidateTokenReq {
    vpn_token: String,
}

#[derive(Serialize, Deserialize)]
struct GrantSubdomainReq {
    subdomain_ids: Vec<String>,
    access_level: Option<String>,
    expires_in: Option<i64>,
}

#[derive(Serialize, Deserialize)]
struct CheckSubdomainAccessReq {
    user_id: String,
    subdomain: String,
    ip_address: Option<String>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let db_url = if let Ok(url) = std::env::var("DATABASE_URL") {
        url
    } else {
        if cfg!(windows) {
            format!("sqlite://{}\\.selfhost\\data\\accounts.db",
                std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Alex".to_string()))
        } else {
            format!("sqlite://{}/.selfhost/data/accounts.db",
                std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
        }
    };

    let pool = SqlitePool::connect(&db_url).await
        .expect("Failed to connect database");

    // Ensure tables exist (create manually below since schema.sql is large)

    // Add columns if missing (for existing databases)
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT 'admin'").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN access_level TEXT DEFAULT 'full_access'").execute(&pool).await;

    // Ensure admin exists
    let admin_exists: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM users WHERE email='alexwaldmann2004@gmail.com'"
    ).fetch_one(&pool).await.unwrap_or((0,));

    if admin_exists.0 == 0 {
        let _ = sqlx::query(
            "INSERT INTO users (id, email, username, status, is_admin, password_hash) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(Uuid::new_v4().to_string())
        .bind("alexwaldmann2004@gmail.com")
        .bind("alex")
        .bind("active")
        .bind(1)
        .bind("admin")
        .execute(&pool)
        .await;
    }

    println!("✓ Database ready");
    println!("✓ Admin: alexwaldmann2004@gmail.com");
    println!("✓ VPN + Subdomain auth enabled");
    println!("✓ Server starting on 127.0.0.1:9000");

    let data = web::Data::new(pool);

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .app_data(data.clone())
            .wrap(cors)
            .wrap(middleware::Logger::default())
            .route("/health", web::get().to(health))
            .route("/api/whoami", web::get().to(whoami))
            .route("/api/auth/register", web::post().to(register))
            .route("/api/auth/login", web::post().to(login))
            .route("/api/users", web::get().to(list_users))
            .route("/api/users/{id}", web::get().to(get_user))
            .route("/api/users/{id}/approve", web::post().to(approve))
            .route("/api/users/{id}/permissions", web::post().to(grant_perm))
            .route("/api/users/{id}/permissions", web::get().to(list_perms))
            .route("/api/users/{id}/permissions/{pid}", web::delete().to(revoke_perm))
            .route("/api/vpn/check-access", web::post().to(check_access))
            .route("/api/vpn/locations", web::get().to(locations))
            // VPN Auth Endpoints
            .route("/api/vpn/login", web::post().to(vpn_login))
            .route("/api/vpn/validate-token", web::post().to(vpn_validate_token))
            .route("/api/vpn/revoke-token", web::post().to(vpn_revoke_token))
            // Subdomain Endpoints
            .route("/api/subdomains", web::get().to(list_subdomains))
            .route("/api/users/{id}/subdomains", web::post().to(grant_subdomain))
            .route("/api/users/{id}/subdomains", web::get().to(list_user_subdomains))
            .route("/api/users/{id}/subdomains/{sid}", web::delete().to(revoke_subdomain))
            .route("/api/vpn/check-subdomain-access", web::post().to(check_subdomain_access))
    })
    .bind("127.0.0.1:9000")?
    .run()
    .await
}

async fn health() -> HttpResponse {
    HttpResponse::Ok().json(json!({"status": "ok"}))
}

async fn whoami(req: HttpRequest) -> HttpResponse {
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                return HttpResponse::Ok().json(json!({
                    "user_id": token,
                    "email": "user@example.com",
                    "is_admin": token == "admin"
                }));
            }
        }
    }
    HttpResponse::Unauthorized().json(json!({"error": "Not authenticated"}))
}

async fn register(pool: web::Data<SqlitePool>, body: web::Json<RegisterReq>) -> HttpResponse {
    let user_id = Uuid::new_v4().to_string();

    match sqlx::query(
        "INSERT INTO users (id, email, username, status, password_hash) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(&user_id)
    .bind(&body.email)
    .bind(&body.username)
    .bind("pending")
    .bind(&body.password)
    .execute(pool.as_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(json!({
            "user_id": user_id,
            "status": "pending",
            "message": "Registration successful. Awaiting admin approval."
        })),
        Err(e) => HttpResponse::BadRequest().json(json!({"error": e.to_string()}))
    }
}

async fn login(pool: web::Data<SqlitePool>, body: web::Json<LoginReq>) -> HttpResponse {
    match sqlx::query_as::<_, (String, String, i64)>(
        "SELECT id, email, is_admin FROM users WHERE email = ? AND password_hash = ? AND status = 'active'"
    )
    .bind(&body.email)
    .bind(&body.password)
    .fetch_one(pool.as_ref())
    .await {
        Ok((id, email, is_admin)) => HttpResponse::Ok().json(json!({
            "token": id,
            "email": email,
            "is_admin": is_admin == 1
        })),
        Err(_) => HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"}))
    }
}

async fn list_users(pool: web::Data<SqlitePool>, req: HttpRequest) -> HttpResponse {
    let token = get_token(&req);
    if !check_is_admin(&pool, &token).await {
        return HttpResponse::Forbidden().json(json!({"error": "Admin only"}));
    }

    match sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, email, username, status FROM users"
    )
    .fetch_all(pool.as_ref())
    .await {
        Ok(rows) => {
            let users: Vec<_> = rows.into_iter().map(|(id, email, username, status)| {
                json!({"id": id, "email": email, "username": username, "status": status})
            }).collect();
            HttpResponse::Ok().json(users)
        },
        Err(_) => HttpResponse::InternalServerError().json(json!({"error": "Database error"}))
    }
}

async fn get_user(pool: web::Data<SqlitePool>, path: web::Path<String>) -> HttpResponse {
    let user_id = path.into_inner();
    match sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, email, username, status FROM users WHERE id = ?"
    )
    .bind(&user_id)
    .fetch_one(pool.as_ref())
    .await {
        Ok((id, email, username, status)) => HttpResponse::Ok().json(json!({
            "id": id, "email": email, "username": username, "status": status
        })),
        Err(_) => HttpResponse::NotFound().json(json!({"error": "User not found"}))
    }
}

async fn approve(pool: web::Data<SqlitePool>, path: web::Path<String>, req: HttpRequest) -> HttpResponse {
    let token = get_token(&req);
    if !check_is_admin(&pool, &token).await {
        return HttpResponse::Forbidden().json(json!({"error": "Admin only"}));
    }

    let user_id = path.into_inner();
    match sqlx::query("UPDATE users SET status = 'active' WHERE id = ?")
        .bind(&user_id)
        .execute(pool.as_ref())
        .await {
        Ok(_) => HttpResponse::Ok().json(json!({"status": "approved"})),
        Err(_) => HttpResponse::InternalServerError().json(json!({"error": "Failed"}))
    }
}

async fn grant_perm(pool: web::Data<SqlitePool>, path: web::Path<String>, body: web::Json<PermReq>, req: HttpRequest) -> HttpResponse {
    let token = get_token(&req);
    if !check_is_admin(&pool, &token).await {
        return HttpResponse::Forbidden().json(json!({"error": "Admin only"}));
    }

    let user_id = path.into_inner();
    match sqlx::query(
        "INSERT INTO permissions (id, user_id, resource_type, resource_id, action) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&user_id)
    .bind(&body.resource_type)
    .bind(&body.resource_id)
    .bind(&body.action)
    .execute(pool.as_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(json!({"status": "granted"})),
        Err(e) => HttpResponse::BadRequest().json(json!({"error": e.to_string()}))
    }
}

async fn list_perms(pool: web::Data<SqlitePool>, path: web::Path<String>) -> HttpResponse {
    let user_id = path.into_inner();
    match sqlx::query_as::<_, (String, String, String)>(
        "SELECT resource_type, resource_id, action FROM permissions WHERE user_id = ?"
    )
    .bind(&user_id)
    .fetch_all(pool.as_ref())
    .await {
        Ok(rows) => {
            let perms: Vec<_> = rows.into_iter().map(|(rt, rid, act)| {
                json!({"resource_type": rt, "resource_id": rid, "action": act})
            }).collect();
            HttpResponse::Ok().json(perms)
        },
        Err(_) => HttpResponse::InternalServerError().json(json!({"error": "Database error"}))
    }
}

async fn revoke_perm(pool: web::Data<SqlitePool>, path: web::Path<(String, String)>, req: HttpRequest) -> HttpResponse {
    let token = get_token(&req);
    if !check_is_admin(&pool, &token).await {
        return HttpResponse::Forbidden().json(json!({"error": "Admin only"}));
    }

    let (user_id, perm_id) = path.into_inner();
    match sqlx::query("DELETE FROM permissions WHERE id = ? AND user_id = ?")
        .bind(&perm_id)
        .bind(&user_id)
        .execute(pool.as_ref())
        .await {
        Ok(_) => HttpResponse::Ok().json(json!({"status": "revoked"})),
        Err(_) => HttpResponse::InternalServerError().json(json!({"error": "Failed"}))
    }
}

/// Where the admin capability API listens. Account-manager runs as an
/// independent process with its own working directory, so it cannot share
/// `Config` with the admin daemon — this is configured on its own.
fn admin_bind() -> String {
    std::env::var("SELFHOST_ADMIN_BIND").unwrap_or_else(|_| "127.0.0.1:9191".to_string())
}

/// Path to the admin daemon's bearer token file. Per docs/SECURITY.md, no
/// service ever receives a secret itself — only a path to read one from. The
/// fallback is a best-effort guess; a wrong guess just fails the read below
/// and the check denies, so it is safe to get wrong.
fn admin_token_file() -> PathBuf {
    if let Ok(path) = std::env::var("SELFHOST_ADMIN_TOKEN_FILE") {
        return PathBuf::from(path);
    }
    if cfg!(windows) {
        PathBuf::from(std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Alex".to_string()))
            .join("Self-Host")
            .join("data")
            .join("admin.token")
    } else {
        PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/root".to_string()))
            .join("Self-Host")
            .join("data")
            .join("admin.token")
    }
}

/// Asks the admin capability API whether `person` holds `vpn.access` for
/// `location`. Fails closed: any error along the way returns `Err`, and the
/// caller treats that as "not allowed" — never a default-allow.
///
/// A one-shot raw-socket client rather than a general HTTP client, mirroring
/// `doctor.rs`'s `ask_daemon` — the established shape for this codebase's
/// loopback admin calls, kept to the one request/response it needs so it
/// doesn't grow into an HTTP client nobody maintains.
async fn admin_check_access(person: &str, location: &str) -> Result<(bool, String), String> {
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(3);
    const MAX_BODY: usize = 64 * 1024;

    let token_path = admin_token_file();
    let token = std::fs::read_to_string(&token_path).map_err(|error| {
        format!("admin token at {} could not be read ({error})", token_path.display())
    })?;
    let token = token.trim();
    if token.is_empty() {
        return Err("admin token file is empty".to_string());
    }

    let bind = admin_bind();
    let address: std::net::SocketAddr = bind
        .parse()
        .map_err(|error| format!("SELFHOST_ADMIN_BIND {bind} is not an address: {error}"))?;

    let body = json!({"user_id": person, "location_id": location}).to_string();

    let exchange = async {
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(|error| format!("nothing is answering on {address}: {error}"))?;
        let request = format!(
            "POST /api/vpn/check-access HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|error| format!("the admin daemon closed the connection: {error}"))?;
        let mut raw = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream
                .read(&mut buffer)
                .await
                .map_err(|error| format!("the admin daemon's answer stopped: {error}"))?;
            if read == 0 {
                break;
            }
            raw.extend_from_slice(buffer.get(..read).unwrap_or_default());
            if raw.len() > MAX_BODY {
                return Err("the admin daemon's answer is larger than this will read".to_string());
            }
        }
        Ok(raw)
    };

    let raw = tokio::time::timeout(DEADLINE, exchange)
        .await
        .map_err(|_| format!("{address} did not answer within {}s", DEADLINE.as_secs()))??;

    let text = String::from_utf8_lossy(&raw);
    let (head, resp_body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "the admin daemon's answer had no complete head".to_string())?;
    let status = head.split_whitespace().nth(1).unwrap_or_default();
    if status != "200" {
        return Err(format!("the admin daemon answered {status}"));
    }

    let parsed: serde_json::Value = serde_json::from_str(resp_body.trim())
        .map_err(|error| format!("the admin daemon's answer is not JSON: {error}"))?;
    let allowed = parsed.get("allowed").and_then(|v| v.as_bool()).unwrap_or(false);
    let reason = parsed
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or(if allowed { "Access granted" } else { "No permission for this location" })
        .to_string();
    Ok((allowed, reason))
}

async fn check_access(pool: web::Data<SqlitePool>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let user_id = body.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
    let location_id = body.get("location_id").and_then(|v| v.as_str()).unwrap_or("");

    // The People registry keys identities by name (e.g. "alex"), not by this
    // service's own row id, so translate before asking the admin API.
    let username: Option<(String,)> = sqlx::query_as("SELECT username FROM users WHERE id = ?")
        .bind(user_id)
        .fetch_optional(pool.as_ref())
        .await
        .unwrap_or(None);
    let Some((username,)) = username else {
        return HttpResponse::Ok().json(json!({"allowed": false, "reason": "unknown user"}));
    };

    match admin_check_access(&username, location_id).await {
        Ok((allowed, reason)) => HttpResponse::Ok().json(json!({
            "allowed": allowed,
            "reason": reason,
            "session_timeout": 86400
        })),
        Err(error) => {
            log::error!("admin capability check failed: {error}");
            HttpResponse::Ok().json(json!({
                "allowed": false,
                "reason": "could not reach the access-control service"
            }))
        }
    }
}

async fn locations(pool: web::Data<SqlitePool>) -> HttpResponse {
    match sqlx::query_as::<_, (String, String, String)>(
        "SELECT id, name, region FROM vpn_locations"
    )
    .fetch_all(pool.as_ref())
    .await {
        Ok(rows) => {
            let locs: Vec<_> = rows.into_iter().map(|(id, name, region)| {
                json!({"id": id, "name": name, "region": region})
            }).collect();
            HttpResponse::Ok().json(locs)
        },
        Err(_) => HttpResponse::InternalServerError().json(json!({"error": "Database error"}))
    }
}

// VPN AUTHENTICATION ENDPOINTS

fn generate_vpn_token() -> String {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut random_bytes = vec![0u8; 32];
    rng.fill_bytes(&mut random_bytes);
    hex::encode(random_bytes)
}

async fn vpn_login(pool: web::Data<SqlitePool>, body: web::Json<VpnLoginReq>) -> HttpResponse {
    match sqlx::query_as::<_, (String, String, i64)>(
        "SELECT id, email, is_admin FROM users WHERE email = ? AND password_hash = ? AND status = 'active'"
    )
    .bind(&body.email)
    .bind(&body.password)
    .fetch_one(pool.as_ref())
    .await {
        Ok((user_id, email, is_admin)) => {
            if is_admin != 1 {
                return HttpResponse::Forbidden().json(json!({
                    "error": "User does not have VPN access permission"
                }));
            }

            let vpn_token = generate_vpn_token();
            let now = Utc::now();
            let expires_at = now + Duration::hours(24);
            let session_id = Uuid::new_v4().to_string();

            match sqlx::query(
                "INSERT INTO vpn_sessions (id, user_id, token, created_at, expires_at) VALUES (?, ?, ?, ?, ?)"
            )
            .bind(&session_id)
            .bind(&user_id)
            .bind(&vpn_token)
            .bind(now.to_rfc3339())
            .bind(expires_at.to_rfc3339())
            .execute(pool.as_ref())
            .await {
                Ok(_) => {
                    HttpResponse::Ok().json(VpnLoginResp {
                        vpn_token,
                        user_id,
                        email,
                        expires_in: 86400,
                    })
                }
                Err(e) => {
                    log::error!("Failed to create VPN session: {}", e);
                    HttpResponse::InternalServerError().json(json!({
                        "error": "Failed to create VPN session"
                    }))
                }
            }
        }
        Err(_) => HttpResponse::Unauthorized().json(json!({
            "error": "Invalid credentials or user not active"
        }))
    }
}

async fn vpn_validate_token(pool: web::Data<SqlitePool>, body: web::Json<VpnValidateTokenReq>) -> HttpResponse {
    match sqlx::query_as::<_, (String, String, String, Option<String>)>(
        "SELECT id, user_id, expires_at, revoked_at FROM vpn_sessions WHERE token = ?"
    )
    .bind(&body.vpn_token)
    .fetch_one(pool.as_ref())
    .await {
        Ok((_session_id, user_id, expires_at, revoked_at)) => {
            if revoked_at.is_some() {
                return HttpResponse::Ok().json(serde_json::json!({
                    "valid": false,
                    "user_id": serde_json::Value::Null,
                    "email": serde_json::Value::Null,
                    "expires_at": serde_json::Value::Null
                }));
            }

            if Utc::now().to_rfc3339() > expires_at {
                return HttpResponse::Ok().json(serde_json::json!({
                    "valid": false,
                    "user_id": serde_json::Value::Null,
                    "email": serde_json::Value::Null,
                    "expires_at": serde_json::Value::Null
                }));
            }

            match sqlx::query_as::<_, (String,)>(
                "SELECT email FROM users WHERE id = ? AND status = 'active'"
            )
            .bind(&user_id)
            .fetch_one(pool.as_ref())
            .await {
                Ok((email,)) => {
                    HttpResponse::Ok().json(serde_json::json!({
                        "valid": true,
                        "user_id": user_id,
                        "email": email,
                        "expires_at": expires_at
                    }))
                }
                Err(_) => HttpResponse::Ok().json(serde_json::json!({
                    "valid": false,
                    "user_id": serde_json::Value::Null,
                    "email": serde_json::Value::Null,
                    "expires_at": serde_json::Value::Null
                }))
            }
        }
        Err(_) => HttpResponse::Ok().json(serde_json::json!({
            "valid": false,
            "user_id": serde_json::Value::Null,
            "email": serde_json::Value::Null,
            "expires_at": serde_json::Value::Null
        }))
    }
}

async fn vpn_revoke_token(pool: web::Data<SqlitePool>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let token = body.get("vpn_token").and_then(|v| v.as_str()).unwrap_or("");

    match sqlx::query("UPDATE vpn_sessions SET revoked_at = ? WHERE token = ?")
        .bind(Utc::now().to_rfc3339())
        .bind(token)
        .execute(pool.as_ref())
        .await {
        Ok(result) => {
            if result.rows_affected() > 0 {
                HttpResponse::Ok().json(json!({"status": "revoked"}))
            } else {
                HttpResponse::NotFound().json(json!({"error": "Token not found"}))
            }
        }
        Err(e) => {
            log::error!("Failed to revoke VPN token: {}", e);
            HttpResponse::InternalServerError().json(json!({"error": "Failed to revoke token"}))
        }
    }
}

// SUBDOMAIN ENDPOINTS

async fn list_subdomains(pool: web::Data<SqlitePool>, req: HttpRequest) -> HttpResponse {
    let token = get_token(&req);
    if !check_is_admin(&pool, &token).await {
        return HttpResponse::Forbidden().json(json!({"error": "Admin access required"}));
    }

    match sqlx::query_as::<_, (String, String, Option<String>, String)>(
        "SELECT id, name, description, url FROM subdomains WHERE disabled_at IS NULL ORDER BY name"
    )
    .fetch_all(pool.as_ref())
    .await {
        Ok(rows) => {
            let subdomains: Vec<_> = rows.into_iter().map(|(id, name, desc, url)| {
                json!({"id": id, "name": name, "description": desc, "url": url})
            }).collect();
            HttpResponse::Ok().json(json!({"subdomains": subdomains, "count": subdomains.len()}))
        },
        Err(e) => {
            log::error!("Database error listing subdomains: {}", e);
            HttpResponse::InternalServerError().json(json!({"error": "Failed to retrieve subdomains"}))
        }
    }
}

async fn grant_subdomain(pool: web::Data<SqlitePool>, path: web::Path<String>, body: web::Json<GrantSubdomainReq>, req: HttpRequest) -> HttpResponse {
    let token = get_token(&req);
    if !check_is_admin(&pool, &token).await {
        return HttpResponse::Forbidden().json(json!({"error": "Admin access required"}));
    }

    let user_id = path.into_inner();
    let access_level = body.access_level.as_deref().unwrap_or("full_access").to_string();
    let expires_at = body.expires_in.map(|seconds| {
        let expiration = Utc::now() + Duration::seconds(seconds);
        expiration.to_rfc3339()
    });

    let mut granted_count = 0;
    for subdomain_id in &body.subdomain_ids {
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO site_permissions (id, user_id, subdomain_id, action, granted_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)"
        )
        .bind(Uuid::new_v4().to_string())
        .bind(&user_id)
        .bind(subdomain_id)
        .bind(&access_level)
        .bind(Utc::now().to_rfc3339())
        .bind(&expires_at)
        .execute(pool.as_ref())
        .await
        .map(|_| granted_count += 1);
    }

    HttpResponse::Created().json(json!({
        "success": true,
        "message": format!("Granted access to {} subdomain(s)", granted_count),
        "granted_count": granted_count
    }))
}

async fn list_user_subdomains(pool: web::Data<SqlitePool>, path: web::Path<String>) -> HttpResponse {
    let user_id = path.into_inner();

    match sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT sp.id, s.name, sp.action, sp.expires_at FROM site_permissions sp JOIN subdomains s ON sp.subdomain_id = s.id WHERE sp.user_id = ? AND (sp.expires_at IS NULL OR sp.expires_at > CURRENT_TIMESTAMP) ORDER BY s.name"
    )
    .bind(&user_id)
    .fetch_all(pool.as_ref())
    .await {
        Ok(rows) => {
            let accesses: Vec<_> = rows.into_iter().map(|(id, name, level, expires)| {
                json!({"id": id, "subdomain": name, "access_level": level, "expires_at": expires})
            }).collect();
            HttpResponse::Ok().json(json!({"user_id": user_id, "subdomains": accesses}))
        },
        Err(e) => {
            log::error!("Database error listing user subdomains: {}", e);
            HttpResponse::InternalServerError().json(json!({"error": "Failed to retrieve user subdomains"}))
        }
    }
}

async fn revoke_subdomain(pool: web::Data<SqlitePool>, path: web::Path<(String, String)>, req: HttpRequest) -> HttpResponse {
    let token = get_token(&req);
    if !check_is_admin(&pool, &token).await {
        return HttpResponse::Forbidden().json(json!({"error": "Admin access required"}));
    }

    let (user_id, subdomain_id) = path.into_inner();

    match sqlx::query("DELETE FROM site_permissions WHERE user_id = ? AND subdomain_id = ?")
        .bind(&user_id)
        .bind(&subdomain_id)
        .execute(pool.as_ref())
        .await {
        Ok(result) => {
            if result.rows_affected() == 0 {
                return HttpResponse::NotFound().json(json!({"error": "Subdomain access record not found"}));
            }
            HttpResponse::Ok().json(json!({"success": true, "message": "Subdomain access revoked"}))
        }
        Err(e) => {
            log::error!("Database error revoking access: {}", e);
            HttpResponse::InternalServerError().json(json!({"error": "Failed to revoke access"}))
        }
    }
}

async fn check_subdomain_access(pool: web::Data<SqlitePool>, body: web::Json<CheckSubdomainAccessReq>) -> HttpResponse {
    let user_id = &body.user_id;
    let subdomain = &body.subdomain;
    let _ip_address = body.ip_address.as_deref().unwrap_or("unknown");

    match sqlx::query_as::<_, (String,)>(
        "SELECT id FROM subdomains WHERE name = ?"
    )
    .bind(subdomain)
    .fetch_optional(pool.as_ref())
    .await {
        Ok(Some((subdomain_id,))) => {
            match sqlx::query_as::<_, (String, Option<String>)>(
                "SELECT action, expires_at FROM site_permissions WHERE user_id = ? AND subdomain_id = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP) LIMIT 1"
            )
            .bind(user_id)
            .bind(&subdomain_id)
            .fetch_optional(pool.as_ref())
            .await {
                Ok(Some((_action, _expires))) => {
                    HttpResponse::Ok().json(json!({
                        "allowed": true,
                        "reason": "Access granted",
                        "access_level": "granted",
                        "timeout": 86400
                    }))
                }
                Ok(None) => {
                    HttpResponse::Ok().json(json!({
                        "allowed": false,
                        "reason": "User does not have access to this subdomain",
                        "access_level": "none",
                        "timeout": 0
                    }))
                }
                Err(e) => {
                    log::error!("Database error checking access: {}", e);
                    HttpResponse::InternalServerError().json(json!({
                        "allowed": false,
                        "reason": "Access check failed",
                        "access_level": "none",
                        "timeout": 0
                    }))
                }
            }
        }
        Ok(None) => {
            HttpResponse::Ok().json(json!({
                "allowed": false,
                "reason": "Subdomain does not exist",
                "access_level": "none",
                "timeout": 0
            }))
        }
        Err(e) => {
            log::error!("Database error checking subdomain: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "allowed": false,
                "reason": "Access check failed",
                "access_level": "none",
                "timeout": 0
            }))
        }
    }
}

// HELPERS

fn get_token(req: &HttpRequest) -> String {
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if auth_str.starts_with("Bearer ") {
                return auth_str[7..].to_string();
            }
        }
    }
    String::new()
}

async fn check_is_admin(pool: &SqlitePool, token: &str) -> bool {
    if token.is_empty() {
        return false;
    }

    match sqlx::query_as::<_, (i64,)>(
        "SELECT is_admin FROM users WHERE id = ?"
    )
    .bind(token)
    .fetch_one(pool)
    .await {
        Ok((is_admin,)) => is_admin == 1,
        Err(_) => false
    }
}
