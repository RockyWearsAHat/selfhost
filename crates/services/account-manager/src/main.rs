use actix_web::{web, App, HttpServer, HttpResponse, middleware, HttpRequest};
use serde_json::json;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let db_url = if let Ok(url) = std::env::var("DATABASE_URL") {
        url
    } else {
        // Use Windows or Unix path depending on OS
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

    // Add is_admin column if missing
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0").execute(&pool).await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN password_hash TEXT DEFAULT 'admin'").execute(&pool).await;

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
    println!("✓ Server starting on 127.0.0.1:9000");

    let data = web::Data::new(pool);

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
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
    if !is_admin(&req) {
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
    if !is_admin(&req) {
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
    if !is_admin(&req) {
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
    if !is_admin(&req) {
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

async fn check_access(pool: web::Data<SqlitePool>, body: web::Json<serde_json::Value>) -> HttpResponse {
    let user_id = body.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
    let location_id = body.get("location_id").and_then(|v| v.as_str()).unwrap_or("");

    match sqlx::query(
        "SELECT 1 FROM permissions WHERE user_id = ? AND resource_type = 'vpn_location' AND resource_id = ?"
    )
    .bind(user_id)
    .bind(location_id)
    .fetch_optional(pool.as_ref())
    .await {
        Ok(Some(_)) => HttpResponse::Ok().json(json!({
            "allowed": true,
            "reason": "Access granted",
            "session_timeout": 86400
        })),
        Ok(None) => HttpResponse::Ok().json(json!({
            "allowed": false,
            "reason": "No permission for this location"
        })),
        Err(_) => HttpResponse::InternalServerError().json(json!({"allowed": false}))
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

fn is_admin(req: &HttpRequest) -> bool {
    if let Some(auth) = req.headers().get("Authorization") {
        if let Ok(auth_str) = auth.to_str() {
            if auth_str.starts_with("Bearer ") {
                let token = &auth_str[7..];
                return token == "admin" || token == "alex-admin";
            }
        }
    }
    false
}
