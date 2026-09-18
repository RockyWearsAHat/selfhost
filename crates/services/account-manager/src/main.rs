use actix_web::{web, App, HttpServer, HttpResponse, middleware};
use serde_json::{json, Value};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:///Users/alexwaldmann/.selfhost/data/accounts.db".to_string());

    let pool = match SqlitePool::connect(&database_url).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Database connection failed: {}", e);
            std::process::exit(1);
        }
    };

    println!("Database connected successfully");
    println!("Starting server on 127.0.0.1:9000");

    let pool_data = web::Data::new(pool);

    HttpServer::new(move || {
        App::new()
            .app_data(pool_data.clone())
            .wrap(middleware::Logger::default())
            .route("/health", web::get().to(health_check))
            .route("/api/whoami", web::get().to(whoami))
            .route("/api/auth/register", web::post().to(register))
            .route("/api/users", web::get().to(list_users))
            .route("/api/users/{user_id}", web::get().to(get_user))
            .route("/api/users/{user_id}/approve", web::post().to(approve_user))
            .route("/api/users/{user_id}/permissions", web::post().to(grant_permission))
            .route("/api/users/{user_id}/permissions", web::get().to(list_permissions))
            .route("/api/vpn/check-access", web::post().to(check_vpn_access))
            .route("/api/vpn/locations", web::get().to(list_vpn_locations))
    })
    .bind("127.0.0.1:9000")?
    .run()
    .await
}

async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(json!({"status": "ok"}))
}

async fn whoami() -> HttpResponse {
    HttpResponse::Ok().json(json!({"user_id": "current", "status": "authenticated"}))
}

async fn register(_body: web::Json<Value>) -> HttpResponse {
    let user_id = uuid::Uuid::new_v4().to_string();
    HttpResponse::Created().json(json!({
        "user_id": user_id,
        "status": "registered"
    }))
}

async fn list_users(pool: web::Data<SqlitePool>) -> HttpResponse {
    match sqlx::query_as::<_, (String, Option<String>, String)>(
        "SELECT id, email, status FROM users"
    )
    .fetch_all(pool.get_ref())
    .await {
        Ok(rows) => {
            let users: Vec<_> = rows.into_iter().map(|(id, email, status)| {
                json!({"id": id, "email": email, "status": status})
            }).collect();
            HttpResponse::Ok().json(users)
        },
        Err(_) => HttpResponse::InternalServerError().json(json!({"error": "Database error"}))
    }
}

async fn get_user(pool: web::Data<SqlitePool>, path: web::Path<String>) -> HttpResponse {
    let user_id = path.into_inner();
    match sqlx::query_as::<_, (String, Option<String>, String)>(
        "SELECT id, email, status FROM users WHERE id = ?"
    )
    .bind(&user_id)
    .fetch_one(pool.get_ref())
    .await {
        Ok((id, email, status)) => HttpResponse::Ok().json(json!({
            "id": id, "email": email, "status": status
        })),
        Err(_) => HttpResponse::NotFound().json(json!({"error": "User not found"}))
    }
}

async fn approve_user(pool: web::Data<SqlitePool>, path: web::Path<String>) -> HttpResponse {
    let user_id = path.into_inner();
    match sqlx::query("UPDATE users SET status = ? WHERE id = ?")
        .bind("active")
        .bind(&user_id)
        .execute(pool.get_ref())
        .await {
        Ok(_) => HttpResponse::Ok().json(json!({"status": "approved"})),
        Err(_) => HttpResponse::InternalServerError().json(json!({"error": "Failed to approve"}))
    }
}

async fn grant_permission(
    pool: web::Data<SqlitePool>,
    path: web::Path<String>,
    body: web::Json<Value>,
) -> HttpResponse {
    let user_id = path.into_inner();
    let resource_type = body.get("resource_type")
        .and_then(|v| v.as_str())
        .unwrap_or("vpn_location");
    let resource_id = body.get("resource_id")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let action = body.get("action").and_then(|v| v.as_str()).unwrap_or("read");

    match sqlx::query(
        "INSERT INTO permissions (id, user_id, resource_type, resource_id, action) VALUES (?, ?, ?, ?, ?)"
    )
    .bind(uuid::Uuid::new_v4().to_string())
    .bind(&user_id)
    .bind(resource_type)
    .bind(resource_id)
    .bind(action)
    .execute(pool.get_ref())
    .await {
        Ok(_) => HttpResponse::Created().json(json!({"status": "permission_granted"})),
        Err(e) => HttpResponse::BadRequest().json(json!({"error": e.to_string()}))
    }
}

async fn list_permissions(pool: web::Data<SqlitePool>, path: web::Path<String>) -> HttpResponse {
    let user_id = path.into_inner();
    match sqlx::query_as::<_, (String, String, String)>(
        "SELECT resource_type, resource_id, action FROM permissions WHERE user_id = ?"
    )
    .bind(&user_id)
    .fetch_all(pool.get_ref())
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

async fn check_vpn_access(pool: web::Data<SqlitePool>, body: web::Json<Value>) -> HttpResponse {
    let user_id = body.get("user_id").and_then(|v| v.as_str()).unwrap_or("");
    let location_id = body.get("location_id").and_then(|v| v.as_str()).unwrap_or("");

    let permission_exists = sqlx::query(
        "SELECT 1 FROM permissions WHERE user_id = ? AND resource_type = ? AND resource_id = ?"
    )
    .bind(user_id)
    .bind("vpn_location")
    .bind(location_id)
    .fetch_optional(pool.get_ref())
    .await;

    match permission_exists {
        Ok(Some(_)) => HttpResponse::Ok().json(json!({
            "allowed": true,
            "reason": "Access granted",
            "session_timeout": 86400
        })),
        Ok(None) => HttpResponse::Ok().json(json!({
            "allowed": false,
            "reason": format!("User does not have access to location {}", location_id)
        })),
        Err(_) => HttpResponse::InternalServerError().json(json!({
            "allowed": false,
            "reason": "Permission check failed"
        }))
    }
}

async fn list_vpn_locations(pool: web::Data<SqlitePool>) -> HttpResponse {
    match sqlx::query_as::<_, (String, String, String)>(
        "SELECT id, name, region FROM vpn_locations"
    )
    .fetch_all(pool.get_ref())
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
