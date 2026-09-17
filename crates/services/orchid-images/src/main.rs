use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use serde_json::json;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use selfhost_orchid_images::FrameStore;

async fn handle_request(
    req: Request<Body>,
    store: Arc<FrameStore>,
) -> Result<Response<Body>, Infallible> {
    match req.uri().path() {
        "/latest-image" => {
            if let Some(frame) = store.get() {
                Ok(Response::builder()
                    .header("Content-Type", "image/jpeg")
                    .header("X-Frame-ID", frame.id())
                    .header("X-Timestamp", frame.timestamp.to_string())
                    .body(Body::from(frame.data))
                    .unwrap())
            } else {
                Ok(Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(Body::empty())
                    .unwrap())
            }
        }
        "/status" => {
            let status = if let Some(frame) = store.get() {
                json!({
                    "status": "ok",
                    "image_id": frame.id(),
                    "timestamp": frame.timestamp,
                    "size_bytes": frame.size,
                })
            } else {
                json!({
                    "status": "ok",
                    "message": "waiting for first frame",
                })
            };

            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(status.to_string()))
                .unwrap())
        }
        "/health" => {
            let health = json!({"status": "ok"});
            Ok(Response::builder()
                .header("Content-Type", "application/json")
                .body(Body::from(health.to_string()))
                .unwrap())
        }
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("404 Not Found"))
            .unwrap()),
    }
}

#[tokio::main]
async fn main() {
    let addr = SocketAddr::from(([0, 0, 0, 0], 8080));
    let store = Arc::new(FrameStore::new());

    // For testing: load a placeholder frame
    let placeholder = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG header
    store.update(placeholder);

    println!("Orchid Image Server listening on http://{}", addr);
    println!("Endpoints:");
    println!("  GET /latest-image - raw JPEG bytes");
    println!("  GET /status - JSON status");
    println!("  GET /health - health check");

    let make_svc = make_service_fn(move |_conn| {
        let store = Arc::clone(&store);
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                handle_request(req, Arc::clone(&store))
            }))
        }
    });

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("server error: {}", e);
    }
}
