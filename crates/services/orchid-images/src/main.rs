use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use selfhost_orchid_images::FrameStore;

async fn handle_connection(mut stream: tokio::net::TcpStream, store: Arc<FrameStore>) {
    let (reader, mut writer) = stream.split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    if reader.read_line(&mut line).await.is_err() {
        return;
    }

    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let path = parts[1];

    let response = match path {
        "/latest-image" => {
            if let Some(frame) = store.get() {
                let body = &frame.data;
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: {}\r\nX-Frame-ID: {}\r\n\r\n",
                    body.len(),
                    frame.id()
                ) + &String::from_utf8_lossy(body)
            } else {
                "HTTP/1.1 204 No Content\r\n\r\n".to_string()
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

            let body = status.to_string();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
        }
        "/health" => {
            let body = json!({"status": "ok"}).to_string();
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            )
        }
        _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 13\r\n\r\n404 Not Found".to_string(),
    };

    let _ = writer.write_all(response.as_bytes()).await;
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

    let listener = TcpListener::bind(addr)
        .await
        .expect("Failed to bind");

    loop {
        let (stream, _) = listener.accept().await.expect("Failed to accept");
        let store = Arc::clone(&store);
        tokio::spawn(handle_connection(stream, store));
    }
}
