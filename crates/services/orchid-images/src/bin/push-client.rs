//! Push client for Windows PC — periodically sends images to VPN server.
//!
//! Usage:
//!   push-client <server-url> <local-image-server> [push-interval-secs]
//!
//! Example:
//!   push-client https://rockywearsahat.com http://127.0.0.1:8080 60

use std::env;
use std::time::Duration;
use std::io::Read;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: push-client <server-url> <local-image-server> [push-interval-secs]");
        eprintln!("Example: push-client https://rockywearsahat.com http://127.0.0.1:8080 60");
        std::process::exit(1);
    }

    let server_url = &args[1];
    let local_server = &args[2];
    let push_interval = args.get(3)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(60);

    eprintln!("Orchid image push client starting");
    eprintln!("  Server URL: {}", server_url);
    eprintln!("  Local server: {}", local_server);
    eprintln!("  Push interval: {} seconds", push_interval);

    // Periodically fetch from local server and push to VPN server
    loop {
        match fetch_and_push(server_url, local_server).await {
            Ok(_) => eprintln!("Image pushed successfully"),
            Err(e) => eprintln!("Error: {}", e),
        }

        tokio::time::sleep(Duration::from_secs(push_interval)).await;
    }
}

async fn fetch_and_push(server_url: &str, local_server: &str) -> Result<(), String> {
    // Fetch image from local orchid server
    let image_url = format!("{}/latest-image", local_server);
    let image_data = fetch_url(&image_url).await?;

    if image_data.is_empty() {
        return Err("Empty image from local server".to_string());
    }

    // Push to VPN server
    let push_url = format!("{}/api/images/push", server_url);
    push_image(&push_url, &image_data).await?;

    Ok(())
}

async fn fetch_url(url: &str) -> Result<Vec<u8>, String> {
    // Simple HTTP GET using std library (no external HTTP client)
    let uri = url.parse::<http::Uri>()
        .map_err(|e| format!("Invalid URL: {}", e))?;

    // For now, use a simple approach with a basic HTTP request
    // In production, would use a proper HTTP client
    Err("Simple HTTP client not implemented. Use curl or a proper HTTP library.".to_string())
}

async fn push_image(_url: &str, _data: &[u8]) -> Result<(), String> {
    Err("Push client not fully implemented yet.".to_string())
}

// HTTP URI parsing - minimal implementation
mod http {
    use std::str::FromStr;

    pub struct Uri {
        pub scheme: String,
        pub host: String,
        pub port: u16,
        pub path: String,
    }

    impl FromStr for Uri {
        type Err = String;

        fn from_str(s: &str) -> Result<Self, Self::Err> {
            // Very simple URI parser for http(s)://host[:port]/path
            if !s.starts_with("http://") && !s.starts_with("https://") {
                return Err("Only http and https supported".to_string());
            }

            let scheme = if s.starts_with("https://") {
                "https".to_string()
            } else {
                "http".to_string()
            };

            let rest = if scheme == "https" {
                &s[8..]
            } else {
                &s[7..]
            };

            let (host_port, path) = if let Some(slash) = rest.find('/') {
                (&rest[..slash], &rest[slash..])
            } else {
                (rest, "/")
            };

            let (host, port) = if let Some(colon) = host_port.find(':') {
                let h = &host_port[..colon];
                let p: u16 = host_port[colon+1..].parse()
                    .map_err(|_| "Invalid port".to_string())?;
                (h.to_string(), p)
            } else {
                let p = if scheme == "https" { 443 } else { 80 };
                (host_port.to_string(), p)
            };

            Ok(Uri {
                scheme,
                host,
                port,
                path: path.to_string(),
            })
        }
    }
}
