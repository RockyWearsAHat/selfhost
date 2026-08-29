//! Integration test: daemon can start with minimal config and serve on loopback.
//!
//! This test verifies that:
//! 1. A minimal configuration can be loaded and validated
//! 2. The configured binds are on loopback and not public addresses
//! 3. Ports are available for binding

use selfhost_config::Config;
use std::net::SocketAddr;
use tokio::net::TcpListener;

#[test]
fn minimal_config_is_valid_and_ports_are_available() {
    // RED PHASE: This test documents what a minimal valid config looks like and
    // verifies that the configured ports are available for binding on loopback.

    let config_toml = r#"version = 1

[server]
acme_email = "test@example.com"
data_dir = ".engine/demo/data"
admin_bind = "127.0.0.1:9999"
http_bind = "127.0.0.1:8080"
https_bind = "127.0.0.1:8443"
acme = "self-signed"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name = "test"
domains = ["test.local"]
static_root = "./public"
"#;

    // Parse and validate the config
    let config = Config::parse(config_toml).expect("minimal config should parse and validate");

    // Verify it's valid
    assert_eq!(config.version, 1);
    assert_eq!(config.server.acme_email, "test@example.com");
    assert_eq!(config.server.admin_bind, "127.0.0.1:9999");
    assert_eq!(config.server.http_bind, "127.0.0.1:8080");
    assert_eq!(config.server.https_bind, "127.0.0.1:8443");
    assert_eq!(config.sites.len(), 1);
    assert_eq!(config.sites[0].name, "test");

    // Verify binds are on loopback, not public
    assert!(config.server.admin_bind.starts_with("127.0.0.1"));
    assert!(config.server.http_bind.starts_with("127.0.0.1"));
    assert!(config.server.https_bind.starts_with("127.0.0.1"));

    // Test that the ports are available for binding (async test)
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    rt.block_on(async {
        test_ports_available(&config).await;
    });
}

async fn test_ports_available(config: &Config) {
    // Try to bind each port to verify it's available
    let admin_addr: SocketAddr =
        config.server.admin_bind.parse().expect("admin_bind should be a valid socket address");
    let http_addr: SocketAddr =
        config.server.http_bind.parse().expect("http_bind should be a valid socket address");
    let https_addr: SocketAddr =
        config.server.https_bind.parse().expect("https_bind should be a valid socket address");

    // Bind and immediately drop to test availability
    let _admin = TcpListener::bind(admin_addr)
        .await
        .expect("admin_bind port should be available");
    let _http = TcpListener::bind(http_addr)
        .await
        .expect("http_bind port should be available");
    let _https = TcpListener::bind(https_addr)
        .await
        .expect("https_bind port should be available");
}
