//! Unit test: minimal valid configuration can be parsed

use selfhost_config::Config;

#[test]
fn minimal_config_parses_and_validates() {
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

    // This should parse and validate without errors
    let config = Config::parse(config_toml).expect("minimal config should parse and validate");

    // Verify basic properties
    assert_eq!(config.version, 1);
    assert_eq!(config.server.acme_email, "test@example.com");
    assert_eq!(config.server.admin_bind, "127.0.0.1:9999");
    assert_eq!(config.server.http_bind, "127.0.0.1:8080");
    assert_eq!(config.server.https_bind, "127.0.0.1:8443");

    // Verify binds are on loopback
    assert!(config.server.admin_bind.starts_with("127.0.0.1"));
    assert!(config.server.http_bind.starts_with("127.0.0.1"));
    assert!(config.server.https_bind.starts_with("127.0.0.1"));
    assert!(!config.server.admin_bind.contains("0.0.0.0"));
    assert!(!config.server.http_bind.contains("0.0.0.0"));
    assert!(!config.server.https_bind.contains("0.0.0.0"));

    // Verify site configuration
    assert_eq!(config.sites.len(), 1);
    assert_eq!(config.sites[0].name, "test");
    assert_eq!(config.sites[0].domains.len(), 1);
    assert_eq!(config.sites[0].domains[0], "test.local");
}
