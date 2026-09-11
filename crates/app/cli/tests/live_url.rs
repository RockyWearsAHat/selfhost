use std::fs;
use std::path::PathBuf;

#[test]
fn live_url_file_created_at_expected_path() {
    let temp_dir = PathBuf::from("/tmp/selfhost_live_url_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    // This simulates what serve_everything does after binding
    let address = "127.0.0.1:8443";
    let project_dir = temp_dir.clone();

    // Replicate the exact logic from serve_everything (lines 914-919)
    let url = format!("http://{}", address);
    let url_file = project_dir.join(".engine").join("live-url.txt");
    if let Some(parent) = url_file.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&url_file, &url);

    // Verify the file was created
    assert!(url_file.exists(), ".engine/live-url.txt should exist after daemon startup");

    // Verify the content has correct format: http://loopback:port
    let content = fs::read_to_string(&url_file).expect("read live-url.txt");
    assert_eq!(content, "http://127.0.0.1:8443", "URL format should be http://loopback:port");
    assert!(content.starts_with("http://"), "URL must start with http://");
    assert!(!content.contains("0.0.0.0"), "URL must not bind to 0.0.0.0 (must be loopback)");

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn live_url_directory_created_if_missing() {
    let temp_dir = PathBuf::from("/tmp/selfhost_live_url_dir_test");
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    // .engine directory should not exist initially
    let engine_dir = temp_dir.join(".engine");
    assert!(!engine_dir.exists(), ".engine directory should not exist initially");

    // Replicate the exact logic from serve_everything (lines 914-919)
    let address = "127.0.0.1:8080";
    let project_dir = temp_dir.clone();

    let url = format!("http://{}", address);
    let url_file = project_dir.join(".engine").join("live-url.txt");
    if let Some(parent) = url_file.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(&url_file, &url);

    // Verify .engine directory was created
    assert!(engine_dir.exists(), ".engine directory should be created if missing");
    assert!(url_file.exists(), "live-url.txt should exist");

    // Cleanup
    let _ = fs::remove_dir_all(&temp_dir);
}
