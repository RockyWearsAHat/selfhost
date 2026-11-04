//! `mac-auto-update.sh` runs under launchd, whose PATH is only
//! `/usr/bin:/bin:/usr/sbin:/sbin`. The toolchain it gates on (cargo, maturin,
//! python3) lives elsewhere, so the script must find it on its own.

use std::path::Path;
use std::process::Command;

fn run(dir: &Path, args: &[&str]) {
    let status = Command::new(args[0])
        .args(&args[1..])
        .current_dir(dir)
        .status()
        .unwrap();
    assert!(status.success(), "{args:?} failed");
}

#[test]
fn under_launchds_bare_path_the_update_still_finds_cargo() {
    let scratch = std::env::temp_dir().join(format!("mac-auto-update-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&scratch);
    let home = scratch.join("home");
    let repo = scratch.join("repo");

    // A Secure-VPN repository one commit ahead of the installed checkout.
    std::fs::create_dir_all(repo.join("mlkem768")).unwrap();
    std::fs::write(repo.join("mlkem768/README"), "v1").unwrap();
    for args in [
        &["git", "init", "-q", "-b", "main"][..],
        &["git", "add", "."],
        &[
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qm",
            "v1",
        ],
    ] {
        run(&repo, args);
    }
    std::fs::create_dir_all(home.join(".securevpn")).unwrap();
    run(
        &scratch,
        &[
            "git",
            "clone",
            "-q",
            repo.to_str().unwrap(),
            home.join(".securevpn/app").to_str().unwrap(),
        ],
    );
    std::fs::write(repo.join("mlkem768/README"), "v2").unwrap();
    run(
        &repo,
        &[
            "git",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-qam",
            "v2",
        ],
    );

    // cargo where rustup puts it, ~/.cargo/bin: it records that it ran and fails
    // the gate, so the run stops before anything else.
    let cargo_bin = home.join(".cargo/bin");
    std::fs::create_dir_all(&cargo_bin).unwrap();
    let marker = scratch.join("cargo-ran");
    let cargo = cargo_bin.join("cargo");
    std::fs::write(
        &cargo,
        format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
    )
    .unwrap();
    run(&scratch, &["chmod", "+x", cargo.to_str().unwrap()]);

    let script =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../scripts/securevpn/mac-auto-update.sh");
    let output = Command::new("/bin/bash")
        .arg(&script)
        .args(["--repo", repo.to_str().unwrap()])
        .env_clear()
        .env("HOME", &home)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .output()
        .unwrap();

    let log = std::fs::read_to_string(home.join(".securevpn/auto-update.log")).unwrap_or_default();
    let cargo_ran = marker.exists();
    let _ = std::fs::remove_dir_all(&scratch);
    assert!(cargo_ran, "the gate never reached ~/.cargo/bin/cargo; log:\n{log}");
    assert!(!log.contains("command not found"), "log:\n{log}");
    assert!(!output.status.success(), "a failed gate must fail the run");
}
