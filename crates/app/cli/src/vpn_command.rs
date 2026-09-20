//! `selfhost vpn` — running relays.
//!
//! A relay is one socket in front of one local service, and a roster of
//! the people allowed through it. `crates/foundation/config/src/vpn.rs` is its
//! schema and `docs/labs/vpn-lab.dx` is its design; this command drives the
//! supervisor that runs each one.
//!
//! Every relay must be enabled in the config before this command will start it,
//! because a relay is a public socket on a box with a public IP. That second
//! decision is made by writing `enabled = true` in the config, not by adding a
//! flag here.
//!
//! # Subcommands:
//!
//! - **`vpn list`** — every relay with its live state.
//! - **`vpn status <name>`** — one relay's state.
//! - **`vpn preflight <name>`** — everything that would run, without running it.
//!   The plan-before-acting shape this codebase uses for the firewall and for SMB;
//!   lets an operator see exactly what would run.
//! - **`vpn up <name>`** — bring a relay up. Prints its state after starting.
//!   **Manual and foreground-lifetime**, not persistence: this builds a
//!   throwaway `Supervisor` scoped to this one CLI invocation. On Windows the
//!   relay lands in that process's Job Object, so the relay dies within
//!   seconds of this command exiting — it does *not* keep running in the
//!   background. Since 2026-09-09, every relay with `enabled = true` is
//!   started automatically by the daemon itself at boot, into its own
//!   long-lived supervisor (see `serve_everything` in `crates/app/cli/src/main.rs`
//!   and `docs/VPN.md`); reach for `vpn up` only for manual diagnosis of a
//!   relay the daemon is not (yet) running, or one deliberately left
//!   `enabled = false`. A config change (`enabled`, addresses) takes
//!   effect at the daemon's next restart, not on this command.
//! - **`vpn down <name>`** — take a relay down. Same caveat in reverse: this
//!   stops whatever the *daemon's* supervisor is running, immediately, and a
//!   daemon still declaring the relay `enabled = true` will not bring it back
//!   up until it is restarted.
//!
//! # Why the CLI loads the relays
//!
//! This command reads the config and the supervisor state rather than asking the
//! API, exactly like `share` and `storage` do: it answers when nothing is
//! running, which is when somebody asks, and it reads the state through the same
//! paths the daemon uses — so a refusal here is word for word the refusal that
//! would stop the daemon.

use selfhost_config::Config;
use selfhost_supervisor::Supervisor;
use selfhost_vpn::{Install, Relays};
use std::path::Path;

/// Dispatches `vpn`'s subcommands.
pub fn vpn(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    match arguments.get(1).map(String::as_str) {
        Some("list") => list_relays(config, project_dir),
        Some("status") => status_relay(arguments, config, project_dir),
        Some("preflight") => preflight_relay(arguments, config, project_dir),
        Some("up") => up_relay(arguments, config, project_dir),
        Some("down") => down_relay(arguments, config, project_dir),
        Some(other) => Err(format!(
            "unknown vpn subcommand \"{other}\" — expected `list`, `status`, `preflight`, `up`, \
             or `down`"
        )),
        None => Err(
            "vpn needs a subcommand: `list`, `status <name>`, `preflight <name>`, `up <name>`, \
             or `down <name>`"
                .to_owned(),
        ),
    }
}

/// Lists every relay with its live state.
fn list_relays(config: &Config, project_dir: &Path) -> Result<(), String> {
    let relays = build_relays(config, project_dir)?;
    if relays.relays().is_empty() {
        println!("no [[vpn]] relays are declared in selfhost.config.toml");
        return Ok(());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    let rows = runtime.block_on(relays.list());
    print_relay_table(&rows);

    Ok(())
}

/// Shows one relay's state.
fn status_relay(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    let name = arguments.get(2).ok_or("status needs a relay name")?;

    let relays = build_relays(config, project_dir)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    let state = runtime.block_on(relays.state(name)).map_err(|e| e.to_string())?;

    println!("relay          {name}");
    println!("state          {}", state.label());
    if state.needs_attention() {
        println!("               needs attention — may not be serving");
    }

    Ok(())
}

/// Reports everything that would run without running it.
fn preflight_relay(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    let name = arguments.get(2).ok_or("preflight needs a relay name")?;

    let relays = build_relays(config, project_dir)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    let plan = runtime.block_on(relays.preflight(name)).map_err(|e| e.to_string())?;

    println!("relay          {}", plan.relay);
    println!("command        {}", plan.launch.command_line());
    println!();

    println!("Roster");
    println!("{}", plan.roster.to_json().to_text());
    println!();

    println!("Keys");
    let keys = &plan.keys;
    println!("  directory    {}", keys.dir.display());
    if !keys.dir_present {
        println!("               (does not exist yet)");
    }
    if keys.server_key {
        println!("  server key   ✓");
    } else {
        println!("  server key   ✗ missing");
    }
    let enrolled_count = plan.roster.enrolled().len();
    println!("  peer keys    {} enrolled", enrolled_count);
    if !keys.shared_keys.is_empty() {
        println!("  shared keys  ✗ delete: {}", keys.shared_keys.join(", "));
    }
    println!();

    if !plan.notes.is_empty() {
        println!("Notes");
        for note in &plan.notes {
            println!("  {note}");
        }
        println!();
    }

    println!("This relay would start — everything is in place.");

    Ok(())
}

/// Brings a relay up.
fn up_relay(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    let name = arguments.get(2).ok_or("up needs a relay name")?;

    let relays = build_relays(config, project_dir)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    let state = runtime.block_on(relays.up(name)).map_err(|e| e.to_string())?;

    println!("relay          {name}");
    println!("state          {}", state.label());
    println!(
        "\nnote: this installed the relay into a Supervisor scoped to this command, not the \
         running daemon's own. If a daemon is running with this relay's `enabled = true` in \
         config, it already started this relay itself at boot and this was redundant; if not, \
         this relay stops again the moment this process exits (Windows kills it immediately via \
         its Job Object — see docs/VPN.md)."
    );

    Ok(())
}

/// Takes a relay down.
fn down_relay(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    let name = arguments.get(2).ok_or("down needs a relay name")?;

    let relays = build_relays(config, project_dir)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("could not start the async runtime: {e}"))?;

    let state = runtime.block_on(relays.down(name)).map_err(|e| e.to_string())?;

    println!("relay          {name}");
    println!("state          {}", state.label());

    Ok(())
}

/// Builds the relays from the config and the supervisor, with error handling.
fn build_relays(config: &Config, project_dir: &Path) -> Result<Relays, String> {
    let data_dir = crate::teardown::data_dir(config, project_dir);
    let supervisor = Supervisor::new(project_dir);

    // The install spec comes from the Secure-VPN repository. The vendored path
    // is the standard location where scripts/securevpn/install-vpn-service.ps1
    // (on Windows) and scripts/securevpn/join-mac.sh (on macOS) place it.
    let install = Install::vendored();

    let vpn_relays = config.vpn.clone();
    if vpn_relays.is_empty() {
        return Err("no [[vpn]] relays are declared in selfhost.config.toml".to_owned());
    }

    Ok(Relays::new(supervisor, &data_dir, &config.server.admin_bind, install, vpn_relays))
}

/// Prints a table of relay summaries.
fn print_relay_table(rows: &[selfhost_vpn::RelaySummary]) {
    if rows.is_empty() {
        return;
    }

    // Column widths, with minimums
    let name_width = rows.iter().map(|r| r.name.len()).max().unwrap_or(4).max(4);
    let state_width = rows.iter().map(|r| r.state.label().len()).max().unwrap_or(5).max(5);

    // Header
    println!("{:<width$} {:<state_w$} {:<8} {:<8} {:<12}", "Name", "State", "Peers", "Rejected", "Listen", width = name_width, state_w = state_width);
    println!("{} {}", "─".repeat(name_width), "─".repeat(state_width + 8 + 8 + 12 + 6));

    // Rows
    for row in rows {
        println!(
            "{:<width$} {:<state_w$} {:<8} {:<8} {}",
            row.name,
            row.state.label(),
            row.peers,
            row.rejected,
            row.listen,
            width = name_width,
            state_w = state_width
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_subcommand_is_refused() {
        let arguments = vec!["vpn".to_owned(), "unknown".to_owned()];
        let config = Config::parse(
            "\
version = 1

[server]
acme_email = \"a@b.com\"
acme = \"self-signed\"

[[nodes]]
name = \"home\"
role = \"owner\"
",
        )
        .expect("config parses");
        let result = vpn(&arguments, &config, Path::new("."));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("unknown vpn subcommand"));
    }
}
