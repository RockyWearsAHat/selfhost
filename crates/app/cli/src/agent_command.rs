//! `selfhost agent` — scoped, revocable credentials for trusted machines.
//!
//! # Why this writes `console.agents` directly, on the same terms `people` does
//!
//! Minting a credential that can act on this deployment is itself an act that
//! needs authority, and the only authority this CLI has to spend is whatever
//! already runs it: a shell on this box. That is the same authority
//! `selfhost console-password` and `selfhost people` already spend to write
//! their own stores directly rather than calling the daemon's API — see
//! `crate::people_command`'s module documentation for the fuller argument. An
//! agent token is not different in kind: it is a second, narrower way to
//! reach the same capability model, and minting one is exactly as
//! consequential as writing the people registry, so it goes through the same
//! door.
//!
//! # The token is shown exactly once
//!
//! `selfhost agent add` prints the whole `agent:<name>:<secret>` token to
//! stdout and stores only its hash (see [`selfhost_admin::agent_store`] for
//! why a hash and not the secret). There is no `selfhost agent show-token`
//! and there cannot be one: this store, like `admin.token`, never holds
//! anything a second display could read back. Losing the token means minting
//! a new one — `selfhost agent add <name>` again overwrites the old secret
//! and immediately revokes every session that still holds it.

use selfhost_admin::agent_store::{self, AgentStore};
use selfhost_identity::{AgentName, Grants};
use std::path::Path;

/// The words this command accepts after `agent`, and what each one is for.
pub const USAGE: &str = "\
Usage
  selfhost agent add <name> --grant <cap>[,<cap>]...
                                 Mint a scoped credential for a trusted machine
                                 and print its token exactly once. Running this
                                 again for the same name replaces its token and
                                 grants, revoking whatever it held before.
  selfhost agent list            Every agent, what it holds, and when it was minted
  selfhost agent revoke <name>   Delete an agent's credential; every request it
                                 authenticates is refused from the daemon's very
                                 next check, with nothing to restart

A capability is a word, and a target after a colon where it takes one — the
same vocabulary `selfhost people capabilities` lists. `site.admin` is what
`selfhost mcp` needs to manage sites and their content on your behalf.

The printed token belongs in SELFHOST_AGENT_TOKEN or ~/.selfhost/agent-token
on the machine that will present it — never in a command line, a config file,
or anywhere this shell's history keeps it.
";

/// Dispatches `selfhost agent <subcommand>`.
pub fn run(arguments: &[String], data_dir: &Path) -> Result<(), String> {
    let store = AgentStore::in_dir(data_dir);
    match arguments.get(1).map(String::as_str) {
        Some("add") => add(arguments, &store),
        Some("list") => list(&store),
        Some("revoke") => revoke(arguments, &store),
        Some(other) => Err(format!("unknown agent subcommand \"{other}\"\n\n{USAGE}")),
        None => Err(format!("agent needs a subcommand\n\n{USAGE}")),
    }
}

/// `selfhost agent add <name> --grant <cap>[,<cap>]...`
fn add(arguments: &[String], store: &AgentStore) -> Result<(), String> {
    let name = arguments
        .get(2)
        .filter(|word| !word.starts_with("--"))
        .ok_or_else(|| format!("agent add needs a name: `selfhost agent add <name> --grant <cap>...`\n\n{USAGE}"))?;
    let name = AgentName::parse(name).map_err(|error| error.to_string())?;

    let words = grant_words(arguments);
    if words.is_empty() {
        return Err(format!(
            "agent add needs at least one --grant, or the agent can do nothing at all\n\n{USAGE}"
        ));
    }
    let mut capabilities = Vec::with_capacity(words.len());
    for word in &words {
        capabilities.push(agent_store::parse_grant(word).map_err(|error| error.to_string())?);
    }
    let grants = Grants::new(capabilities).map_err(|error| error.to_string())?;

    let minted = store.mint(&name, grants).map_err(|error| format!("could not save the agent store: {error}"))?;
    println!("✓ minted an agent named \"{name}\", granted: {}", words.join(", "));
    println!();
    println!("  {}", minted.as_str());
    println!();
    println!("Record this now — it will not be shown again. On the trusted machine, set:");
    println!("  export SELFHOST_AGENT_TOKEN={}", minted.as_str());
    println!("or write it to ~/.selfhost/agent-token, owner-readable only.");
    Ok(())
}

/// Every `--grant` value, allowing the flag to repeat and each occurrence to
/// be a comma-separated list — the same convention `selfhost people
/// grant`/`selfhost site add --domain` already use.
fn grant_words(arguments: &[String]) -> Vec<String> {
    let mut words = Vec::new();
    for (i, argument) in arguments.iter().enumerate() {
        if argument == "--grant" {
            if let Some(value) = arguments.get(i + 1) {
                words.extend(value.split(',').map(str::trim).filter(|w| !w.is_empty()).map(str::to_owned));
            }
        }
    }
    words
}

/// `selfhost agent list`
fn list(store: &AgentStore) -> Result<(), String> {
    let agents = store.list();
    if agents.is_empty() {
        println!("no agents enrolled — add one with `selfhost agent add <name> --grant <cap>`");
        return Ok(());
    }
    let width = agents.iter().map(|(name, _, _)| name.as_str().len()).max().unwrap_or(4).max(4);
    println!("  {:<width$}  GRANTS", "NAME");
    for (name, grants, _created_unix) in &agents {
        let words: Vec<String> = grants.iter().map(selfhost_admin::people_api::wire_word).collect();
        let rendered = if words.is_empty() { "(nothing)".to_owned() } else { words.join(", ") };
        println!("  {:<width$}  {rendered}", name.as_str());
    }
    Ok(())
}

/// `selfhost agent revoke <name>`
fn revoke(arguments: &[String], store: &AgentStore) -> Result<(), String> {
    let name = arguments
        .get(2)
        .ok_or_else(|| format!("agent revoke needs a name: `selfhost agent revoke <name>`\n\n{USAGE}"))?;
    let name = AgentName::parse(name).map_err(|error| error.to_string())?;
    match store.revoke(&name) {
        Ok(true) => {
            println!("✓ revoked \"{name}\" — its token stops working on the daemon's next check");
            Ok(())
        }
        Ok(false) => Err(format!("no agent named \"{name}\"")),
        Err(error) => Err(format!("could not save the agent store: {error}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("selfhost-agentcmd-test-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        path
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn adding_an_agent_then_listing_it_shows_its_grants() {
        let dir = scratch("add-list");
        run(&args(&["agent", "add", "claude-mac", "--grant", "site.admin"]), &dir).expect("mints");
        let store = AgentStore::in_dir(&dir);
        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0.as_str(), "claude-mac");
        assert!(listed[0].1.holds(&selfhost_identity::Capability::SiteAdmin));
    }

    #[test]
    fn adding_with_no_grant_is_refused() {
        let dir = scratch("no-grant");
        let error = run(&args(&["agent", "add", "claude-mac"]), &dir).unwrap_err();
        assert!(error.contains("--grant"), "{error}");
    }

    #[test]
    fn revoking_an_unknown_agent_is_refused() {
        let dir = scratch("revoke-unknown");
        let error = run(&args(&["agent", "revoke", "nobody"]), &dir).unwrap_err();
        assert!(error.contains("no agent named"), "{error}");
    }

    #[test]
    fn revoking_a_real_agent_removes_it() {
        let dir = scratch("revoke-real");
        run(&args(&["agent", "add", "claude-mac", "--grant", "site.admin"]), &dir).expect("mints");
        run(&args(&["agent", "revoke", "claude-mac"]), &dir).expect("revokes");
        assert!(AgentStore::in_dir(&dir).list().is_empty());
    }

    #[test]
    fn a_repeat_mint_replaces_the_previous_token() {
        let dir = scratch("remint");
        run(&args(&["agent", "add", "claude-mac", "--grant", "site.admin"]), &dir).expect("mints");
        let store = AgentStore::in_dir(&dir);
        let first_grants = store.list()[0].1.clone();
        assert!(first_grants.holds(&selfhost_identity::Capability::SiteAdmin));

        // Re-minting under the same name is what the module documentation
        // promises: the old token stops working, the new grants take over.
        run(&args(&["agent", "add", "claude-mac", "--grant", "console.read"]), &dir).expect("re-mints");
        let listed = store.list();
        assert_eq!(listed.len(), 1, "the same name, not a second entry");
        assert!(listed[0].1.holds(&selfhost_identity::Capability::ConsoleRead));
        assert!(!listed[0].1.holds(&selfhost_identity::Capability::SiteAdmin));
    }
}
