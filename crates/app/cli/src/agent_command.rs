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
use crate::arguments::value_of;
use selfhost_identity::{AgentName, Grants, People, PersonName};
use std::path::Path;

/// The words this command accepts after `agent`, and what each one is for.
pub const USAGE: &str = "\
Usage
  selfhost agent add <name> --person <name> --grant <cap>[,<cap>]...
                                 Mint a scoped credential for a trusted machine,
                                 acting for one registered Person and never
                                 holding more than they do, and print its token
                                 exactly once. Running this again for the
                                 same name replaces its token and grants,
                                 revoking whatever it held before.
  selfhost agent list            Every agent, what it holds, its owner Person,
                                 and when it was minted
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
        Some("add") => add(arguments, &store, &selfhost_admin::people_registry(data_dir)),
        Some("list") => list(&store),
        Some("revoke") => revoke(arguments, &store),
        Some(other) => Err(format!("unknown agent subcommand \"{other}\"\n\n{USAGE}")),
        None => Err(format!("agent needs a subcommand\n\n{USAGE}")),
    }
}

/// `selfhost agent add <name> --person <name> --grant <cap>[,<cap>]...`
fn add(arguments: &[String], store: &AgentStore, people: &People) -> Result<(), String> {
    let name = arguments
        .get(2)
        .filter(|word| !word.starts_with("--"))
        .ok_or_else(|| format!("agent add needs a name: `selfhost agent add <name> --person <name> --grant <cap>...`\n\n{USAGE}"))?;
    let name = AgentName::parse(name).map_err(|error| error.to_string())?;

    let person = value_of(arguments, "--person")
        .ok_or_else(|| format!("agent add needs a --person: `selfhost agent add <name> --person <name> --grant <cap>...`\n\n{USAGE}"))?;
    let person = PersonName::parse(&person).map_err(|error| error.to_string())?;

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

    agent_store::check_mint(people, &person, &grants).map_err(|error| error.to_string())?;

    let minted = store.mint(&name, grants, &person).map_err(|error| format!("could not save the agent store: {error}"))?;
    println!("✓ minted an agent named \"{name}\" for Person \"{person}\", granted: {}", words.join(", "));
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
        println!("no agents enrolled — add one with `selfhost agent add <name> --person <name> --grant <cap>`");
        return Ok(());
    }
    let person_of = |agent: &agent_store::Agent| match &agent.person {
        Some(person) => person.to_string(),
        None => "(none — re-mint with --person; holds nothing)".to_owned(),
    };
    let name_width = agents.iter().map(|agent| agent.name.as_str().len()).max().unwrap_or(4).max(4);
    let person_width = agents.iter().map(|agent| person_of(agent).len()).max().unwrap_or(6).max(6);
    println!("  {:<name_width$}  {:<person_width$}  GRANTS (capped by the Person's own)", "NAME", "PERSON");
    for agent in &agents {
        let words: Vec<String> = agent.grants.iter().map(selfhost_admin::people_api::wire_word).collect();
        let rendered = if words.is_empty() { "(nothing)".to_owned() } else { words.join(", ") };
        println!("  {:<name_width$}  {:<person_width$}  {rendered}", agent.name.as_str(), person_of(agent));
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

    /// A scratch data dir in which `names` are registered People holding
    /// `site.admin` and `console.read`.
    fn scratch_with_people(name: &str, names: &[&str]) -> std::path::PathBuf {
        let dir = scratch(name);
        let people = selfhost_admin::people_registry(&dir);
        for person in names {
            people
                .set_grants(
                    &PersonName::parse(person).unwrap(),
                    Grants::new([
                        selfhost_identity::Capability::SiteAdmin,
                        selfhost_identity::Capability::ConsoleRead,
                    ])
                    .unwrap(),
                )
                .unwrap();
        }
        dir
    }

    #[test]
    fn an_agent_for_an_unknown_person_is_refused() {
        let dir = scratch("unknown-person");
        let error = run(&args(&["agent", "add", "ci-bot", "--person", "nonexistent-person", "--grant", "site.admin"]), &dir)
            .unwrap_err();
        assert!(error.contains("not a registered Person"), "{error}");
        assert!(AgentStore::in_dir(&dir).list().is_empty());
    }

    #[test]
    fn an_agent_may_not_hold_more_than_its_person() {
        let dir = scratch_with_people("beyond", &["intern"]);
        let error = run(&args(&["agent", "add", "bot", "--person", "intern", "--grant", "site.admin,dns.admin"]), &dir)
            .unwrap_err();
        assert!(error.contains("dns.admin") && !error.contains("site.admin,"), "{error}");
        assert!(AgentStore::in_dir(&dir).list().is_empty());
    }

    #[test]
    fn a_person_name_is_validated_like_every_other() {
        let dir = scratch("bad-person");
        let error = run(&args(&["agent", "add", "bot", "--person", "owner", "--grant", "site.admin"]), &dir).unwrap_err();
        assert!(error.contains("may not name a person"), "{error}");
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn adding_an_agent_then_listing_it_shows_its_grants_and_person() {
        let dir = scratch_with_people("add-list", &["Alex"]);
        run(&args(&["agent", "add", "claude-mac", "--person", "Alex", "--grant", "site.admin"]), &dir).expect("mints");
        let store = AgentStore::in_dir(&dir);
        let listed = store.list();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name.as_str(), "claude-mac");
        assert_eq!(listed[0].person.as_ref().map(PersonName::as_str), Some("Alex"));
        assert!(listed[0].grants.holds(&selfhost_identity::Capability::SiteAdmin));
    }

    #[test]
    fn adding_with_no_person_is_refused() {
        let dir = scratch("no-person");
        let error = run(&args(&["agent", "add", "claude-mac", "--grant", "site.admin"]), &dir).unwrap_err();
        assert!(error.contains("--person"), "{error}");
    }

    #[test]
    fn adding_with_no_grant_is_refused() {
        let dir = scratch_with_people("no-grant", &["Alex"]);
        let error = run(&args(&["agent", "add", "claude-mac", "--person", "Alex"]), &dir).unwrap_err();
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
        let dir = scratch_with_people("revoke-real", &["Alex"]);
        run(&args(&["agent", "add", "claude-mac", "--person", "Alex", "--grant", "site.admin"]), &dir).expect("mints");
        run(&args(&["agent", "revoke", "claude-mac"]), &dir).expect("revokes");
        assert!(AgentStore::in_dir(&dir).list().is_empty());
    }

    #[test]
    fn a_repeat_mint_replaces_the_previous_token_and_can_change_person() {
        let dir = scratch_with_people("remint", &["Alex", "Claude"]);
        run(&args(&["agent", "add", "claude-mac", "--person", "Alex", "--grant", "site.admin"]), &dir).expect("mints");
        let store = AgentStore::in_dir(&dir);
        let first_grants = store.list()[0].grants.clone();
        assert!(first_grants.holds(&selfhost_identity::Capability::SiteAdmin));
        assert_eq!(store.list()[0].person.as_ref().map(PersonName::as_str), Some("Alex"));

        // Re-minting under the same name is what the module documentation
        // promises: the old token stops working, the new grants take over.
        run(&args(&["agent", "add", "claude-mac", "--person", "Claude", "--grant", "console.read"]), &dir).expect("re-mints");
        let listed = store.list();
        assert_eq!(listed.len(), 1, "the same name, not a second entry");
        assert!(listed[0].grants.holds(&selfhost_identity::Capability::ConsoleRead));
        assert!(!listed[0].grants.holds(&selfhost_identity::Capability::SiteAdmin));
        assert_eq!(listed[0].person.as_ref().map(PersonName::as_str), Some("Claude"));
    }
}
