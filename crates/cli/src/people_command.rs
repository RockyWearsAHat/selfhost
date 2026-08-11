//! `selfhost people` — who this deployment knows, and what each of them may do.
//!
//! # Why the CLI writes the registry directly and does not call the API
//!
//! Every other multi-machine command here talks to the daemon. This one opens
//! `<data_dir>/console.people` itself, for the same reason `console-password`
//! writes the password file itself: it is the command an operator reaches for
//! when the console is the thing that is not working, and a permission tool that
//! needs a working console to grant somebody the ability to use the console is
//! a tool with a cycle in it. The registry is a file, the daemon re-reads it,
//! and both writers persist the same way — a private temporary file and a
//! rename — so a change made here is a change the running daemon honours.
//!
//! # Grants are stated whole, and shown before they are written
//!
//! `grant` takes the complete set a person is to hold, exactly as the API's
//! `PUT` does and for the reason [`selfhost_identity::People::set_grants`]
//! gives. `allow` and `deny` are the convenience forms that read the current set
//! first, and both print the before and after so that a set stated in a hurry is
//! read back before it is a fact.

use selfhost_admin::invite::{DEFAULT_TTL_HOURS, Invites};
use selfhost_config::Config;
use selfhost_identity::{Capability, Grants, People, Person, PersonName};
use std::path::Path;

/// The words this command accepts after `people`, and what each one is for.
pub const USAGE: &str = "\
Usage
  selfhost people list                       Everyone with an entry, and what they hold
  selfhost people show <name>                One person's capabilities
  selfhost people grant <name> <cap>[,<cap>] Replace what they hold with exactly this set
  selfhost people allow <name> <cap>[,<cap>] Add to what they already hold
  selfhost people deny  <name> <cap>[,<cap>] Take these away, leaving the rest
  selfhost people forget <name>              Remove the entry entirely
  selfhost people capabilities               Every capability word, and its target

Letting somebody in
  selfhost people invite <name> [<cap>,…] [--hours N]
                                             Grant, then mint a one-time code they
                                             use to register their own passkey
  selfhost people invited                    Who has an invitation pending, until when
  selfhost people uninvite <name>            Withdraw an invitation nobody has used

A capability is a word, and a target after a colon where it takes one:
  console.read       everything the console shows, and nothing it does
  service.control    start/stop/install/deploy services, reconcile the firewall
  files.read:<share> list and download from one share
  files.write:<share> upload, rename and delete in one share (implies read)
  files.admin        every share, the SMB export state, and reconciling it
  desktop.view:<node>    watch one machine's screen
  desktop.control:<node> drive its pointer and keyboard (implies view)
  clipboard.read:<node>  read what was last copied there
  node.admin         invite, revoke and list peer machines
  site.admin         create, change and remove websites
  dns.admin          create, change and remove DNS records
  mail.admin         create, change and remove mailboxes and aliases

The owner is never in this list. The owner's authority is their identity, not a
grant, so it cannot be edited away here — which is what keeps a mistake in this
file from locking the operator out of the console they would fix it with.
";

/// Runs the command. `arguments[0]` is the word `people`.
///
/// `config` is read for exactly one thing — the console site's hostname, so an
/// invitation can be printed as a link the person can actually open rather than
/// a code with no address attached.
pub fn run(arguments: &[String], data_dir: &Path, config: &Config) -> Result<(), String> {
    let people = selfhost_admin::people_registry(data_dir);
    match arguments.get(1).map(String::as_str) {
        Some("list") | None => list(&people),
        Some("capabilities") => {
            print!("{}", vocabulary());
            Ok(())
        }
        Some("show") => show(&people, name_argument(arguments)?),
        Some("grant") => set(&people, name_argument(arguments)?, wanted(arguments)?),
        Some("allow") => amend(&people, name_argument(arguments)?, wanted(arguments)?, Amend::Add),
        Some("deny") => amend(&people, name_argument(arguments)?, wanted(arguments)?, Amend::Take),
        Some("forget") => forget(&people, name_argument(arguments)?),
        Some("invite") => invite(&people, data_dir, config, arguments),
        Some("invited") => invited(data_dir),
        Some("uninvite") => uninvite(data_dir, name_argument(arguments)?),
        Some(other) => Err(format!("unknown people command \"{other}\"\n\n{USAGE}")),
    }
}

/// Grants what was asked for, then mints the one-time code that lets the person
/// register their own passkey.
///
/// The two halves are one command because they are one intention — "let this
/// person in, with these powers" — and because doing only the first is the
/// mistake this whole subcommand exists to stop an operator making: an entry in
/// the registry with no way to prove you are the person it names is a permission
/// nobody can use. The capability list is optional all the same, since inviting
/// somebody who will be granted things later is a legitimate order to do it in;
/// it just gets said out loud.
///
/// The code is printed once and cannot be printed again — the store keeps only
/// its digest, so a lost code is re-minted rather than looked up.
fn invite(
    people: &People,
    data_dir: &Path,
    config: &Config,
    arguments: &[String],
) -> Result<(), String> {
    let name = name_argument(arguments)?;
    let hours = hours_argument(arguments)?;
    // The capability list is whatever positional argument is not the `--hours`
    // pair, so `invite mom console.read` and `invite mom --hours 4` both read
    // the way they look.
    if let Some(text) = arguments.get(3).filter(|word| !word.starts_with("--")) {
        let capabilities = parse_list(text)?;
        let before = people.find(&name).map(|person| person.grants).unwrap_or_else(Grants::none);
        let after = Grants::new(capabilities)
            .map_err(|_| "too many capabilities for one person".to_owned())?;
        people
            .set_grants(&name, after)
            .map_err(|error| format!("could not write the registry: {error}"))?;
        println!("✓ {name}");
        println!("  was: {}", spell(&before));
        match people.find(&name) {
            Some(person) => println!("  now: {}", spell(&person.grants)),
            None => println!("  now: (the registry accepted the change and lost it)"),
        }
        println!();
    }

    let holds_nothing = people.find(&name).is_none_or(|person| person.grants.is_empty());
    let code = Invites::load(data_dir)
        .mint(&name, hours)
        .map_err(|error| format!("could not write the invitation: {error}"))?;

    println!("✓ an invitation for {name}, good for {hours} hours and usable once");
    println!();
    match console_host(config) {
        Some(host) => {
            println!("  Send them this link:");
            println!();
            println!("    https://{host}/#invite={code}");
        }
        None => {
            // No console site is configured, so there is no address to put the
            // code at. Say that rather than printing half a link.
            println!("  Their code is:");
            println!();
            println!("    {code}");
            println!();
            println!(
                "  This deployment declares no console site, so there is no address to send \
                 them to yet. Add a [[sites]] block with console = true, and they open it \
                 at https://<that host>/#invite=<code>."
            );
        }
    }
    println!();
    println!(
        "  Opening it asks their device for a fingerprint or face and registers a passkey \
         under the name {name}. Nobody needs to be present but them. The code works once and \
         is not stored anywhere it can be read back, so send it now — if it is lost, run this \
         again and the old one stops working."
    );
    if holds_nothing {
        println!();
        println!(
            "  Note: {name} holds nothing, so they will log in to an empty console. \
             `selfhost people allow {name} console.read` is usually the least they want."
        );
    }
    Ok(())
}

/// Who has an invitation pending, and until when.
fn invited(data_dir: &Path) -> Result<(), String> {
    let outstanding = Invites::load(data_dir).outstanding();
    if outstanding.is_empty() {
        println!("No invitation is pending.");
        println!();
        println!("  selfhost people invite <name> console.read");
        println!();
        println!("mints one, and prints the link to send.");
        return Ok(());
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0);
    for entry in &outstanding {
        let left = entry.expires_unix.saturating_sub(now);
        println!();
        println!("{}", entry.name);
        println!("  expires in {} hours", left / 3_600);
    }
    println!();
    println!(
        "{} pending. The codes themselves are not stored and cannot be shown again.",
        outstanding.len()
    );
    Ok(())
}

/// Withdraws an invitation nobody has used yet.
fn uninvite(data_dir: &Path, name: PersonName) -> Result<(), String> {
    match Invites::load(data_dir).revoke(&name) {
        Ok(true) => {
            println!("✓ the invitation for {name} is withdrawn and its code opens nothing");
            println!();
            println!(
                "  Their entry in the registry is untouched. `selfhost people forget {name}` \
                 removes that too."
            );
            Ok(())
        }
        Ok(false) => Err(format!("{name} has no invitation pending; nothing changed")),
        Err(error) => Err(format!("could not write the invitations: {error}")),
    }
}

/// The `--hours N` pair, or [`DEFAULT_TTL_HOURS`] when it is not given.
fn hours_argument(arguments: &[String]) -> Result<u64, String> {
    let Some(index) = arguments.iter().position(|word| word == "--hours") else {
        return Ok(DEFAULT_TTL_HOURS);
    };
    let text = arguments
        .get(index + 1)
        .ok_or_else(|| "--hours needs a number of hours after it".to_owned())?;
    let hours: u64 = text
        .parse()
        .map_err(|_| format!("\"{text}\" is not a number of hours"))?;
    if hours == 0 {
        return Err("an invitation that lasts no time cannot be used".to_owned());
    }
    Ok(hours.min(selfhost_admin::invite::MAX_TTL_HOURS))
}

/// The console site's hostname, if this deployment declares one.
///
/// The first domain of the first site with `console = true`, which is the same
/// name the daemon hands the WebAuthn relying party — so the link printed here
/// is the origin the passkey will actually be scoped to, and not a second guess
/// at it.
fn console_host(config: &Config) -> Option<&str> {
    config
        .sites
        .iter()
        .find(|site| site.console)
        .and_then(|site| site.domains.first())
        .map(String::as_str)
}

/// Whether an amendment adds capabilities or takes them away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Amend {
    /// `allow`.
    Add,
    /// `deny`.
    Take,
}

/// The person named by the third argument, validated.
fn name_argument(arguments: &[String]) -> Result<PersonName, String> {
    let text = arguments.get(2).ok_or_else(|| format!("which person?\n\n{USAGE}"))?;
    PersonName::parse(text).map_err(|_| {
        format!(
            "\"{text}\" is not a usable person name: lower-case letters, digits and dashes, and \
             never the owner's own name, which names an authority that is not granted"
        )
    })
}

/// The comma-separated capability list in the fourth argument.
///
/// An unknown word names itself and stops the whole command, rather than being
/// dropped — a permission list quietly missing an entry is the failure this
/// refusal exists to prevent.
fn wanted(arguments: &[String]) -> Result<Vec<Capability>, String> {
    let text = arguments.get(3).ok_or_else(|| format!("which capabilities?\n\n{USAGE}"))?;
    parse_list(text)
}

/// Reads a comma-separated capability list, whole or not at all.
///
/// Pure, so the rule is asserted rather than trusted.
fn parse_list(text: &str) -> Result<Vec<Capability>, String> {
    text.split(',')
        .map(str::trim)
        .filter(|word| !word.is_empty())
        .map(|word| {
            Capability::parse(word).ok_or_else(|| {
                format!(
                    "\"{word}\" is not a capability this deployment knows, or it is missing the \
                     target it takes; run `selfhost people capabilities` for the list"
                )
            })
        })
        .collect()
}

/// Prints everyone with an entry.
fn list(people: &People) -> Result<(), String> {
    let entries = people.list();
    if entries.is_empty() {
        println!("Nobody but the owner holds anything on this deployment.");
        println!();
        println!("  selfhost people allow <name> console.read");
        println!();
        println!(
            "creates the first entry. They still need a way to prove who they are: a passkey \
             registered under that same name, from the browser console."
        );
        return Ok(());
    }
    for person in &entries {
        print_person(person);
    }
    println!();
    println!(
        "{} {}, and the owner, who is never listed.",
        entries.len(),
        if entries.len() == 1 { "person" } else { "people" }
    );
    Ok(())
}

/// Prints one person's entry, or says there is none.
fn show(people: &People, name: PersonName) -> Result<(), String> {
    match people.find(&name) {
        Some(person) => {
            print_person(&person);
            Ok(())
        }
        None => Err(format!(
            "{name} has no entry here, so they hold nothing; `selfhost people allow {name} \
             console.read` makes one"
        )),
    }
}

/// One entry: the name, then a line per capability.
fn print_person(person: &Person) {
    println!();
    println!("{}", person.name);
    if person.grants.is_empty() {
        println!("  holds nothing");
        return;
    }
    for capability in person.grants.iter() {
        println!("  {}", selfhost_admin::people_api::wire_word(capability));
    }
}

/// Replaces a person's set with exactly `capabilities`.
fn set(people: &People, name: PersonName, capabilities: Vec<Capability>) -> Result<(), String> {
    let before = people.find(&name).map(|person| person.grants).unwrap_or_else(Grants::none);
    let after = Grants::new(capabilities).map_err(|_| "too many capabilities for one person".to_owned())?;
    write(people, &name, &before, after)
}

/// Adds to or takes from what a person already holds.
fn amend(
    people: &People,
    name: PersonName,
    capabilities: Vec<Capability>,
    how: Amend,
) -> Result<(), String> {
    let before = people.find(&name).map(|person| person.grants).unwrap_or_else(Grants::none);
    let mut after = before.clone();
    for capability in capabilities {
        match how {
            Amend::Add => {
                after
                    .grant(capability)
                    .map_err(|_| "too many capabilities for one person".to_owned())?;
            }
            Amend::Take => {
                after.revoke(&capability);
            }
        }
    }
    write(people, &name, &before, after)
}

/// Persists a change and reports it as a before and an after.
fn write(people: &People, name: &PersonName, before: &Grants, after: Grants) -> Result<(), String> {
    let unchanged = before == &after;
    people
        .set_grants(name, after)
        .map_err(|error| format!("could not write the registry: {error}"))?;
    if unchanged {
        println!("✓ {name} already held exactly that; nothing changed");
    } else {
        println!("✓ {name}");
        println!("  was: {}", spell(before));
        match people.find(name) {
            Some(person) => println!("  now: {}", spell(&person.grants)),
            None => println!("  now: (the registry accepted the change and lost it)"),
        }
    }
    println!();
    println!(
        "  Takes effect on the daemon's next read of the registry. They also need a passkey \
         registered under the name {name} before any of this can be used."
    );
    Ok(())
}

/// A grant set on one line, or the word for an empty one.
fn spell(grants: &Grants) -> String {
    if grants.is_empty() {
        return "nothing".to_owned();
    }
    grants
        .iter()
        .map(selfhost_admin::people_api::wire_word)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Removes an entry entirely.
fn forget(people: &People, name: PersonName) -> Result<(), String> {
    match people.remove(&name) {
        Ok(true) => {
            println!("✓ {name} is no longer in the registry and holds nothing");
            println!();
            println!(
                "  Their passkey is a separate store and still exists. Take it out from the \
                 console's PEOPLE screen, or they can still log in — holding nothing."
            );
            Ok(())
        }
        Ok(false) => Err(format!("{name} had no entry here; nothing changed")),
        Err(error) => Err(format!("could not write the registry: {error}")),
    }
}

/// The capability vocabulary, from the API's own list rather than a second copy.
fn vocabulary() -> String {
    let mut text = String::from("Every capability word, and the target it takes:\n\n");
    for (word, target) in selfhost_admin::people_api::VOCABULARY {
        match target {
            Some(kind) => text.push_str(&format!("  {word}:<{kind}>\n")),
            None => text.push_str(&format!("  {word}\n")),
        }
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_is_read_whole_or_refused_whole() {
        let parsed = parse_list("console.read, files.write:vault").unwrap();
        assert_eq!(parsed.len(), 2);
        // The failure this prevents: a set applied minus the word that did not
        // parse, leaving a person holding something nobody chose.
        let refusal = parse_list("console.read,desktop.view").unwrap_err();
        assert!(refusal.contains("desktop.view"), "the bad word names itself: {refusal}");
    }

    #[test]
    fn an_empty_list_is_the_empty_set_and_not_an_error() {
        // `people grant alex ""` is how an operator says "hold nothing" without
        // removing the entry, and it must not be spelled like a mistake.
        assert!(parse_list("").unwrap().is_empty());
        assert!(parse_list(" , ").unwrap().is_empty());
    }

    #[test]
    fn the_owner_can_never_be_named_as_a_person() {
        // The property the whole command rests on: no invocation of this tool
        // can write an entry that edits the operator's own authority.
        let owner = ["owner".to_owned(), "show".to_owned(), "owner".to_owned()];
        let refusal = name_argument(&owner).unwrap_err();
        assert!(refusal.contains("not a usable person name"), "{refusal}");
    }

    #[test]
    fn every_word_the_help_advertises_is_a_word_that_parses() {
        // USAGE lists the vocabulary for a person reading it; this is the guard
        // that keeps that copy honest against the enum that enforces it.
        for (word, target) in selfhost_admin::people_api::VOCABULARY {
            assert!(USAGE.contains(word), "{word} is missing from the help text");
            let spelling = match target {
                Some("share") => format!("{word}:vault"),
                Some(_) => format!("{word}:alex-desktop"),
                None => word.to_owned(),
            };
            assert!(Capability::parse(&spelling).is_some(), "{spelling}");
        }
    }
}
