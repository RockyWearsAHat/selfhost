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
//! That last clause was **untrue between this command shipping and 2026-08-18**,
//! and it is worth leaving the correction here rather than quietly fixing the
//! sentence. `People` snapshotted the file when it was constructed, and the
//! daemon constructs one at start-up and keeps it, so a grant written here was
//! invisible to the running box until it restarted — and, far worse, so was a
//! revocation. `selfhost people deny` printed a confident ✓ and changed nothing
//! about what the person could actually still do. The fix is in
//! `selfhost_identity::registry`'s `Stored`; the property is pinned by
//! `a_handle_answers_for_the_file_and_not_for_the_moment_it_was_built`.
//!
//! # Grants are stated whole, and shown before they are written
//!
//! `grant` takes the complete set a person is to hold, exactly as the API's
//! `PUT` does and for the reason [`selfhost_identity::People::set_grants`]
//! gives. `allow` and `deny` are the convenience forms that read the current set
//! first, and both print the before and after so that a set stated in a hurry is
//! read back before it is a fact.

use selfhost_admin::invite::{DEFAULT_TTL_HOURS, Invites};
use selfhost_identity::audit::{AuditLog, AuditRecord, Authority};
use selfhost_identity::{Credential, Decision, Identity};
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
  selfhost people invite <name> [<cap>,…] [--hours N] [--email <address>]
                                             Grant, then mint a one-time code they
                                             use to register their own passkey.
                                             --email sends it to them; without it
                                             the code is printed for you to pass on
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
/// `config` is read for exactly one thing — the console site's hostname and the
/// port it is served on, so an invitation can be printed as a link the person
/// can actually open rather than a code with no address attached.
pub fn run(arguments: &[String], data_dir: &Path, config: &Config) -> Result<(), String> {
    let people = selfhost_admin::people_registry(data_dir);
    match arguments.get(1).map(String::as_str) {
        Some("list") | None => list(&people, data_dir),
        Some("capabilities") => {
            print!("{}", vocabulary());
            Ok(())
        }
        Some("show") => show(&people, name_argument(arguments)?, data_dir),
        Some("grant") => set(&people, data_dir, name_argument(arguments)?, wanted(arguments)?),
        Some("allow") => {
            amend(&people, data_dir, name_argument(arguments)?, wanted(arguments)?, Amend::Add)
        }
        Some("deny") => {
            amend(&people, data_dir, name_argument(arguments)?, wanted(arguments)?, Amend::Take)
        }
        Some("forget") => forget(&people, data_dir, name_argument(arguments)?),
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
    // Validate the destination address BEFORE anything is written. A typo that
    // cannot be an address at all must not cost an invitation: minting one
    // supersedes any previous code for this person, so a command that fails
    // halfway would silently revoke a live invitation to punish a typo.
    let recipient = match email_argument(arguments)? {
        Some(typed) => Some(
            crate::invite_email::check_address(&typed).map_err(|error| error.to_string())?,
        ),
        None => None,
    };
    // Fail early on a deployment that cannot send at all, for the same reason:
    // better to refuse before minting than to mint and then discover there is
    // no mail subsystem to hand it to.
    if recipient.is_some() {
        crate::invite_email::sender(config).map_err(|error| error.to_string())?;
    }
    // The capability list is whatever positional argument is not the `--hours`
    // pair, so `invite mom console.read` and `invite mom --hours 4` both read
    // the way they look.
    if let Some(text) = arguments.get(3).filter(|word| !word.starts_with("--")) {
        let capabilities = parse_list(text)?;
        let before = people.find(&name).map(|person| person.grants).unwrap_or_else(Grants::none);
        let after = Grants::new(capabilities)
            .map_err(|_| "too many capabilities for one person".to_owned())?;
        let written = spell(&after);
        people
            .set_grants(&name, after)
            .map_err(|error| format!("could not write the registry: {error}"))?;
        record(data_dir, Authority::GrantsChanged, name.as_str(), &format!("now:{written}"));
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
    // Never the code itself: it exists in exactly one readable place by design,
    // and a log file in the same directory as its digest would be a second.
    record(
        data_dir,
        Authority::InvitationMinted,
        name.as_str(),
        &format!("hours:{hours} holds:{}", if holds_nothing { "nothing" } else { "grants" }),
    );

    println!("✓ an invitation for {name}, good for {hours} hours and usable once");
    println!();
    // The one text that is both shown here and sent, so the operator reads
    // exactly what the person will read rather than a summary of it.
    let instructions = match console_origin(config) {
        Some(origin) => format!(
            "Open this link on the device you want to use, and it will ask for your \
             fingerprint or face:\n\n    {origin}/#invite={code}\n\nThat registers you as \
             \"{name}\". Nobody needs to be present but you. The link works once, and stops \
             working after {hours} hours."
        ),
        None => format!(
            "Your code is:\n\n    {code}\n\nThis deployment declares no console site, so there \
             is no address to open it at yet. It works once, and stops working after {hours} \
             hours."
        ),
    };
    for line in instructions.lines() {
        if line.is_empty() {
            println!();
        } else {
            println!("  {line}");
        }
    }

    if let Some(to) = &recipient {
        println!();
        match crate::invite_email::send(config, data_dir, name.as_str(), to, &instructions) {
            Ok(id) => {
                println!("✓ queued for delivery to {to} (message {id})");
                println!();
                println!(
                    "  Queued is not delivered: the daemon signs it, routes it and retries a \
                     deferral, so read the daemon log if it does not arrive. Check the address \
                     above — a code sent to the wrong person is withdrawn with \
                     `selfhost people uninvite {name}`, which is worth doing immediately rather \
                     than hoping."
                );
            }
            Err(error) => {
                println!("✗ the invitation was minted but not sent: {error}");
            }
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
            record(
                data_dir,
                Authority::InvitationWithdrawn,
                name.as_str(),
                "invitation withdrawn before use",
            );
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

/// The address `--email` names, if it was given.
///
/// Absent is the default and stays the default: an invitation that travels by
/// itself travels to whatever was typed, so sending is something the operator
/// asks for in as many words, never something a flag's default does for them.
fn email_argument(arguments: &[String]) -> Result<Option<String>, String> {
    let Some(index) = arguments.iter().position(|word| word == "--email") else {
        return Ok(None);
    };
    let text = arguments
        .get(index + 1)
        .ok_or_else(|| "--email needs an address after it".to_owned())?;
    if text.starts_with("--") {
        return Err(format!(
            "--email needs an address after it, and \"{text}\" is another option"
        ));
    }
    Ok(Some(text.clone()))
}

/// The origin an invitation link must be opened at, if this deployment declares
/// a console site.
///
/// The first domain of the first site with `console = true`, which is the same
/// name the daemon hands the WebAuthn relying party — so the link printed here
/// is the origin the passkey will actually be scoped to, and not a second guess
/// at it.
///
/// # Why the port is here and is not assumed to be 443
///
/// It used to be assumed. The link was built as `https://{host}/#invite=…`
/// whatever `https_bind` said, so on every deployment not serving HTTPS on 443
/// — which includes the one `selfhost init` writes, and therefore the first
/// deployment anybody following `docs/getting-started.md` builds — the operator
/// was handed a link to a port nothing listens on and told to send it to
/// somebody else. The person receiving it gets a connection refused, on the one
/// credential-issuing door they have no other way through. A hostname with no
/// port is only right on the production shape, and printing an address is
/// exactly the place where "usually right" is worth nothing.
///
/// 443 is still spelled without a port, because that is what a browser and a
/// WebAuthn origin both mean by the bare name, and adding it would make the two
/// spellings of one origin differ.
fn console_origin(config: &Config) -> Option<String> {
    let host = config
        .sites
        .iter()
        .find(|site| site.console)
        .and_then(|site| site.domains.first())?;
    let port = config
        .server
        .https_bind
        .parse::<std::net::SocketAddr>()
        .map(|address| address.port())
        .unwrap_or(443);
    Some(match port {
        443 => format!("https://{host}"),
        other => format!("https://{host}:{other}"),
    })
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
            let capability = Capability::parse(word).ok_or_else(|| {
                format!(
                    "\"{word}\" is not a capability this deployment knows, or it is missing the \
                     target it takes; run `selfhost people capabilities` for the list"
                )
            })?;
            // The same refusal `PUT /api/people/<name>` makes, for the same
            // reason and from the same predicate: a word nothing honours is a
            // promise, and the granting seam is the only place the operator can
            // be told before they rely on it. Two seams, one rule, stated in
            // `Capability::is_honoured` and read here rather than repeated.
            if !capability.is_honoured() {
                return Err(format!(
                    "\"{word}\" is a real capability that nothing in this deployment honours \
                     yet: no route asks for it, so granting it would record a power {} \
                     and you would believe you had delegated something you had not",
                    "its holder cannot use",
                ));
            }
            Ok(capability)
        })
        .collect()
}

/// Writes down an act of authority the CLI performed.
///
/// # Why this command writes to the trail at all
///
/// Because it writes the registry. The console's routes were given audit
/// records on 2026-08-18; this command is the *other* writer of the same file,
/// and a trail that recorded only the half of the writes that went through the
/// browser would be worse than none — it would read as complete. `via:cli` is
/// in every detail below so an operator can tell which door a change came
/// through, since the two have genuinely different threat models: the console
/// needs a passkey, and this needs a shell on the box.
///
/// Recorded as [`Identity::Owner`] with [`Credential::Bearer`], matching
/// `crates/app/cli/src/audit.rs`: a process that can read and write the data
/// directory holds everything the bearer token holds, and claiming a passkey
/// was presented would be the log inventing a ceremony that did not happen.
fn record(data_dir: &Path, authority: Authority, subject: &str, detail: &str) {
    let log = AuditLog::in_dir(data_dir);
    let wrote = AuditRecord::now(
        Identity::Owner,
        Credential::Bearer,
        authority.against(subject),
        Decision::Allow,
        format!("{detail} via:cli"),
    )
    .and_then(|record| log.append(&record));
    if let Err(error) = wrote {
        eprintln!(
            "  ! could not write {} ({error}); this change happened and is unlogged",
            log.path().display()
        );
    }
}

/// Everyone who has registered a passkey under a name that could be a person's,
/// newest registration last.
///
/// # Why this command reads the credential store at all
///
/// Minting a credential and granting a power are deliberately separate acts —
/// `crates/app/admin/src/invite.rs` states why, and that separation is not
/// something to collapse. What it left open is the state *between* them, and
/// that state was invisible from here: redeeming an invitation writes a passkey
/// and nothing else, so somebody who had completed the ceremony and was waiting
/// to be given something appeared in no `selfhost people` output at all.
/// `people list` said "nobody", `people invited` said nothing was pending
/// (their invitation had been spent, correctly), and `people show <name>` said
/// they had no entry — while `selfhost doctor` counted their passkey and the
/// browser console listed it. Two halves of one deployment disagreeing about
/// who exists is how an operator ends up sharing the console password instead
/// of finishing the grant, which is the outcome the whole invite door was built
/// to remove.
///
/// The store is read, never written: this reports a fact about who can prove
/// who they are. It does not confer anything, and being listed here is
/// precisely the state of holding nothing.
///
/// Names that cannot be a person's are dropped rather than shown. The owner's
/// own passkeys are stored under the reserved name `owner`, which
/// [`PersonName::parse`] refuses by design, so the operator never appears in
/// their own waiting list. An owner who deliberately registered a passkey under
/// an ordinary name *will* appear, and that is the honest answer: at that point
/// the deployment holds a named identity with no grants, whoever it belongs to.
fn enrolled_names(data_dir: &Path) -> Vec<PersonName> {
    let mut names: Vec<PersonName> = Vec::new();
    for passkey in selfhost_admin::webauthn::Passkeys::load(data_dir).list() {
        let Ok(name) = PersonName::parse(&passkey.user) else {
            continue;
        };
        if !names.contains(&name) {
            names.push(name);
        }
    }
    names
}

/// Prints everyone with an entry, and everyone who can log in and has not been
/// given anything yet.
fn list(people: &People, data_dir: &Path) -> Result<(), String> {
    let entries = people.list();
    // Somebody with an entry that is empty is in the same stalled state as
    // somebody with no entry at all, so the two are reported together rather
    // than as separate kinds of nothing.
    let waiting: Vec<PersonName> = enrolled_names(data_dir)
        .into_iter()
        .filter(|name| people.find(name).is_none_or(|person| person.grants.is_empty()))
        .collect();

    if entries.is_empty() && waiting.is_empty() {
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

    // Somebody who is in both lists is printed once, in the second: an empty
    // entry beside a registered passkey is the stalled state, not two facts.
    let mut listed = 0;
    for person in &entries {
        if waiting.contains(&person.name) {
            continue;
        }
        print_person(person);
        listed += 1;
    }
    if !waiting.is_empty() {
        println!();
        println!("Registered a passkey and holds nothing — waiting on you:");
        for name in &waiting {
            println!("  {name}");
            println!("    selfhost people allow {name} console.read");
        }
    }
    println!();
    print!(
        "{listed} {}",
        if listed == 1 { "person holds something" } else { "people hold something" }
    );
    if !waiting.is_empty() {
        print!(", {} waiting on you", waiting.len());
    }
    println!(", and the owner, who is never listed.");
    Ok(())
}

/// Prints one person's entry, or says what state they are actually in.
///
/// "No entry" and "no such person" are different answers and were being given
/// the same one. Somebody who has enrolled holds nothing *yet*, which is a
/// waiting grant rather than a typo, and the command that finishes it belongs
/// in the message.
fn show(people: &People, name: PersonName, data_dir: &Path) -> Result<(), String> {
    let enrolled = enrolled_names(data_dir).contains(&name);
    match people.find(&name) {
        Some(person) => {
            print_person(&person);
            if person.grants.is_empty() && enrolled {
                println!("  — but has registered a passkey, so they can log in to an empty console");
            }
            Ok(())
        }
        None if enrolled => {
            println!();
            println!("{name}");
            println!("  holds nothing");
            println!("  — but has registered a passkey, so they can log in to an empty console");
            println!();
            println!("  selfhost people allow {name} console.read");
            Ok(())
        }
        None => Err(format!(
            "{name} has no entry here and has registered no passkey, so they hold nothing and \
             cannot log in; `selfhost people invite {name} console.read` does both"
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
fn set(
    people: &People,
    data_dir: &Path,
    name: PersonName,
    capabilities: Vec<Capability>,
) -> Result<(), String> {
    let before = people.find(&name).map(|person| person.grants).unwrap_or_else(Grants::none);
    let after = Grants::new(capabilities).map_err(|_| "too many capabilities for one person".to_owned())?;
    write(people, data_dir, &name, &before, after)
}

/// Adds to or takes from what a person already holds.
fn amend(
    people: &People,
    data_dir: &Path,
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
    write(people, data_dir, &name, &before, after)
}

/// Persists a change and reports it as a before and an after.
fn write(
    people: &People,
    data_dir: &Path,
    name: &PersonName,
    before: &Grants,
    after: Grants,
) -> Result<(), String> {
    let unchanged = before == &after;
    let written = spell(&after);
    people
        .set_grants(name, after)
        .map_err(|error| format!("could not write the registry: {error}"))?;
    if unchanged {
        // No record: the trail says what changed, and nothing did. A line here
        // would make re-running a command look like a second permission change.
        println!("✓ {name} already held exactly that; nothing changed");
    } else {
        record(data_dir, Authority::GrantsChanged, name.as_str(), &format!("now:{written}"));
        println!("✓ {name}");
        println!("  was: {}", spell(before));
        match people.find(name) {
            Some(person) => println!("  now: {}", spell(&person.grants)),
            None => println!("  now: (the registry accepted the change and lost it)"),
        }
    }
    println!();
    println!(
        "  In effect now: a running daemon re-reads this file, so this needs no restart. \
         They also need a passkey registered under the name {name} before any of this can \
         be used."
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
fn forget(people: &People, data_dir: &Path, name: PersonName) -> Result<(), String> {
    match people.remove(&name) {
        Ok(true) => {
            record(data_dir, Authority::PersonForgotten, name.as_str(), "removed from the registry");
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
    for (word, target, grantable) in selfhost_admin::people_api::VOCABULARY {
        let spelled = match target {
            Some(kind) => format!("  {word}:<{kind}>"),
            None => format!("  {word}"),
        };
        // Shown rather than hidden, and marked rather than silently refused on
        // submit: an operator planning who gets what is entitled to know that a
        // word exists and is not yet wired to anything.
        if grantable {
            text.push_str(&format!("{spelled}\n"));
        } else {
            text.push_str(&format!("{spelled:<28}(no route honours this yet; not grantable)\n"));
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

    /// The config `selfhost init` writes, plus a console site — the shape every
    /// first deployment has, and the one the link used to be wrong on.
    ///
    /// Written as the text an operator would write rather than as a struct
    /// literal, so the fixture goes through the same parser and validator a
    /// real deployment does and cannot describe a config that would be refused.
    fn config_with_console(https_bind: &str) -> Config {
        Config::parse(&format!(
            r#"
version = 1
[server]
http_bind = "127.0.0.1:8080"
https_bind = "{https_bind}"
acme_email = "a@b.com"
acme = "self-signed"
data_dir = "./data"
[[nodes]]
name = "home"
role = "owner"
[[sites]]
name = "console"
domains = ["admin.example.com"]
static_root = "./sites/console"
spa = true
console = true
allowed_cidrs = ["10.66.0.0/24"]
"#
        ))
        .expect("the fixture must be a config this deployment would accept")
    }

    #[test]
    fn an_invitation_link_names_the_port_the_console_is_actually_served_on() {
        // The failure this prevents: the operator is handed a link to :443 on a
        // deployment serving 8443, sends it to somebody else, and that person
        // gets a connection refused on the one door meant to admit them.
        assert_eq!(
            console_origin(&config_with_console("127.0.0.1:8443")).as_deref(),
            Some("https://admin.example.com:8443")
        );
        // And 443 keeps the bare spelling, which is what a browser and a
        // WebAuthn origin both mean by the hostname alone.
        assert_eq!(
            console_origin(&config_with_console("0.0.0.0:443")).as_deref(),
            Some("https://admin.example.com")
        );
    }

    #[test]
    fn a_deployment_with_no_console_site_has_no_link_to_print() {
        let mut config = config_with_console("0.0.0.0:443");
        config.sites.clear();
        assert_eq!(console_origin(&config), None);
    }

    #[test]
    fn somebody_who_has_enrolled_is_visible_even_though_they_hold_nothing() {
        // The stall this closes: redeeming an invitation writes a passkey and
        // nothing else, so between enrolling and being granted a person existed
        // on the box and appeared in no `selfhost people` output at all.
        let dir = std::env::temp_dir()
            .join(format!("selfhost-people-enrolled-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        // The store's own on-disk shape. An uncompressed P-256 point — 0x04 and
        // sixty-four bytes — is all the loader checks, because a public key is
        // verified at login and not at read, so a constant stands in for a real
        // credential without pretending a ceremony happened.
        let key = "BAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
        std::fs::write(
            dir.join(selfhost_admin::webauthn::PASSKEYS_FILENAME),
            format!(
                r#"{{"passkeys":[
                    {{"id":"a","publicKey":"{key}","user":"dad","label":"phone","createdUnix":1}},
                    {{"id":"b","publicKey":"{key}","user":"dad","label":"laptop","createdUnix":2}},
                    {{"id":"c","publicKey":"{key}","user":"owner","label":"mac","createdUnix":3}}
                ]}}"#
            ),
        )
        .expect("writes the fixture");

        let names = enrolled_names(&dir);
        assert_eq!(names.len(), 1, "one person, not one per device: {names:?}");
        assert_eq!(names[0].as_str(), "dad");
        // The operator must never appear in their own waiting list: the owner's
        // passkeys are stored under the reserved name, which `PersonName`
        // refuses in every casing.
        assert!(!names.iter().any(|name| name.as_str().eq_ignore_ascii_case("owner")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_deployment_nobody_has_enrolled_on_lists_nobody() {
        let dir = std::env::temp_dir()
            .join(format!("selfhost-people-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        assert!(enrolled_names(&dir).is_empty(), "a missing store is an empty one");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_word_the_help_advertises_is_a_word_that_parses() {
        // USAGE lists the vocabulary for a person reading it; this is the guard
        // that keeps that copy honest against the enum that enforces it.
        for (word, target, grantable) in selfhost_admin::people_api::VOCABULARY {
            assert!(USAGE.contains(word), "{word} is missing from the help text");
            let spelling = match target {
                Some("share") => format!("{word}:vault"),
                Some(_) => format!("{word}:alex-desktop"),
                None => word.to_owned(),
            };
            let capability = Capability::parse(&spelling).expect(&spelling);
            // And `parse_list` — the seam this command grants through — agrees
            // with the table about which words are offerable. A help text that
            // advertises a word the command then refuses is worse than one that
            // omits it.
            assert_eq!(
                parse_list(&spelling).is_ok(),
                grantable,
                "{word}: the help text and `parse_list` disagree",
            );
            assert_eq!(capability.is_honoured(), grantable, "{word}");
        }
    }

    #[test]
    fn the_help_says_which_words_are_not_grantable_yet() {
        // The two that exist and open nothing are shown rather than hidden —
        // an operator planning who gets what is entitled to know a word exists
        // and is not wired to anything — but they are marked, so nobody plans
        // around one. `site.admin` used to be a third word here; it has a real
        // route now (`crates/app/admin::site_api`) and is offered without the
        // caveat, same as every other honoured word.
        let listed = vocabulary();
        for word in ["dns.admin", "mail.admin"] {
            let line = listed
                .lines()
                .find(|line| line.trim_start().starts_with(word))
                .unwrap_or_else(|| panic!("{word} is missing from `people capabilities`"));
            assert!(line.contains("not grantable"), "{word} is offered without a caveat: {line}");
        }
    }
}
