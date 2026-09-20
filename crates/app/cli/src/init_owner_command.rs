//! `selfhost init-owner <name> --email <address>` — bootstrapping the first
//! owner as an ordinary [`selfhost_identity::Person`] who happens to hold
//! [`Capability::Owner`], rather than the separate `Identity::Owner` +
//! console-password credential this replaces.
//!
//! # Why this always writes the registry directly, with a daemon running or not
//!
//! `selfhost people`'s writer tries the admin API first and only falls back to
//! a direct file write when nothing answers on the loopback admin port — see
//! that module's documentation. This command cannot follow that idiom, because
//! for this one write the API path is not merely inconvenient, it is
//! structurally impossible to succeed on: `PUT /api/people/<name>` is gated by
//! `Demand::OwnerOnly`, which is granted only when
//! `Policy::decide(caller, &Capability::Owner)` allows it, and the bearer
//! (machine) credential this CLI process holds can *never* satisfy that check.
//! `Policy::decide` answers a machine identity from `the_machine_may`, a fixed
//! list that explicitly excludes [`Capability::Owner`] — a leaked bearer token
//! must never be able to mint an owner — and that branch is checked before the
//! owner-blanket-allow branch could ever apply. So a bootstrap tool that tried
//! the API first would always fall through to "refused" while a daemon is
//! running, which is exactly the one moment this command has to work.
//!
//! Writing the registry (and the login-password store beside it) directly is
//! also *sufficient*, not just necessary: both [`selfhost_identity::People`] and [`PersonPasswords`]
//! are deliberately read fresh on every access rather than cached, precisely so
//! that this CLI and a running daemon never disagree about who may do what. A
//! change made here is visible to a running daemon on its very next check —
//! no restart, and no admin-API round trip either.
//!
//! # What this does not yet remove
//!
//! The single shared console password (`Identity::Owner` /
//! `selfhost console-password`) still exists after this command runs. Deleting
//! it is a deliberate later step, made only once `init-owner` has been
//! live-tested — see `index.dx`.

use selfhost_admin::PersonPasswords;
use selfhost_admin::person_password::MIN_PASSWORD_LENGTH;
use selfhost_identity::audit::{AuditLog, AuditRecord, Authority};
use selfhost_identity::{Capability, Credential, Decision, Grants, Identity, PersonEmail, PersonName};
use std::io::IsTerminal;
use std::path::Path;

/// The words this command accepts.
pub const USAGE: &str = "\
Usage
  selfhost init-owner <name> --email <address>

Creates the deployment's first owner: an ordinary Person, holding the `owner`
capability, which `Policy::decide` treats as implying every other one. Refuses
if an owner already exists — a second owner is granted by an existing one,
with `selfhost people grant <name> owner`, not minted by this command.

The password is never a command-line argument: it is prompted for twice, with
no echo, on a real terminal, or read as two lines from stdin otherwise. If
<name> is already a registered Person, this grants them `owner` instead of
creating a duplicate — after confirming the password given matches the one
they already have, or setting it as their first one if they have none.

Writes the registry and the login-password store directly, whether or not a
daemon is running: both are read fresh on every check, so the change is live
immediately and needs no restart.
";

/// Runs the command. `arguments[0]` is the word `init-owner`.
pub fn run(arguments: &[String], data_dir: &Path) -> Result<(), String> {
    refuse_a_password_on_the_command_line(arguments)?;
    refuse_unexpected_shape(arguments)?;
    let name = name_argument(arguments)?;
    let email = email_argument(arguments)?;

    let people = selfhost_admin::people_registry(data_dir);
    if people.any_owner() {
        let owners: Vec<String> = people.owners().iter().map(|owner| owner.name.to_string()).collect();
        return Err(format!(
            "this deployment already has an owner: {}. `selfhost init-owner` only bootstraps \
             the first one; one of them grants a second with \
             `selfhost people grant <name> owner`.",
            owners.join(", ")
        ));
    }

    let existing = people.find(&name);
    if let Some(person) = &existing {
        if let Some(current) = &person.email {
            if current != &email {
                return Err(format!(
                    "{name} is already registered with the login email {current}, not {email}; \
                     this command does not change an existing email — fix the address you typed, \
                     or clear their entry first if {current} is wrong."
                ));
            }
        }
    }

    // Read and validate the password, and — if this Person already has one —
    // confirm it matches, all before anything is written. A command that
    // failed halfway here would leave a Person granted `owner` with no proof
    // of who they are, or would silently overwrite a working password with a
    // typo. See `people_command::invite` for the same shape of reasoning.
    let password = read_new_owner_password()?;
    let passwords = PersonPasswords::in_dir(data_dir);
    if passwords.holds(&name) && !passwords.verify(&name, &password) {
        return Err(format!(
            "the password given does not match {name}'s existing password; nothing was \
             changed. Run this again with their real password, or clear it first with a way \
             that lets you set a new one."
        ));
    }

    // Now perform the writes.
    if !passwords.holds(&name) {
        passwords
            .set(&name, &password)
            .map_err(|error| format!("could not write the login password: {error}"))?;
    }
    let mut grants = existing.as_ref().map(|person| person.grants.clone()).unwrap_or_else(Grants::none);
    grants.grant(Capability::Owner).map_err(|error| error.to_string())?;
    people
        .set_grants(&name, grants)
        .map_err(|error| format!("could not write the registry: {error}"))?;
    let email_already_set = existing.as_ref().and_then(|person| person.email.as_ref()) == Some(&email);
    if !email_already_set {
        people
            .set_email(&name, Some(email.clone()))
            .map_err(|error| format!("could not write the registry: {error}"))?;
    }

    record(data_dir, name.as_str(), &format!("email:{email}"));

    println!("✓ {name} is now the owner");
    println!("  login email: {email}");
    println!();
    println!(
        "  In effect now: the registry and the login password store are both read fresh on \
         every check, so a running daemon sees this immediately — no restart needed."
    );
    Ok(())
}

/// Refuses a password given on the command line, and says why it matters.
///
/// The password is never accepted as an argument at all — not behind a flag,
/// not positionally — so there is no shape of invocation this needs to permit
/// and then warn about. `--password` (bare or `--password=...`) is the one
/// spelling somebody reaching for a `console-password`-style interface would
/// try, so it gets a specific answer instead of falling through to the
/// generic usage refusal.
fn refuse_a_password_on_the_command_line(arguments: &[String]) -> Result<(), String> {
    let offered = arguments
        .iter()
        .any(|argument| argument == "--password" || argument.starts_with("--password="));
    if offered {
        return Err("a password is never given as an argument here: it would sit in this \
             shell's history and in `ps` output on a machine with a public IP. Run \
             `selfhost init-owner <name> --email <address>` with no password, and it will be \
             prompted for (or read from stdin) instead."
            .to_owned());
    }
    Ok(())
}

/// Refuses anything but exactly `init-owner <name> --email <address>`.
fn refuse_unexpected_shape(arguments: &[String]) -> Result<(), String> {
    if arguments.len() != 4 || arguments.get(2).map(String::as_str) != Some("--email") {
        return Err(format!("usage: selfhost init-owner <name> --email <address>\n\n{USAGE}"));
    }
    Ok(())
}

/// The person named by the first argument, validated.
fn name_argument(arguments: &[String]) -> Result<PersonName, String> {
    let text = arguments.get(1).ok_or_else(|| format!("which person?\n\n{USAGE}"))?;
    PersonName::parse(text).map_err(|error| format!("\"{text}\" is not a usable person name: {error}"))
}

/// The `--email <address>` pair, validated.
fn email_argument(arguments: &[String]) -> Result<PersonEmail, String> {
    let text = crate::arguments::value_of(arguments, "--email")
        .ok_or_else(|| format!("which login email?\n\n{USAGE}"))?;
    PersonEmail::parse(&text).map_err(|error| format!("\"{text}\" is not a usable login email: {error}"))
}

/// Reads the new owner's password twice and refuses a mismatch: no echo and
/// [`rpassword`] on a real terminal, two lines from stdin otherwise.
///
/// Never accepts the password as an argument (see
/// [`refuse_a_password_on_the_command_line`]), so this is the *only* way the
/// value enters the process.
fn read_new_owner_password() -> Result<String, String> {
    if std::io::stdin().is_terminal() {
        let first = rpassword::prompt_password("New owner password: ")
            .map_err(|error| format!("could not read the password: {error}"))?;
        let second = rpassword::prompt_password("Repeat it: ")
            .map_err(|error| format!("could not read the password: {error}"))?;
        passwords_match_or_error(&first, &second)
    } else {
        eprintln!("Reading the new owner's password twice from stdin, one line each.");
        let mut first = String::new();
        std::io::stdin()
            .read_line(&mut first)
            .map_err(|error| format!("could not read the password from stdin: {error}"))?;
        let mut second = String::new();
        std::io::stdin()
            .read_line(&mut second)
            .map_err(|error| format!("could not read the password from stdin: {error}"))?;
        passwords_match_or_error(
            first.trim_end_matches(['\r', '\n']),
            second.trim_end_matches(['\r', '\n']),
        )
    }
}

/// The core of [`read_new_owner_password`], pulled out so the mismatch and
/// minimum-length refusals are unit-testable without a real terminal.
///
/// Reuses [`MIN_PASSWORD_LENGTH`] — the same rule [`PersonPasswords::set`]
/// enforces — so a short password is refused here, before anything is
/// written, rather than after the mismatch check has already been trusted.
fn passwords_match_or_error(first: &str, second: &str) -> Result<String, String> {
    if first != second {
        return Err("the passwords did not match; nothing was changed".to_owned());
    }
    if first.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(format!("a login password must be at least {MIN_PASSWORD_LENGTH} characters"));
    }
    Ok(first.to_owned())
}

/// Writes down that this command created or promoted an owner.
///
/// The same pattern `people_command::record` uses — [`Identity::Owner`] with
/// [`Credential::Bearer`] and a `via:cli` suffix, warning rather than failing
/// if the audit write itself fails — kept as its own copy here rather than a
/// shared call because that helper is private to its module and this is a
/// distinct [`Authority`] act, not a grant change.
fn record(data_dir: &Path, subject: &str, detail: &str) {
    let log = AuditLog::in_dir(data_dir);
    let wrote = AuditRecord::now(
        Identity::Owner,
        Credential::Bearer,
        Authority::OwnerInitialized.against(subject),
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

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(label: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir()
            .join(format!("selfhost-init-owner-{label}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("a scratch directory");
        dir
    }

    fn name(text: &str) -> PersonName {
        PersonName::parse(text).expect("a valid name")
    }

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    /// A password long enough for the store to accept.
    const GOOD: &str = "hunter22";

    #[test]
    fn refuses_when_an_owner_already_exists_and_names_them() {
        let data_dir = scratch("existing-owner");
        let people = selfhost_admin::people_registry(&data_dir);
        let mut grants = Grants::none();
        grants.grant(Capability::Owner).unwrap();
        people.set_grants(&name("mom"), grants).unwrap();

        let arguments = args(&["init-owner", "dad", "--email", "dad@example.com"]);
        // The refusal happens before any password is read, so it is safe to
        // call `run` directly even though nothing supplies stdin here: the
        // `any_owner` check is the very first thing after argument parsing.
        let refusal = run(&arguments, &data_dir).unwrap_err();
        assert!(refusal.contains("mom"), "{refusal}");
        assert!(refusal.contains("people grant"), "{refusal}");
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn a_new_person_is_created_with_the_owner_grant_email_and_password() {
        let data_dir = scratch("create");
        let people = selfhost_admin::people_registry(&data_dir);
        assert!(!people.any_owner());

        // The password-reading half is exercised directly here, the way
        // `run` would use it, since a unit test has no real terminal and no
        // piped stdin to read two lines from.
        let password = passwords_match_or_error(GOOD, GOOD).unwrap();
        let passwords = PersonPasswords::in_dir(&data_dir);
        passwords.set(&name("mom"), &password).unwrap();
        let mut grants = Grants::none();
        grants.grant(Capability::Owner).unwrap();
        people.set_grants(&name("mom"), grants).unwrap();
        people.set_email(&name("mom"), Some(PersonEmail::parse("mom@example.com").unwrap())).unwrap();

        assert!(people.any_owner());
        let person = people.find(&name("mom")).expect("the entry exists");
        assert!(person.grants.holds(&Capability::Owner));
        assert_eq!(person.email.as_ref().map(PersonEmail::as_str), Some("mom@example.com"));
        assert!(passwords.verify(&name("mom"), GOOD));
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn a_password_mismatch_is_refused_and_changes_nothing() {
        let refusal = passwords_match_or_error("first-password", "second-password").unwrap_err();
        assert!(refusal.contains("did not match"), "{refusal}");
    }

    #[test]
    fn a_password_shorter_than_the_minimum_is_refused() {
        let refusal = passwords_match_or_error("short", "short").unwrap_err();
        assert!(refusal.contains(&MIN_PASSWORD_LENGTH.to_string()), "{refusal}");
    }

    #[test]
    fn granting_owner_to_an_already_registered_person_does_not_duplicate_them() {
        let data_dir = scratch("grant-existing");
        let people = selfhost_admin::people_registry(&data_dir);
        // Registered already, holding something ordinary and no password yet.
        people.set_grants(&name("dad"), Grants::new([Capability::ConsoleRead]).unwrap()).unwrap();
        assert_eq!(people.len(), 1);

        // No password set yet: the command's own rule is "set it as new".
        let passwords = PersonPasswords::in_dir(&data_dir);
        assert!(!passwords.holds(&name("dad")));
        let password = passwords_match_or_error(GOOD, GOOD).unwrap();
        passwords.set(&name("dad"), &password).unwrap();

        let mut grants = people.find(&name("dad")).unwrap().grants;
        grants.grant(Capability::Owner).unwrap();
        people.set_grants(&name("dad"), grants).unwrap();

        assert_eq!(people.len(), 1, "the same entry was amended, not duplicated");
        let person = people.find(&name("dad")).unwrap();
        assert!(person.grants.holds(&Capability::Owner));
        assert!(person.grants.holds(&Capability::ConsoleRead), "their existing grant survives");
        let _ = std::fs::remove_dir_all(&data_dir);
    }

    #[test]
    fn the_password_never_appears_in_command_line_argument_parsing() {
        let with_flag = args(&["init-owner", "dad", "--email", "dad@example.com", "--password", "hunter22"]);
        let refusal = refuse_a_password_on_the_command_line(&with_flag).unwrap_err();
        assert!(refusal.contains("never given as an argument"), "{refusal}");

        let with_equals = args(&["init-owner", "dad", "--email", "dad@example.com", "--password=hunter22"]);
        let refusal = refuse_a_password_on_the_command_line(&with_equals).unwrap_err();
        assert!(refusal.contains("never given as an argument"), "{refusal}");

        // The ordinary, correct invocation carries no such flag and is not
        // refused by this check.
        let clean = args(&["init-owner", "dad", "--email", "dad@example.com"]);
        assert!(refuse_a_password_on_the_command_line(&clean).is_ok());

        // And no argument-parsing helper in this module has a code path that
        // returns anything password-shaped: `name_argument` and
        // `email_argument` each read one specific, unrelated position.
        assert_eq!(name_argument(&clean).unwrap(), name("dad"));
        assert_eq!(email_argument(&clean).unwrap(), PersonEmail::parse("dad@example.com").unwrap());
    }

    #[test]
    fn the_shape_check_refuses_anything_but_name_and_email() {
        let too_few = args(&["init-owner", "dad"]);
        assert!(refuse_unexpected_shape(&too_few).is_err());

        let missing_flag = args(&["init-owner", "dad", "email", "dad@example.com"]);
        assert!(refuse_unexpected_shape(&missing_flag).is_err());

        let extra = args(&["init-owner", "dad", "--email", "dad@example.com", "extra"]);
        assert!(refuse_unexpected_shape(&extra).is_err());

        let right = args(&["init-owner", "dad", "--email", "dad@example.com"]);
        assert!(refuse_unexpected_shape(&right).is_ok());
    }

    #[test]
    fn a_name_that_is_the_reserved_owner_word_is_refused() {
        let arguments = args(&["init-owner", "owner", "--email", "a@b.com"]);
        let refusal = name_argument(&arguments).unwrap_err();
        assert!(refusal.contains("not a usable person name"), "{refusal}");
    }

    #[test]
    fn an_unparseable_email_is_refused_before_anything_is_read_from_stdin() {
        let arguments = args(&["init-owner", "dad", "--email", "not-an-email"]);
        let refusal = email_argument(&arguments).unwrap_err();
        assert!(refusal.contains("not a usable login email"), "{refusal}");
    }
}
