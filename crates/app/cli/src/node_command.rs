//! `selfhost node` — enrolling one machine with another.
//!
//! Two commands and a listing. On the owner, `node invite <name>` mints a
//! thirty-two byte secret for a declared worker, stores it, and prints it
//! **once**. On the worker, `node join` reads that secret and stores it where
//! the daemon's dialler will look for it.
//!
//! # The token is read from stdin, never from an argument
//!
//! `docs/SECURITY.md` (VPN-03) already states the rule for this deployment: *an
//! argv password lands in shell history and `ps`*. It applies here without a
//! word of adaptation, and on this box it applies harder than usual — the
//! machine has a public IP, and the process table is readable by every account
//! on it, so a `--token <hex>` would publish the credential to anybody with a
//! shell for as long as the command ran and to `~/.zsh_history` for ever after.
//!
//! So there is no `--token` flag. There is not even a rejected one that prints
//! an error: [`join`] refuses any argument that looks like a token and says why,
//! because an operator who tried it needs to know that the value they just typed
//! is now in their shell history and should be re-minted rather than re-used.
//!
//! # What a token actually authorises
//!
//! It is the HMAC key a worker proves enrolment with, and only that. It never
//! travels on the wire — the proof is a tag computed under it, bound to the one
//! handshake it is presented on, so a captured proof cannot be replayed onto
//! another connection. Holding a token lets a machine *link*; it grants nothing
//! over the owner's desktop, its shares or its console, which is why
//! [`Capability::NodeAdmin`](selfhost_identity::Capability::NodeAdmin)
//! deliberately implies no power over the nodes it manages.
//!
//! # Where the files are, and why they are two different places
//!
//! The owner keeps one file per invited node under `<data_dir>/peers/`, because
//! it has to be able to verify any of them. The worker keeps exactly one, at
//! `<data_dir>/<[mesh].token_file>`, because it links to exactly one owner. A
//! single shared filename would have made a machine that is both — an owner with
//! its own upstream — impossible to configure.

use selfhost_config::{Config, Role};
use selfhost_mesh::enroll::NodeToken;
use std::path::{Path, PathBuf};

/// The directory on an owner holding one token per invited node.
///
/// Public because `doctor` reports which nodes have been invited, and a second
/// spelling of this path would be a second place for it to be wrong.
pub const PEERS_DIR: &str = "peers";

/// Dispatches `node`'s subcommands.
pub fn run(arguments: &[String], config: &Config, data_dir: &Path) -> Result<(), String> {
    match arguments.get(1).map(String::as_str) {
        Some("invite") => invite(arguments, config, data_dir),
        Some("join") => join(arguments, config, data_dir),
        None | Some("list") => list(config, data_dir),
        Some(other) => Err(format!(
            "unknown node subcommand \"{other}\" — expected invite, join, or list"
        )),
    }
}

/// Where an owner keeps the token it minted for one node.
pub fn owner_token_path(data_dir: &Path, node: &str) -> PathBuf {
    data_dir.join(PEERS_DIR).join(format!("{node}.token"))
}

/// Mints a node's enrolment secret, stores it, and prints it once.
///
/// # Why the name must already be declared
///
/// The proof is computed under the node's name, so a token minted for a name
/// that is not in `[[nodes]]` verifies against nothing and produces a worker
/// that dials for ever and is refused every time. Refusing here — with the list
/// of names that *would* work — costs one line and saves that afternoon.
fn invite(arguments: &[String], config: &Config, data_dir: &Path) -> Result<(), String> {
    let name = arguments.get(2).ok_or_else(|| {
        format!(
            "node invite needs the name of a declared node.\n  Declared: {}",
            declared_names(config)
        )
    })?;
    let node = config.nodes.iter().find(|node| &node.name == name).ok_or_else(|| {
        format!(
            "no [[nodes]] entry is named \"{name}\", so a token minted for it would verify \
             against nothing.\n  Declared: {}",
            declared_names(config)
        )
    })?;
    if !matches!(node.role, Role::Worker) {
        return Err(format!(
            "\"{name}\" is declared with role = \"owner\". The owner is the machine that \
             *accepts* links; it is the workers that dial in and need a token."
        ));
    }

    crate::data_dir::create_if_absent(&data_dir.join(PEERS_DIR))
        .map_err(|error| format!("cannot create {}: {error}", data_dir.join(PEERS_DIR).display()))?;

    let token = NodeToken::generate().map_err(|error| {
        format!("cannot mint a token: {error}. The system's random source refused.")
    })?;
    let path = owner_token_path(data_dir, name);
    let previous = path.exists();
    write_secret(&path, &token.to_hex())?;
    crate::audit::Auditor::in_dir(data_dir).node_admin("invite", name);

    if previous {
        println!(
            "note: {name} already had a token and it has been replaced. Its old one stops \
             working at the owner's next daemon restart."
        );
    }
    println!("✓ minted an enrolment token for {name} — {}", path.display());
    println!("\nOn {name}, run this and paste the token when it asks:\n");
    println!("  selfhost node join --owner wss://<this console's hostname>/api/mesh/link\n");
    println!("The token is printed once and is not recoverable from this machine's output");
    println!("afterwards; re-run `selfhost node invite {name}` to mint a fresh one.\n");
    println!("{}", token.to_hex());
    Ok(())
}

/// Stores the owner's token on this worker, reading it from stdin.
///
/// `--owner <url>` is accepted and only *checked*, never written into the
/// config: `[mesh]` is a deployment decision an operator makes once by hand, and
/// a command that holds a secret is the wrong command to also be rewriting the
/// document that decides what this machine dials. When the config disagrees with
/// what was passed, or has no `[mesh]` at all, the exact block to add is
/// printed.
fn join(arguments: &[String], config: &Config, data_dir: &Path) -> Result<(), String> {
    refuse_a_token_on_the_command_line(arguments)?;
    let owner = crate::value_of(arguments, "--owner");

    let token_file = config
        .mesh
        .as_ref()
        .map(|mesh| mesh.token_file.clone())
        .unwrap_or_else(|| PathBuf::from(selfhost_config::mesh::DEFAULT_TOKEN_FILE));
    let path = crate::mesh_task::token_path(data_dir, &token_file);

    eprintln!("Paste the token `selfhost node invite` printed on the owner, then press Enter.");
    eprintln!("It is read from stdin so it never reaches this shell's history or `ps`.");
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|error| format!("could not read the token from stdin: {error}"))?;
    let token = NodeToken::from_hex(&line).map_err(|error| {
        format!(
            "that is not a node token: {error}. It is exactly 64 hex characters, as the owner \
             printed it — check nothing was cut off by the paste."
        )
    })?;

    crate::data_dir::create_if_absent(data_dir)
        .map_err(|error| format!("cannot create {}: {error}", data_dir.display()))?;
    write_secret(&path, &token.to_hex())?;
    let node = config.mesh.as_ref().map_or("this node", |mesh| mesh.node.as_str());
    crate::audit::Auditor::in_dir(data_dir).node_admin("join", node);

    println!("✓ stored the node token — {}", path.display());
    match (config.mesh.as_ref(), owner.as_deref()) {
        (Some(mesh), Some(given)) if mesh.owner_url != given => println!(
            "\nnote: [mesh].owner_url is \"{}\", not \"{given}\". The daemon dials what the \
             config says; edit it if the config is the one that is wrong.",
            mesh.owner_url
        ),
        (Some(mesh), _) => println!(
            "  the daemon dials {} as {} at its next restart",
            mesh.owner_url, mesh.node
        ),
        (None, given) => {
            println!("\nThere is no [mesh] section yet, so nothing dials. Add this to the config:\n");
            println!("[mesh]");
            println!("node = \"<this machine's name in [[nodes]]>\"");
            println!("owner_url = \"{}\"", given.unwrap_or("wss://<owner console host>/api/mesh/link"));
            println!("\nthen restart the daemon.");
        }
    }
    Ok(())
}

/// Shows which nodes are declared and which have been enrolled.
fn list(config: &Config, data_dir: &Path) -> Result<(), String> {
    if config.nodes.is_empty() {
        println!("no [[nodes]] declared — this deployment is one machine");
    } else {
        println!("declared nodes");
        for node in &config.nodes {
            let role = match node.role {
                Role::Owner => "owner",
                Role::Worker => "worker",
            };
            let enrolled = if owner_token_path(data_dir, &node.name).exists() {
                "invited"
            } else {
                "no token minted here"
            };
            println!("  {:<20} {role:<7} {enrolled}", node.name);
        }
    }

    println!("\nthis machine's own link");
    match crate::mesh_task::start(config, data_dir) {
        crate::mesh_task::Posture::Absent => {
            println!("  no [mesh] section — this machine dials nothing and is not a worker");
        }
        posture => println!("  {}", posture.banner().unwrap_or_default()),
    }
    Ok(())
}

/// Refuses a token given on the command line, and says why it matters.
///
/// Checks for the flag *and* for a bare argument that is the right shape,
/// because the mistake this prevents is a person typing what they expected the
/// interface to be — and a token that has been typed is a token that is already
/// in the shell's history whether or not this command accepted it.
fn refuse_a_token_on_the_command_line(arguments: &[String]) -> Result<(), String> {
    let looks_like_a_token = |text: &String| {
        text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
    };
    let offered = arguments.iter().any(|argument| {
        argument == "--token" || argument.starts_with("--token=") || looks_like_a_token(argument)
    });
    if !offered {
        return Ok(());
    }
    Err("a node token is never passed as an argument: it would be in this shell's history, in \
         `ps` output, and in the process table of a machine with a public IP.\n  \
         Mint a fresh one with `selfhost node invite <name>` on the owner — treat the one you \
         just typed as burned — and run `selfhost node join` with no token, which reads it from \
         stdin."
        .to_owned())
}

/// Writes a secret so that only this account can read it.
///
/// # The Windows half is honest rather than pretended
///
/// On unix the file is created `0600` from the outset by
/// [`selfhost_identity::write_owner_only`] — created, not chmod'ed afterwards,
/// because the gap between those two steps is exactly when a shared machine gets
/// to read it.
///
/// On Windows that function refuses, and this one falls back to an ordinary
/// write followed by **reading the resulting ACL back** and telling the operator
/// what it admits. That is the same shape [`crate::data_dir`] settles for and it
/// is settled for the same reason: this workspace has exactly one audited
/// Windows ACL implementation, it is private to `selfhost_admin::token`, and a
/// second one written here would be a second thing to get right, to audit, and
/// to drift. The gap is visible in this command's own output rather than
/// invisible everywhere.
fn write_secret(path: &Path, contents: &str) -> Result<(), String> {
    match selfhost_identity::write_owner_only(path, contents) {
        Ok(()) => Ok(()),
        // The reason is carried, not dropped. This is a *credential* failing to
        // land, and "cannot write it privately" without the cause is what sends
        // an operator to check permissions on a disk that is simply full.
        Err(error) if cfg!(unix) => {
            Err(format!("cannot write {} privately: {error}", path.display()))
        }
        Err(error) => {
            // Kept for the same reason, and reported only if the fallback also
            // fails: on Windows the private write is *expected* to be refused —
            // there is one audited ACL implementation and it is not this one —
            // so a first failure here is the ordinary path rather than news.
            let private_write_refused = error;
            std::fs::write(path, contents).map_err(|fallback| {
                format!(
                    "cannot write {}: {fallback} (the private write was refused first: \
                     {private_write_refused})",
                    path.display()
                )
            })?;
            match selfhost_admin::token::privacy_of(path) {
                Ok(selfhost_admin::token::Privacy::Private(_)) => {}
                Ok(selfhost_admin::token::Privacy::Exposed(detail)) => println!(
                    "warning: {} is readable beyond this account ({detail}). It is a credential; \
                     tighten it before this machine is left running.",
                    path.display()
                ),
                Ok(selfhost_admin::token::Privacy::Unanswerable(why)) => println!(
                    "warning: cannot tell who may read {} ({why}); treat it as readable by this \
                     machine's other accounts until it can be checked.",
                    path.display()
                ),
                Err(error) => println!(
                    "warning: cannot inspect the permissions of {} ({error}).",
                    path.display()
                ),
            }
            Ok(())
        }
    }
}

/// Every declared node's name, for a refusal that has to name the alternatives.
fn declared_names(config: &Config) -> String {
    if config.nodes.is_empty() {
        return "none — this config declares no [[nodes]]".to_owned();
    }
    config.nodes.iter().map(|node| node.name.as_str()).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_nodes() -> Config {
        Config::parse(
            "version = 1\n\n[server]\nacme_email = \"a@b.com\"\nacme = \"self-signed\"\n\n\
             [[nodes]]\nname = \"home\"\nrole = \"owner\"\n\n\
             [[nodes]]\nname = \"alex-desktop\"\nrole = \"worker\"\n",
        )
        .expect("the config parses")
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("selfhost-node-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create the temp dir");
        dir
    }

    /// The rule this module exists to enforce.
    #[test]
    fn a_token_on_the_command_line_is_refused_and_declared_burned() {
        let hex = "ab".repeat(32);
        for argument in [format!("--token={hex}"), "--token".to_owned(), hex] {
            let arguments = vec!["node".to_owned(), "join".to_owned(), argument.clone()];
            let refusal = refuse_a_token_on_the_command_line(&arguments)
                .expect_err("a token on argv is always refused");
            assert!(refusal.contains("shell's history"), "{refusal}");
            assert!(refusal.contains("burned"), "{argument}: {refusal}");
        }
    }

    /// An ordinary flag must not be mistaken for a token.
    #[test]
    fn the_owner_url_is_not_mistaken_for_a_token() {
        let arguments = vec![
            "node".to_owned(),
            "join".to_owned(),
            "--owner".to_owned(),
            "wss://admin.example.com/api/mesh/link".to_owned(),
        ];
        assert!(refuse_a_token_on_the_command_line(&arguments).is_ok());
    }

    #[test]
    fn a_token_is_only_minted_for_a_declared_worker() {
        let dir = temp_dir("invite");
        let config = config_with_nodes();

        let missing = invite(
            &["node".to_owned(), "invite".to_owned(), "nowhere".to_owned()],
            &config,
            &dir,
        )
        .expect_err("an undeclared node is refused");
        assert!(missing.contains("alex-desktop"), "the refusal lists what would work: {missing}");

        let owner =
            invite(&["node".to_owned(), "invite".to_owned(), "home".to_owned()], &config, &dir)
                .expect_err("the owner accepts links rather than dialling");
        assert!(owner.contains("role = \"owner\""), "{owner}");

        invite(
            &["node".to_owned(), "invite".to_owned(), "alex-desktop".to_owned()],
            &config,
            &dir,
        )
        .expect("a declared worker is invited");
        let stored = std::fs::read_to_string(owner_token_path(&dir, "alex-desktop"))
            .expect("the token is stored");
        assert_eq!(stored.len(), 64, "a full-length token is written: {stored:?}");
        assert!(NodeToken::from_hex(&stored).is_ok(), "and it is readable back");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Inviting the same node twice must produce a *different* token, or the
    /// re-mint an operator reaches for after a leak would change nothing.
    #[test]
    fn re_inviting_replaces_the_token() {
        let dir = temp_dir("reinvite");
        let config = config_with_nodes();
        let arguments = ["node".to_owned(), "invite".to_owned(), "alex-desktop".to_owned()];

        invite(&arguments, &config, &dir).expect("first invite");
        let first = std::fs::read_to_string(owner_token_path(&dir, "alex-desktop")).expect("read");
        invite(&arguments, &config, &dir).expect("second invite");
        let second = std::fs::read_to_string(owner_token_path(&dir, "alex-desktop")).expect("read");

        assert_ne!(first, second, "a re-mint that reissued the same secret would be no re-mint");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One line per control action, and inviting a node is one.
    #[test]
    fn inviting_a_node_writes_exactly_one_audit_line() {
        let dir = temp_dir("audit");
        let config = config_with_nodes();
        invite(
            &["node".to_owned(), "invite".to_owned(), "alex-desktop".to_owned()],
            &config,
            &dir,
        )
        .expect("invited");
        let log = std::fs::read_to_string(dir.join("audit.log")).expect("the log exists");
        assert_eq!(log.lines().count(), 1, "{log}");
        let line = log.lines().next().unwrap_or_default();
        assert!(line.contains("capability=node.admin"), "{line}");
        assert!(line.contains("detail=invite:alex-desktop"), "{line}");
        assert!(!line.contains(&std::fs::read_to_string(
            owner_token_path(&dir, "alex-desktop")
        ).unwrap_or_default()), "the token is never written into the log");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// On unix the token file must be unreadable by anybody else the moment it
    /// exists, which is the whole reason it is not written with `fs::write`.
    #[cfg(unix)]
    #[test]
    fn a_stored_token_is_private_from_the_moment_it_exists() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("private");
        let config = config_with_nodes();
        invite(
            &["node".to_owned(), "invite".to_owned(), "alex-desktop".to_owned()],
            &config,
            &dir,
        )
        .expect("invited");
        let mode = std::fs::metadata(owner_token_path(&dir, "alex-desktop"))
            .expect("the token exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the token is owner-only, not {mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
