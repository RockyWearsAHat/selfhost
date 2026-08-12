//! `selfhost storage` — the operating system's half of the NAS.
//!
//! `selfhost share` and `selfhost sync` are about *files*: what this box holds
//! and how to move bytes in and out of it through the resolver, the quota and the
//! collision scan that every other write path uses. This command is about
//! everything the box asks the **operating system** to do on the NAS's behalf,
//! which is a different question with a different failure mode — one that needs a
//! privilege the daemon may not have, and one whose answer differs on each of the
//! three platforms.
//!
//! Two subcommands, and they answer the two questions an operator actually has:
//!
//! - **`storage smb plan|apply`** — is the machine exporting the shares the
//!   config declares, and if not, what would it take? Dry-run by default, exactly
//!   as every other plan-then-apply command here: the plan is printed and nothing is touched until `apply`. The
//!   whole diff, the ownership ledger and the four backends live in
//!   `selfhost_storage::smb`; this module gathers the inputs and presents the
//!   answer.
//! - **`storage discover`** — what would a laptop on this network see, and what
//!   on this machine is going to put it there? The record set is derived purely;
//!   the second half is the honest one, because on Windows the answer is "nothing
//!   publishes these records" and a command that printed a tidy list without
//!   saying so would be describing a network that does not exist.
//!
//! # Why this reads the config rather than asking a running daemon
//!
//! The same reason `share` does: it answers when nothing is running, which is
//! when somebody asks, and it opens the declared shares through the same
//! [`crate::open_shares`] the daemon calls — so a refusal here is word for word
//! the refusal that would stop the daemon.
//!
//! # Two things this command will not do
//!
//! **It never touches a share point this deployment did not create.** That rule
//! lives in `selfhost_storage::smb`'s ownership ledger rather than here, and it is
//! not a nicety: this very Mac exports a pre-existing guest-accessible *"Alex
//! Waldmann's Public Folder"*, and a reconcile that treated "not in my config" as
//! "delete it" would take it away the first time anybody ran this.
//!
//! **It never creates a guest-accessible export.** Also not configurable, and
//! also enforced in the backend rather than here, so no caller can ask for it.
//!
//! # What this cannot fix, and says so instead
//!
//! SMB authenticates against **operating-system accounts** — NTLM, Kerberos,
//! `smbpasswd`. The console password cannot open an SMB session on any of the
//! three platforms. Every output below carries that sentence, from
//! `selfhost_storage::smb::plan::AUTHENTICATION_NOTICE`, because an operator who
//! exports a share and then cannot mount it will otherwise conclude the export
//! failed.

use selfhost_config::Config;
use selfhost_storage::share::Shares;
use selfhost_storage::smb::{self, Apply, OwnershipLedger, SmbError, SyncReport};
use std::net::IpAddr;
use std::path::Path;

/// The `_device-info._tcp` model this box advertises unless told otherwise.
///
/// `Xserve` is one of the two values Apple's own clients recognise, and it is
/// what makes Finder draw a server in the sidebar rather than a generic box.
/// Anything else is legal and simply gets the default icon.
pub(crate) const DEFAULT_MODEL: &str = "Xserve";

/// The name advertised when the config gives nothing better to use.
pub(crate) const FALLBACK_HOSTNAME: &str = "selfhost";

/// Dispatches `storage`'s subcommands.
pub fn storage(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    match arguments.get(1).map(String::as_str) {
        Some("smb") => smb_command(arguments, config, project_dir),
        Some("discover") => discover_command(arguments, config, project_dir),
        Some(other) => Err(format!(
            "unknown storage subcommand \"{other}\" — expected `smb plan`, `smb apply`, or \
             `discover`"
        )),
        None => Err("storage needs a subcommand: `smb plan`, `smb apply`, or `discover`".to_owned()),
    }
}

/// Reconciles the host's SMB exports with what the config declares.
///
/// `plan` is the default and writes nothing; `apply` is the only word that
/// changes the machine. Spelled as two subcommands rather than one plus a flag
/// because this one can *remove* an export, and a flag that is easy to add is a
/// flag that is easy to add by accident.
fn smb_command(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    let apply = requested_apply(arguments.get(2).map(String::as_str))?;

    let shares = declared_shares(config, project_dir)?;
    let exports = smb::plan::desired_exports(&shares)
        .map_err(|error| format!("the declared shares cannot be exported: {error}"))?;
    if exports.is_empty() {
        println!(
            "no share declares a [shares.smb] block, so this box never speaks to its SMB server.\n\
             Add `[shares.smb] name = \"…\"` to a share to export it."
        );
        return Ok(());
    }

    let data_dir = crate::teardown::data_dir(config, project_dir);
    let ledger = OwnershipLedger::under(&data_dir);
    let backend = smb::detect();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start the async runtime: {error}"))?;

    let report = runtime
        .block_on(smb::sync(&backend, &ledger, &shares, apply))
        .map_err(|error| smb_refusal(&error))?;
    print_report(&report, apply, ledger.path());
    Ok(())
}

/// Which mode a word asks for, refusing anything it does not know.
///
/// Pure, and separate from the command, because this is the decision that
/// distinguishes a report from a change to the machine. The absent word is a dry
/// run — an operator who typed `selfhost storage smb` and pressed return has
/// asked a question, not given an instruction — and an unrecognised word is
/// refused rather than defaulted, because the mistake worth guarding against is a
/// mistyped `apply` silently becoming one.
fn requested_apply(word: Option<&str>) -> Result<Apply, String> {
    match word {
        None | Some("plan") => Ok(Apply::DryRun),
        Some("apply") => Ok(Apply::Write),
        Some(other) => {
            Err(format!("unknown smb subcommand \"{other}\" — expected plan or apply"))
        }
    }
}

/// Prints what the reconcile decided, did, and deliberately left alone.
fn print_report(report: &SyncReport, apply: Apply, ledger: &Path) {
    let state = &report.state;
    println!("backend      {} ({})", state.backend.label(), state.backend.tag());
    println!(
        "service      {}",
        match state.service_running {
            Some(true) => "running",
            Some(false) => "not running",
            // Not the same as "no", and said as its own answer: a backend that
            // cannot tell must not be reported as one that said no.
            None => "this platform will not say",
        }
    );
    println!("ledger       {}", ledger.display());

    let plan = &report.plan;
    println!("\nPlan");
    if plan.is_settled() {
        println!("  ✓ the host already exports exactly what the config declares");
    }
    for desired in &plan.create {
        println!("  + create  {:<24} {}{}", desired.name().as_str(), desired.root_text(), flags(desired));
    }
    for update in &plan.update {
        println!(
            "  ~ update  {:<24} {}{}",
            update.desired.name().as_str(),
            update.desired.root_text(),
            flags(&update.desired),
        );
        if update.path_moved() {
            println!("            it currently points at {}", update.live_path);
        }
        if update.live_guest_access {
            println!("            it is currently reachable WITHOUT credentials");
        }
    }
    for name in &plan.remove {
        println!("  - remove  {:<24} no longer declared in the config", name.as_str());
    }
    for name in &plan.forget {
        println!(
            "  · forget  {:<24} gone from the host already; only the ledger changes",
            name.as_str()
        );
    }
    for desired in &plan.keep {
        println!("  = keep    {:<24} {}", desired.name().as_str(), desired.root_text());
    }

    if !plan.conflicts.is_empty() {
        println!("\nRefused — these names belong to share points this deployment did not create");
        for conflict in &plan.conflicts {
            println!(
                "  ! {:<24} {}{}",
                conflict.name.as_str(),
                conflict.existing_path,
                if conflict.existing_guest_access { "  (guest-accessible)" } else { "" },
            );
        }
        println!(
            "  Neither adopted nor deleted. Rename the export in the config, or remove the\n  \
             existing share point with the platform's own tools first."
        );
    }

    if !plan.untouched.is_empty() {
        println!(
            "\n{} other share point(s) on this host, left alone: {}",
            plan.untouched.len(),
            plan.untouched.join(", "),
        );
    }

    if !report.performed.is_empty() {
        println!("\nSteps");
        for step in &report.performed {
            println!(
                "  {:<7} {:<24} {}",
                step.action.tag(),
                step.name.as_str(),
                if step.applied { "done" } else { "not run (dry run)" },
            );
        }
    }

    if !apply.writes() && plan.changes_the_host() {
        println!("\ndry-run: nothing was changed. `selfhost storage smb apply` performs the plan.");
    }

    println!("\n{}", smb::plan::AUTHENTICATION_NOTICE);
}

/// The one-line summary of an export's posture.
fn flags(desired: &smb::DesiredShare) -> String {
    let mut notes = Vec::new();
    if desired.read_only() {
        notes.push("read-only");
    }
    if desired.encrypt() {
        notes.push("encrypted");
    }
    if notes.is_empty() {
        return String::new();
    }
    format!("  ({})", notes.join(", "))
}

/// Turns a backend refusal into something an operator can act on.
///
/// The privilege case is the one worth expanding: every platform wants a
/// different thing, and "access denied" on its own sends a Linux operator looking
/// for an elevated shell that does not exist there.
fn smb_refusal(error: &SmbError) -> String {
    match error {
        SmbError::Denied { program, privilege } => format!(
            "{program} needs {privilege}, which this command does not have — nothing was \
             changed.\n  Re-run it with that privilege, or let the daemon reconcile: it runs as \
             the account the service was installed under."
        ),
        other => other.to_string(),
    }
}

/// Prints the DNS-SD registrations these shares imply, and who will publish them.
///
/// The derivation is pure and lives in `selfhost_storage::discover`; what this
/// adds is the machine's own name and addresses, and the sentence about
/// publication — which is the half an operator is actually asking about, and the
/// half that differs per platform.
fn discover_command(
    arguments: &[String],
    config: &Config,
    project_dir: &Path,
) -> Result<(), String> {
    use selfhost_storage::discover;

    let shares = declared_shares(config, project_dir)?;
    let label = crate::value_of(arguments, "--host")
        .unwrap_or_else(|| advertised_label(config).unwrap_or_else(|| FALLBACK_HOSTNAME.to_owned()));
    let model = crate::value_of(arguments, "--model").unwrap_or_else(|| DEFAULT_MODEL.to_owned());
    let addresses = advertised_addresses(arguments)?;

    let host = discover::HostIdentity::new(&label, &model, addresses)
        .map_err(|error| format!("this machine cannot be advertised as \"{label}\": {error}"))?;
    let dav = dav_endpoint(config)?;

    println!("host         {}.{}", host.hostname(), discover::LOCAL_DOMAIN);
    println!("model        {}", host.model());
    println!(
        "addresses    {}",
        if host.addresses().is_empty() {
            "none — pass --address <ip> to include A/AAAA records".to_owned()
        } else {
            host.addresses().iter().map(IpAddr::to_string).collect::<Vec<_>>().join(", ")
        }
    );
    match dav.as_ref() {
        Some(dav) => println!(
            "webdav       {} port {} ({})",
            dav.target(),
            dav.port(),
            if dav.tls() { "TLS" } else { "plain" }
        ),
        None => println!(
            "webdav       not advertised — no site sets `console = true`, and WebDAV is served \
             on the console site"
        ),
    }

    let ads = discover::advertisements(&shares, &host, dav.as_ref());
    println!("\nRegistrations");
    if ads.is_empty() {
        println!(
            "  none — a share is advertised only when it sets `browsable = true`, and a\n  \
             browsable share contributes an _smb._tcp entry only when it also declares\n  \
             [shares.smb]."
        );
    }
    for advertisement in &ads {
        println!(
            "  {:<16} {}  →  {} port {}",
            advertisement.service.label(),
            advertisement.instance_name(),
            advertisement.target,
            advertisement.port,
        );
        for entry in &advertisement.txt {
            println!("  {:<16}   {entry}", "");
        }
    }

    let records = discover::records(&shares, &host, dav.as_ref());
    println!("\n{} record(s) would be published.", records.len());

    // The honest half, and the reason this subcommand exists rather than a
    // pretty-printer for a record list.
    let publication = discover::publication(std::env::consts::OS);
    println!("\nPublication  {} ({})", publication.tag(), std::env::consts::OS);
    println!("  {}", publication.explanation());
    if !publication.publishes_dns_sd() && !ads.is_empty() {
        println!(
            "  These records are what a responder *would* carry. Nothing on this machine will\n  \
             put them on the wire, and selfhost deliberately does not run its own responder:\n  \
             mDNSResponder and Avahi already own 224.0.0.251:5353, and a second one is treated\n  \
             by Bonjour as a conflicting peer rather than as a helper."
        );
    }

    Ok(())
}

/// Every declared share, opened the way the daemon opens them.
pub(crate) fn declared_shares(config: &Config, project_dir: &Path) -> Result<Shares, String> {
    if config.shares.is_empty() {
        return Err(
            "no [[shares]] are declared in selfhost.config.toml, so there is nothing to export \
             or advertise."
                .to_owned(),
        );
    }
    let data_dir = crate::teardown::data_dir(config, project_dir);
    let volumes = crate::open_shares(config, project_dir, &data_dir)?;
    // The checked shares, in declaration order, from the volumes that were just
    // opened — rather than re-derived from the config, which would be a second
    // reading that could disagree with the daemon's.
    let shares: Vec<_> = volumes.all().iter().map(|volume| volume.share().clone()).collect();
    Shares::new(shares).map_err(|error| format!("the declared shares are not a usable set: {error}"))
}

/// The label to advertise this machine under, taken from the console site.
///
/// The console site's canonical domain is the name this deployment already
/// answers to, so its first label is the name a person on this network will
/// recognise. Reading the machine's own hostname would need an FFI call this
/// crate forbids, and running `hostname` would be a subprocess for a string the
/// config already holds.
pub(crate) fn advertised_label(config: &Config) -> Option<String> {
    let site = config.sites.iter().find(|site| site.console)?;
    let domain = site.domains.first()?;
    let label = domain.split('.').next()?;
    (!label.is_empty()).then(|| label.to_owned())
}

/// The addresses to put in the advertisement's A and AAAA records.
///
/// `--address` may be given more than once and is authoritative when it is. With
/// none, this asks the operating system which local address it would use to reach
/// a remote one — [`crate::investigate::local_address`], the same call `doctor`
/// already makes. **It binds an ephemeral UDP client socket and sends no packet**;
/// nothing listens on it, and it is gone before this function returns.
fn advertised_addresses(arguments: &[String]) -> Result<Vec<IpAddr>, String> {
    let mut given = Vec::new();
    let mut expecting = false;
    for argument in arguments {
        if expecting {
            given.push(
                argument
                    .parse::<IpAddr>()
                    .map_err(|error| format!("--address {argument}: {error}"))?,
            );
            expecting = false;
            continue;
        }
        expecting = argument == "--address";
    }
    if expecting {
        return Err("--address needs an IP address after it".to_owned());
    }
    if !given.is_empty() {
        return Ok(given);
    }
    Ok(crate::investigate::local_address().map(IpAddr::V4).into_iter().collect())
}

/// The WebDAV endpoint to advertise, when this deployment serves one.
///
/// WebDAV is mounted on the console site, so a deployment with no `console =
/// true` site serves none and advertises none. Port 443 and TLS, because that is
/// the only door this box opens: the one public surface is the reverse proxy, and
/// a DNS-SD record pointing anywhere else would be advertising a service that is
/// not there.
pub(crate) fn dav_endpoint(
    config: &Config,
) -> Result<Option<selfhost_storage::discover::DavEndpoint>, String> {
    let Some(site) = config.sites.iter().find(|site| site.console) else {
        return Ok(None);
    };
    let Some(domain) = site.domains.first() else {
        return Ok(None);
    };
    selfhost_storage::discover::DavEndpoint::new(domain, 443, true)
        .map(Some)
        .map_err(|error| format!("the console site's domain cannot be advertised: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config with a console site and one browsable, exported share.
    fn config_with_console() -> Config {
        Config::parse(
            "\
version = 1

[server]
acme_email = \"a@b.com\"
acme = \"self-signed\"

[[nodes]]
name = \"home\"
role = \"owner\"

[[sites]]
name = \"console\"
domains = [\"admin.example.com\"]
static_root = \"./console\"
console = true
allowed_cidrs = [\"127.0.0.1/32\"]
",
        )
        .expect("the config parses")
    }

    #[test]
    fn the_advertised_name_comes_from_the_console_site() {
        assert_eq!(advertised_label(&config_with_console()).as_deref(), Some("admin"));
    }

    #[test]
    fn a_deployment_with_no_console_site_advertises_no_webdav() {
        // WebDAV is served on the console site. Advertising it from a box that
        // serves none would be a record pointing at nothing, which is worse than
        // no record at all: a client that finds it reports a broken server.
        let mut config = config_with_console();
        config.sites.clear();
        assert!(advertised_label(&config).is_none());
        assert_eq!(dav_endpoint(&config).expect("no site is not an error"), None);
    }

    #[test]
    fn the_webdav_endpoint_is_the_console_site_on_the_one_public_port() {
        let dav = dav_endpoint(&config_with_console())
            .expect("the console domain is advertisable")
            .expect("there is a console site");
        assert_eq!(dav.target(), "admin.example.com.");
        assert_eq!(dav.port(), 443);
        assert!(dav.tls(), "the only door this box opens is the proxy's 443");
    }

    #[test]
    fn addresses_given_on_the_command_line_win_and_are_checked() {
        let arguments = vec![
            "storage".to_owned(),
            "discover".to_owned(),
            "--address".to_owned(),
            "192.168.1.8".to_owned(),
            "--address".to_owned(),
            "::1".to_owned(),
        ];
        let addresses = advertised_addresses(&arguments).expect("both parse");
        assert_eq!(addresses.len(), 2);
        assert!(addresses.iter().any(|address| address.is_ipv6()));

        let bad = vec!["storage".to_owned(), "--address".to_owned(), "not-an-ip".to_owned()];
        assert!(advertised_addresses(&bad).is_err(), "a malformed address is refused, not skipped");

        let dangling = vec!["storage".to_owned(), "--address".to_owned()];
        assert!(advertised_addresses(&dangling).is_err());
    }

    #[test]
    fn an_unknown_subcommand_is_refused_rather_than_defaulted() {
        let config = config_with_console();
        let arguments = vec!["storage".to_owned(), "smbb".to_owned()];
        let refusal = storage(&arguments, &config, Path::new("."))
            .expect_err("a typo must not silently do something");
        assert!(refusal.contains("smb plan"), "the refusal names what exists: {refusal}");
    }

    /// The word `apply` is the only thing that changes the machine, and a word
    /// this command does not know changes nothing at all.
    #[test]
    fn only_the_word_apply_writes_and_a_typo_writes_nothing() {
        assert_eq!(requested_apply(None), Ok(Apply::DryRun));
        assert_eq!(requested_apply(Some("plan")), Ok(Apply::DryRun));
        assert_eq!(requested_apply(Some("apply")), Ok(Apply::Write));
        // The mistake this guards against: a mistyped `apply` must not become
        // one, and must not become a dry run that reads as a successful apply
        // either. It is refused.
        assert!(requested_apply(Some("aply")).is_err());
        assert!(requested_apply(Some("--apply")).is_err());
        assert_eq!(Apply::default(), Apply::DryRun, "the crate's own default agrees");
    }
}
