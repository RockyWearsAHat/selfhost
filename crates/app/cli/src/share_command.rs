//! `selfhost share` and `selfhost sync` — the NAS from a terminal on the box.
//!
//! # Why this reads the config and not the daemon
//!
//! Every command here opens the declared shares itself, through the same
//! [`Volumes::open`] the daemon calls, rather than asking a running daemon over
//! loopback. Two reasons, and the second is the load-bearing one:
//!
//! - It answers when nothing is running, which is when somebody asks. This is
//!   the principle `selfhost services` already follows for the catalogue.
//! - **It is the same code.** The resolver that refuses `..` after trimming
//!   trailing dots, the descriptor walk that refuses a reparse point, the
//!   case-collision scan, the quota admission and the free-space floor are all
//!   inside [`selfhost_storage`], and a CLI that copied a file with
//!   `std::fs::copy` would be a second write path with none of them. A file
//!   arriving over WebDAV, from the browser, or from this command lands under
//!   exactly one set of rules.
//!
//! The one consequence worth stating: these commands write as **the owner**.
//! They are run by somebody with a shell on the box, who could edit the config
//! that declares the shares in the first place, so a per-person grant would be
//! ceremony rather than a boundary. A share's `read_only` flag is still
//! honoured, because that is a statement about the data and it binds the owner
//! too.
//!
//! # Dry-run by default
//!
//! `sync` prints its plan and writes nothing unless `--apply` is passed, which
//! is the convention every plan-then-apply command here follows. A copy that silently overwrote a file
//! because the operator got an argument order wrong is exactly the mistake this
//! costs one word to prevent.

use selfhost_admin::storage_api::Volumes;
use selfhost_config::Config;
use selfhost_identity::Identity;
use selfhost_storage::fs::Existing;
use selfhost_storage::listing::Kind;
use selfhost_storage::{RelativePath, Volume};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// How many bytes move per read/write turn.
///
/// The same 64 KiB the storage crate copies with, so a large file costs one
/// buffer here as it does there rather than one allocation per file.
const COPY_BUFFER_BYTES: usize = 64 * 1024;

/// The deepest local tree `sync push` will descend.
///
/// Matches [`selfhost_storage::fs::MAX_TREE_DEPTH`], so a tree this refuses to
/// walk is the same tree the share would refuse to hold — one limit, stated in
/// one place, rather than a walk that succeeds and a write that then fails
/// halfway through.
const MAX_DEPTH: usize = selfhost_storage::fs::MAX_TREE_DEPTH;

/// Dispatches `share`'s subcommands.
pub fn share(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    let volumes = open(config, project_dir)?;
    match arguments.get(1).map(String::as_str) {
        None | Some("list") => list(&volumes),
        Some("usage") => usage(&volumes, arguments.get(2).map(String::as_str)),
        Some("ls") => ls(&volumes, arguments.get(2).map(String::as_str)),
        Some(other) => Err(format!(
            "unknown share subcommand \"{other}\" — expected list, usage, or ls"
        )),
    }
}

/// Dispatches `sync`'s subcommands.
pub fn sync(arguments: &[String], config: &Config, project_dir: &Path) -> Result<(), String> {
    let apply = arguments.iter().any(|argument| argument == "--apply");
    let volumes = open(config, project_dir)?;
    match arguments.get(1).map(String::as_str) {
        Some("push") => push(&volumes, arguments.get(2), arguments.get(3), apply),
        Some("pull") => pull(&volumes, arguments.get(2), arguments.get(3), apply),
        Some(other) => Err(format!("unknown sync subcommand \"{other}\" — expected push or pull")),
        None => Err("sync needs a subcommand: push or pull".to_owned()),
    }
}

/// Opens every declared share, or says why one cannot be served.
///
/// One call, shared with the daemon's own start-up: an operator who fixes what
/// this reports has fixed what would otherwise stop the daemon, because it is
/// the same check and the same sentence.
fn open(config: &Config, project_dir: &Path) -> Result<Volumes, String> {
    if config.shares.is_empty() {
        return Err(
            "no [[shares]] are declared in selfhost.config.toml, so there is nothing to serve.\n  \
             `selfhost init` writes a commented example block to start from."
                .to_owned(),
        );
    }
    let data_dir = crate::teardown::data_dir(config, project_dir);
    crate::open_shares(config, project_dir, &data_dir)
}

/// Prints every declared share and the posture it is served under.
fn list(volumes: &Volumes) -> Result<(), String> {
    let width = volumes
        .all()
        .iter()
        .map(|volume| volume.share().id().as_str().len())
        .max()
        .unwrap_or(0)
        .max(2);
    println!("  {:<width$}  {:<10}  ROOT", "ID", "MODE");
    for volume in volumes.all() {
        let share = volume.share();
        println!(
            "  {:<width$}  {:<10}  {}",
            share.id().as_str(),
            if share.read_only() { "read-only" } else { "writable" },
            share.root().display(),
        );
        let mut notes = Vec::new();
        if let Some(quota) = share.quota_bytes() {
            notes.push(format!("quota {}", human(quota)));
        }
        if share.browsable() {
            notes.push("advertised over DNS-SD".to_owned());
        }
        if let Some(smb) = share.smb() {
            notes.push(format!(
                "smb \"{}\"{}",
                smb.name.as_str(),
                if share.smb_read_only() { ", read-only" } else { "" }
            ));
        }
        for grant in share.grants() {
            notes.push(format!("{} may {}", grant.user, grant.mode.tag()));
        }
        if !notes.is_empty() {
            println!("  {:<width$}  {}", "", notes.join(" · "));
        }
    }
    println!(
        "\nSMB authenticates against operating-system accounts. The console password cannot\n\
         open an SMB session on any platform; the browser, WebDAV and these commands use it."
    );
    Ok(())
}

/// Prints what each share holds and what is left.
///
/// Measuring a subtree is a walk, so this is deliberately its own command rather
/// than a column of `share list`: a listing that took thirty seconds on a large
/// share would stop being run.
fn usage(volumes: &Volumes, only: Option<&str>) -> Result<(), String> {
    let chosen = select(volumes, only)?;
    for volume in chosen {
        let share = volume.share();
        let usage = volume
            .usage()
            .map_err(|error| format!("cannot measure share \"{}\": {error}", share.id().as_str()))?;
        let (available, used) = volume
            .quota()
            .map_err(|error| format!("cannot read share \"{}\"'s quota: {error}", share.id().as_str()))?;

        println!("{}", share.id().as_str());
        println!("  root       {}", share.root().display());
        println!("  holding    {}", human(used));
        match share.quota_bytes() {
            Some(quota) => println!(
                "  quota      {} · {} still accepted",
                human(quota),
                human(available)
            ),
            None => println!("  quota      none — bounded only by the volume"),
        }
        println!("  volume     {} free", human(usage.free_bytes));
    }
    Ok(())
}

/// Lists one directory inside one share.
fn ls(volumes: &Volumes, target: Option<&str>) -> Result<(), String> {
    let target = target.ok_or_else(|| {
        "share ls needs a share and an optional path: `selfhost share ls vault:photos`".to_owned()
    })?;
    let (id, path) = split_target(target)?;
    let volume = find(volumes, &id)?;
    let at = volume
        .resolve(&path)
        .map_err(|error| format!("{path}: {error}"))?;
    let listing = volume
        .listing(&Identity::Owner, &at)
        .map_err(|error| format!("cannot list {id}:{path} — {error}"))?;

    if listing.entries.is_empty() {
        println!("{id}:{at} is empty");
        return Ok(());
    }
    for entry in &listing.entries {
        let size = match entry.kind {
            Kind::Directory => "        —".to_owned(),
            Kind::File => format!("{:>9}", human(entry.size)),
        };
        let mark = match (entry.kind, &entry.blocked) {
            // A name the share cannot serve is shown, because pretending a file
            // is not there is how an operator concludes the copy worked.
            (_, Some(why)) => format!("  ! {}", why.reason()),
            (Kind::Directory, None) => "/".to_owned(),
            (Kind::File, None) => String::new(),
        };
        println!("  {size}  {}{mark}", entry.name);
    }
    Ok(())
}

/// Copies a local file or tree into a share.
fn push(
    volumes: &Volumes,
    from: Option<&String>,
    to: Option<&String>,
    apply: bool,
) -> Result<(), String> {
    let (from, to) = pair(from, to, "sync push <local-path> <share>:<path>")?;
    let (id, path) = split_target(to)?;
    let volume = find(volumes, &id)?;
    if volume.share().read_only() {
        return Err(format!(
            "share \"{id}\" is published read-only, so nothing can be written to it.\n  \
             Set read_only = false on its [[shares]] block if that is not what you meant."
        ));
    }

    let source = PathBuf::from(from);
    let base = volume.resolve(&path).map_err(|error| format!("{path}: {error}"))?;
    let mut steps = Vec::new();
    collect(&source, &base, volume, &mut steps, 0)?;
    if steps.is_empty() {
        println!("nothing to copy — {} holds no files this can carry", source.display());
        return Ok(());
    }
    let folders = missing_folders(volume, &steps);

    report(&steps, &folders, &id);
    if !apply {
        println!("\nDry run — nothing was written. Pass --apply to carry this out.");
        return Ok(());
    }
    if folders.is_empty() && steps.iter().all(|step| step.action == Action::Unchanged) {
        println!("\n✓ \"{id}\" already holds every one of these files");
        return Ok(());
    }

    println!();
    for folder in &folders {
        volume
            .create_directory(&Identity::Owner, folder)
            .map_err(|error| format!("cannot create {folder}/: {error}"))?;
        println!("  {:<9} {folder}/", "created");
    }
    let mut copied = 0u64;
    for step in &steps {
        if step.action == Action::Unchanged {
            continue;
        }
        upload(volume, step)?;
        copied = copied.saturating_add(step.size);
        println!("  {:<9} {}", step.action.verb(), step.remote);
    }
    println!("\n✓ {} written to \"{id}\"", human(copied));
    Ok(())
}

/// Copies a file or tree out of a share onto the local disk.
fn pull(
    volumes: &Volumes,
    from: Option<&String>,
    to: Option<&String>,
    apply: bool,
) -> Result<(), String> {
    let (from, to) = pair(from, to, "sync pull <share>:<path> <local-path>")?;
    let (id, path) = split_target(from)?;
    let volume = find(volumes, &id)?;
    volume
        .permit(&Identity::Owner, selfhost_storage::Want::Read)
        .map_err(|error| format!("cannot read share \"{id}\": {error}"))?;

    let base = volume.resolve(&path).map_err(|error| format!("{path}: {error}"))?;
    let destination = PathBuf::from(to);
    let mut steps = Vec::new();
    gather(volume, &base, &destination, &mut steps, 0)?;
    if steps.is_empty() {
        println!("nothing to copy — {id}:{base} holds no files");
        return Ok(());
    }

    report(&steps, &[], &id);
    if !apply {
        println!("\nDry run — nothing was written. Pass --apply to carry this out.");
        return Ok(());
    }
    if steps.iter().all(|step| step.action == Action::Unchanged) {
        println!("\n✓ {} already holds every one of these files", destination.display());
        return Ok(());
    }

    println!();
    let mut copied = 0u64;
    for step in &steps {
        if step.action == Action::Unchanged {
            continue;
        }
        download(volume, step)?;
        copied = copied.saturating_add(step.size);
        println!("  {:<9} {}", step.action.verb(), step.local.display());
    }
    println!("\n✓ {} written to {}", human(copied), destination.display());
    Ok(())
}

/// What one file's copy will do.
///
/// Three answers rather than two because "already there and the same" is the
/// common case on a second run, and a plan that listed it as an overwrite would
/// make a re-sync look like a rewrite of the whole share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    /// Nothing is at the destination.
    Create,
    /// Something is, and it will be replaced.
    Replace,
    /// Something is, and it already matches.
    Unchanged,
}

impl Action {
    /// The word printed beside the path.
    fn verb(self) -> &'static str {
        match self {
            Self::Create => "created",
            Self::Replace => "replaced",
            Self::Unchanged => "unchanged",
        }
    }
}

/// One file to copy, and what copying it will do.
#[derive(Debug, Clone)]
struct Step {
    /// Where it is (push) or where it will land (pull), on the local disk.
    local: PathBuf,
    /// Where it will land (push) or where it is (pull), inside the share.
    remote: RelativePath,
    /// Its size in bytes, as the source reports it.
    size: u64,
    /// What copying it will do.
    action: Action,
}

/// Whether two ends of a copy already agree.
///
/// # This is a heuristic and it is named as one
///
/// Same size, and a destination no older than the source. That is what `rsync`
/// calls its quick check, and it is wrong in exactly one case: a file edited in
/// place without changing its length or its modification time. Nothing here
/// hashes gigabytes to close that gap — a NAS sync that read every byte of both
/// ends would be slower than copying — so the rule is stated instead, and
/// `--apply` on a plan that says `unchanged` copies nothing.
fn already_there(source_size: u64, source_time: Option<std::time::SystemTime>, target_size: u64, target_time: Option<std::time::SystemTime>) -> bool {
    if source_size != target_size {
        return false;
    }
    match (source_time, target_time) {
        (Some(source), Some(target)) => target >= source,
        // A filesystem that will not report a modification time cannot be asked
        // this question, so the answer is "copy it" rather than "assume".
        _ => false,
    }
}

/// Walks a local path and records what pushing it would do.
fn collect(
    source: &Path,
    base: &RelativePath,
    volume: &Volume,
    steps: &mut Vec<Step>,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!(
            "{} is nested deeper than {MAX_DEPTH} directories, which is as deep as a share goes",
            source.display()
        ));
    }
    // `symlink_metadata`, and links are skipped: following one out of the tree
    // being pushed would copy something the operator did not name, and the share
    // itself refuses to hold a link either way.
    let metadata = std::fs::symlink_metadata(source)
        .map_err(|error| format!("cannot read {}: {error}", source.display()))?;
    if metadata.file_type().is_symlink() {
        println!("  ! skipped {} — a symbolic link is not copied", source.display());
        return Ok(());
    }

    if metadata.is_file() {
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| format!("{} has a name this share cannot hold", source.display()))?;
        let remote = base
            .join(name)
            .map_err(|error| format!("{}: {error}", source.display()))?;
        let action = match volume.stat(&Identity::Owner, &remote) {
            Ok(there) => {
                if already_there(metadata.len(), metadata.modified().ok(), there.size, there.modified) {
                    Action::Unchanged
                } else {
                    Action::Replace
                }
            }
            Err(_) => Action::Create,
        };
        steps.push(Step { local: source.to_path_buf(), remote, size: metadata.len(), action });
        return Ok(());
    }

    if !metadata.is_dir() {
        println!("  ! skipped {} — not a file or a directory", source.display());
        return Ok(());
    }

    // A directory is pushed under its own name, so `push photos vault:` lands
    // `vault:photos` rather than emptying `photos` into the share root. A
    // directory whose name is not one this share can hold — `..`, a reserved
    // device stem, a trailing space — is refused here rather than silently
    // flattened into its parent.
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("{} has a name this share cannot hold", source.display()))?;
    let here = base.join(name).map_err(|error| format!("{}: {error}", source.display()))?;
    let mut names: Vec<PathBuf> = std::fs::read_dir(source)
        .map_err(|error| format!("cannot list {}: {error}", source.display()))?
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .collect();
    names.sort();
    for child in names {
        collect(&child, &here, volume, steps, depth + 1)?;
    }
    Ok(())
}

/// Walks a share subtree and records what pulling it would do.
fn gather(
    volume: &Volume,
    at: &RelativePath,
    destination: &Path,
    steps: &mut Vec<Step>,
    depth: usize,
) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err(format!("{at} is nested deeper than {MAX_DEPTH} directories"));
    }
    match volume.stat(&Identity::Owner, at) {
        Ok(there) if there.kind == Kind::File => {
            let name = at.file_name().unwrap_or("download");
            let local = destination.join(name);
            let action = match std::fs::symlink_metadata(&local) {
                Ok(here) if already_there(there.size, there.modified, here.len(), here.modified().ok()) => {
                    Action::Unchanged
                }
                Ok(_) => Action::Replace,
                Err(_) => Action::Create,
            };
            steps.push(Step { local, remote: at.clone(), size: there.size, action });
            return Ok(());
        }
        Ok(_) => {}
        Err(error) => return Err(format!("cannot read {at}: {error}")),
    }

    let listing = volume
        .listing(&Identity::Owner, at)
        .map_err(|error| format!("cannot list {at}: {error}"))?;
    // A directory arrives as a directory of the same name, mirroring what push
    // does in the other direction.
    let here = match at.file_name() {
        Some(name) => destination.join(name),
        None => destination.to_path_buf(),
    };
    for entry in &listing.entries {
        if entry.blocked.is_some() {
            let why = entry.blocked.map_or_else(String::new, |blocked| blocked.reason());
            println!("  ! skipped {}/{} — {why}", at, entry.name);
            continue;
        }
        let child = at
            .join(&entry.name)
            .map_err(|error| format!("{}/{}: {error}", at, entry.name))?;
        gather(volume, &child, &here, steps, depth + 1)?;
    }
    Ok(())
}

/// Streams one local file into the share.
///
/// Every byte goes through [`Volume::receive`], so the quota admission, the
/// free-space floor, the case-collision scan and the atomic in-directory rename
/// all apply exactly as they do to an upload from a browser.
fn upload(volume: &Volume, step: &Step) -> Result<(), String> {
    let mut file = std::fs::File::open(&step.local)
        .map_err(|error| format!("cannot open {}: {error}", step.local.display()))?;
    let mut receiver = volume
        .receive(&Identity::Owner, &step.remote, Existing::Replace, step.size)
        .map_err(|error| format!("cannot write {}: {error}", step.remote))?;

    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let read = match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => {
                let _ = receiver.abandon();
                return Err(format!("cannot read {}: {error}", step.local.display()));
            }
        };
        if let Err(error) = receiver.write(&buffer[..read]) {
            let _ = receiver.abandon();
            return Err(format!("cannot write {}: {error}", step.remote));
        }
    }
    receiver.commit().map_err(|error| format!("cannot finish {}: {error}", step.remote))
}

/// Streams one file out of the share onto the local disk.
fn download(volume: &Volume, step: &Step) -> Result<(), String> {
    if let Some(parent) = step.local.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let mut source = volume
        .root()
        .open_at(&step.remote)
        .map_err(|error| format!("cannot read {}: {error}", step.remote))?;
    let mut target = std::fs::File::create(&step.local)
        .map_err(|error| format!("cannot create {}: {error}", step.local.display()))?;

    let mut buffer = vec![0u8; COPY_BUFFER_BYTES];
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|error| format!("cannot read {}: {error}", step.remote))?;
        if read == 0 {
            break;
        }
        target
            .write_all(&buffer[..read])
            .map_err(|error| format!("cannot write {}: {error}", step.local.display()))?;
    }
    // The bytes are only really there once the filesystem says so; a sync that
    // reported success and lost a file to a power cut would be worse than one
    // that took a moment longer.
    target
        .sync_all()
        .map_err(|error| format!("cannot flush {}: {error}", step.local.display()))
}

/// Every directory a push needs and the share does not have, outermost first.
///
/// Ordered by depth so that creating them in sequence never asks for a folder
/// whose parent is still missing — [`Volume::create_directory`] deliberately
/// creates only the last segment, because a `mkdir` that invented intermediate
/// directories would make a typo in a path build a tree.
fn missing_folders(volume: &Volume, steps: &[Step]) -> Vec<RelativePath> {
    let mut wanted: Vec<RelativePath> = Vec::new();
    for step in steps {
        let mut at = step.remote.parent();
        while !at.is_root() {
            if !wanted.contains(&at) {
                wanted.push(at.clone());
            }
            at = at.parent();
        }
    }
    wanted.sort_by_key(|path| path.segments().len());
    wanted
        .into_iter()
        .filter(|path| volume.stat(&Identity::Owner, path).is_err())
        .collect()
}

/// Prints the plan, grouped the way somebody reads it: what changes first.
fn report(steps: &[Step], folders: &[RelativePath], id: &str) {
    let creates = steps.iter().filter(|step| step.action == Action::Create).count();
    let replaces = steps.iter().filter(|step| step.action == Action::Replace).count();
    let unchanged = steps.len() - creates - replaces;
    let bytes: u64 = steps
        .iter()
        .filter(|step| step.action != Action::Unchanged)
        .fold(0u64, |total, step| total.saturating_add(step.size));

    println!(
        "share \"{id}\": {folders} folder(s), {creates} file(s) to create, {replaces} to replace, \
         {unchanged} already there — {} to move\n",
        human(bytes),
        folders = folders.len(),
    );
    for folder in folders {
        println!("  {:>9}  {:<9} {folder}/", "", "created");
    }
    for step in steps {
        if step.action == Action::Unchanged {
            continue;
        }
        println!("  {:>9}  {:<9} {}", human(step.size), step.action.verb(), step.remote);
    }
}

/// The volumes named, or all of them.
fn select<'a>(volumes: &'a Volumes, only: Option<&str>) -> Result<Vec<&'a Volume>, String> {
    match only {
        Some(id) => Ok(vec![find(volumes, id)?]),
        None => Ok(volumes.all().iter().map(std::convert::AsRef::as_ref).collect()),
    }
}

/// The share with this id, or a message naming the ones that exist.
fn find<'a>(volumes: &'a Volumes, id: &str) -> Result<&'a Volume, String> {
    volumes.find(id).map(std::convert::AsRef::as_ref).ok_or_else(|| {
        let known: Vec<&str> =
            volumes.all().iter().map(|volume| volume.share().id().as_str()).collect();
        format!("no share \"{id}\" is declared — this deployment serves: {}", known.join(", "))
    })
}

/// Splits `<share>:<path>` into its two halves.
///
/// The colon is unambiguous **because of where this is called**: the share half
/// of a `push` or a `pull` is always a fixed argument position, so a Windows
/// drive letter never reaches this function. A target with no colon at all is
/// the whole share, which is what somebody means by `vault`.
fn split_target(target: &str) -> Result<(String, String), String> {
    let (id, path) = match target.split_once(':') {
        Some((id, path)) => (id, path),
        None => (target, ""),
    };
    if id.is_empty() {
        return Err(format!(
            "\"{target}\" names no share. Write it as <share>:<path>, for example vault:photos"
        ));
    }
    Ok((id.to_owned(), path.to_owned()))
}

/// The two paths a copy needs, or the usage line for the command that wanted
/// them.
fn pair<'a>(
    first: Option<&'a String>,
    second: Option<&'a String>,
    usage: &str,
) -> Result<(&'a str, &'a str), String> {
    match (first, second) {
        (Some(first), Some(second)) => Ok((first.as_str(), second.as_str())),
        _ => Err(format!("that needs two paths: `selfhost {usage}`")),
    }
}

/// A byte count somebody can read at a glance.
///
/// Powers of two with the units spelled the way a disk utility spells them, and
/// no rounding below a kilobyte: the difference between 0 and 900 bytes matters
/// when the question is whether a file copied at all.
fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, SystemTime};

    #[test]
    fn a_target_splits_into_a_share_and_a_path() {
        assert_eq!(split_target("vault:photos/2026"), Ok(("vault".into(), "photos/2026".into())));
        assert_eq!(split_target("vault:"), Ok(("vault".into(), String::new())));
        assert_eq!(split_target("vault"), Ok(("vault".into(), String::new())));
        assert!(split_target(":photos").is_err(), "a target with no share names nothing");
    }

    #[test]
    fn the_quick_check_agrees_only_when_size_and_time_both_agree() {
        let earlier = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let later = earlier + Duration::from_secs(60);

        assert!(already_there(10, Some(earlier), 10, Some(later)), "same size, target newer");
        assert!(already_there(10, Some(earlier), 10, Some(earlier)), "same size, same time");
        assert!(!already_there(10, Some(later), 10, Some(earlier)), "target is older");
        assert!(!already_there(10, Some(earlier), 11, Some(later)), "sizes differ");
        assert!(
            !already_there(10, None, 10, Some(later)),
            "a filesystem that will not say is not evidence that the copy can be skipped"
        );
    }

    #[test]
    fn byte_counts_read_the_way_a_person_reads_them() {
        assert_eq!(human(0), "0 B");
        assert_eq!(human(900), "900 B");
        assert_eq!(human(1024), "1.0 KiB");
        assert_eq!(human(1024 * 1024 * 3 / 2), "1.5 MiB");
    }
}
