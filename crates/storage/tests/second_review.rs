//! A second adversarial pass over the NAS write path, after the first one's
//! findings were repaired.
//!
//! The first review is recorded in `review_findings.rs`. This file is the
//! follow-up question that review could not ask of itself: *were those fixes
//! made at the cause, or at the place the demonstration happened to touch?* Each
//! test below is the **next spelling of a finding that was already fixed once**
//! — another verb that removes a destination before the source is known good,
//! another control path that lets a ceiling be spent twice, another way for the
//! ledger to count bytes that are not on the disk.
//!
//! Everything here drives the real types against a real directory on the running
//! volume, for the reason `review_findings.rs` gives: the folding rules that make
//! several of these dangerous are properties of a filesystem rather than of a
//! function.
//!
//! # The volume this machine may not have, and how the suite gets one anyway
//!
//! [`s3_a_case_only_rename_never_replaces_a_different_file`] guards a branch
//! whose two correct outcomes are decided by the **volume**, not by this crate.
//! On a case-folding volume `report.pdf` and `Report.pdf` are one file, and the
//! branch must perform the capitalisation change. On a case-sensitive one they
//! may be two unrelated files, and it must refuse. A test that runs on whichever
//! volume `TMPDIR` happens to sit on therefore exercises one of those and
//! reports a green tick that reads as both — which is exactly how this test
//! spent its life until now, because `TMPDIR` on a Mac is a folding volume and
//! the case-sensitive half was reached by nobody.
//!
//! So the suite **obtains the volume it is missing** rather than asking a person
//! to. [`scratch_that_folds`] takes the behaviour a test needs and returns a
//! scratch directory on a volume that really has it:
//!
//! 1. the ambient temporary directory, when its own volume already folds that
//!    way — asked of the volume by [`folding_of`], never assumed from the
//!    platform, for the reason `fs.rs` gives about folding generally;
//! 2. an operator's `SELFHOST_TEST_CASE_FOLDING_ROOT` /
//!    `SELFHOST_TEST_CASE_SENSITIVE_ROOT`, for a host that has such a volume
//!    mounted but not as its temporary directory;
//! 3. otherwise, on macOS, a small sparse disk image created with the wanted
//!    filesystem, attached for the life of the test and detached again by its
//!    `Drop`. That is precisely the act a person once performed by hand to prove
//!    S3; performing it inside the suite is what turns a one-off proof into a
//!    regression guard.
//!
//! When none of the three can produce the volume — a Linux host, where mounting
//! a folding filesystem needs root, or Windows, where per-directory case
//! sensitivity needs an administrator — the test **fails**, naming the volume it
//! could not get and the two environment variables that would give it one. The
//! single way past that failure is to set
//! [`ACKNOWLEDGED_UNTESTED_VOLUMES`][], which downgrades it to a
//! `SKIPPED:` banner on stderr. That is deliberate: a skip should cost somebody a
//! visible, reviewable line in a CI file, because the alternative — the silent
//! early return this file used to contain — is a regression guard that does not
//! run and cannot be told apart from one that does.
//!
//! [`ACKNOWLEDGED_UNTESTED_VOLUMES`]: ACKNOWLEDGED_UNTESTED_VOLUMES

use selfhost_storage::api::{Sessions, Volume};
use selfhost_storage::fs::{Dir, Existing, WriteError};
use selfhost_storage::quota::Ledger;
use selfhost_storage::share::{Grantee, Reserved, Share};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A scratch directory that removes itself, even when a test panics.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        Self::under(&std::env::temp_dir(), name)
    }

    /// The same scratch directory, on a volume the caller chose.
    ///
    /// Separate from [`Scratch::new`] because the tests about case folding are
    /// about a property of the volume, so they must be able to say which volume
    /// rather than inheriting whichever one `TMPDIR` names.
    fn under(base: &Path, name: &str) -> Self {
        let path = base.join(format!("selfhost-review2-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(std::fs::canonicalize(&path).expect("a canonical scratch directory"))
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn reserved() -> Reserved {
    Reserved::new(std::env::temp_dir().join("selfhost-data-unused"), None).expect("reserved")
}

fn volume(id: &str, root: &Path, quota: Option<u64>) -> Volume {
    let share = Share::new(&reserved(), id, root, false, true, quota).expect("a legal share");
    Volume::open(share, Arc::new(Ledger::new())).expect("the root opens")
}

fn owner() -> Grantee {
    Grantee::Owner
}

// ---------------------------------------------------------------------------
// Volumes. A folding rule is a property of a filesystem, so a test about one
// has to be able to name the filesystem it runs on rather than accept the one
// it was handed.
// ---------------------------------------------------------------------------

/// The environment variable that lets a host with no way to build a volume
/// declare, out loud and in a file somebody reviews, that a case-folding
/// property is going untested there.
///
/// Set to anything at all. It exists because the alternative to a loud failure
/// is not a quiet pass — it is a suite whose green tick means less than the
/// reader thinks, which is the failure this project has already been bitten by.
const ACKNOWLEDGED_UNTESTED_VOLUMES: &str = "SELFHOST_TEST_ALLOW_UNTESTED_VOLUMES";

/// What a volume does with two names that differ only in case.
///
/// The whole subject of S3. Named after the observable consequence rather than
/// after "case sensitivity", because that phrase is routinely used for both
/// halves of it and the tests below need to say which one they mean.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Folding {
    /// `report.pdf` and `Report.pdf` name one file — APFS as Apple ships it,
    /// NTFS, exFAT.
    OneFile,
    /// They name two — ext4, and a case-sensitive APFS volume, which is
    /// precisely the volume `crate::fs`'s fold scan exists to protect.
    TwoFiles,
}

impl Folding {
    /// The environment variable an operator sets to lend the suite a volume
    /// that behaves this way.
    fn override_variable(self) -> &'static str {
        match self {
            Self::OneFile => "SELFHOST_TEST_CASE_FOLDING_ROOT",
            Self::TwoFiles => "SELFHOST_TEST_CASE_SENSITIVE_ROOT",
        }
    }

    /// The `hdiutil -fs` argument that formats an image this way.
    #[cfg(target_os = "macos")]
    fn apfs_flavour(self) -> &'static str {
        match self {
            Self::OneFile => "APFS",
            Self::TwoFiles => "Case-sensitive APFS",
        }
    }
}

/// A serial number, so two threads probing the same temporary directory at once
/// do not collide on a fixture name. `cargo test` runs these in parallel and a
/// probe that races another probe answers about neither volume.
static PROBE_SERIAL: AtomicU64 = AtomicU64::new(0);

/// Asks a directory's own volume which [`Folding`] it applies, by writing one
/// name and trying to create the other spelling exclusively.
///
/// Asked of the volume rather than derived from `cfg!(target_os = ...)` for the
/// reason `crates/storage/src/fs.rs` gives about collisions generally: folding
/// is a per-*volume* property, and a mounted image, a network share or an APFS
/// volume formatted case-sensitively each contradict whatever the platform
/// suggests. The exclusive create is the same oracle `Upload::begin` uses, so
/// the probe and the code under test are asking the filesystem the same
/// question.
fn folding_of(directory: &Path) -> Result<Folding, String> {
    let serial = PROBE_SERIAL.fetch_add(1, Ordering::Relaxed);
    let probe = directory.join(format!("selfhost-fold-probe-{}-{serial}", std::process::id()));
    std::fs::create_dir_all(&probe).map_err(|error| {
        format!("{} cannot hold a probe directory: {error}", directory.display())
    })?;
    let answer = probe_folding(&probe);
    let _ = std::fs::remove_dir_all(&probe);
    answer
}

/// The body of [`folding_of`], split out so the probe directory is removed on
/// every path including the failing ones.
fn probe_folding(probe: &Path) -> Result<Folding, String> {
    std::fs::write(probe.join("report.pdf"), b"probe")
        .map_err(|error| format!("a probe fixture could not be written: {error}"))?;
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(probe.join("Report.pdf"))
    {
        Ok(_) => Ok(Folding::TwoFiles),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(Folding::OneFile),
        Err(error) => Err(format!("a probe fixture could not be created: {error}")),
    }
}

/// Whatever had to be mounted to obtain a volume with a wanted [`Folding`],
/// held for the life of the scratch directory on it and given back by `Drop`.
enum Mounted {
    /// Nothing was mounted: the volume was already there.
    Ambient,
    /// A sparse disk image this suite created and attached. Detaching it is not
    /// optional — a test killed between the attach and the detach leaves a
    /// volume on the operator's machine — so it is a `Drop` rather than a last
    /// line, exactly as [`Scratch`] is.
    #[cfg(target_os = "macos")]
    Image { directory: PathBuf, mountpoint: PathBuf },
}

impl Drop for Mounted {
    fn drop(&mut self) {
        match self {
            Self::Ambient => {}
            #[cfg(target_os = "macos")]
            Self::Image { directory, mountpoint } => {
                let _ = std::process::Command::new("/usr/bin/hdiutil")
                    .arg("detach")
                    .arg(mountpoint)
                    .arg("-force")
                    .output();
                let _ = std::fs::remove_dir_all(directory);
            }
        }
    }
}

/// A scratch directory on a volume whose folding behaviour has been *proved*,
/// together with the mount that provides it.
struct OnVolume {
    scratch: Scratch,
    /// Dropped after `scratch`, because fields drop in declaration order and
    /// the directory has to go before the volume holding it does.
    _mount: Mounted,
}

impl OnVolume {
    fn path(&self) -> &Path {
        self.scratch.path()
    }
}

/// A scratch directory on a volume that really applies `folding`, or the reason
/// this host could not provide one.
///
/// The three sources are tried in the order the module documentation gives:
/// operator override, ambient temporary directory, purpose-built image. Every
/// one of them is *verified* with [`folding_of`] before it is returned — an
/// override that points at the wrong kind of volume, or an image the platform
/// formatted differently from what was asked, would otherwise put the wrong half
/// of S3 on the wrong volume and pass.
fn scratch_that_folds(folding: Folding, label: &str) -> Result<OnVolume, String> {
    let variable = folding.override_variable();
    if let Some(root) = std::env::var_os(variable) {
        let root = PathBuf::from(root);
        let found = folding_of(&root)?;
        if found != folding {
            return Err(format!(
                "{variable} points at {}, whose volume is {found:?} rather than {folding:?}",
                root.display()
            ));
        }
        return Ok(OnVolume { scratch: Scratch::under(&root, label), _mount: Mounted::Ambient });
    }

    let ambient = std::env::temp_dir();
    if folding_of(&ambient)? == folding {
        return Ok(OnVolume { scratch: Scratch::under(&ambient, label), _mount: Mounted::Ambient });
    }

    build_volume(folding, label)
}

/// Builds a volume with the wanted folding out of a sparse disk image.
///
/// macOS is the one platform where an unprivileged process can format and mount
/// a filesystem of its choosing, and `hdiutil` is how: `create` writes a sparse
/// image with an explicitly named flavour of APFS, `attach` mounts it at a
/// path this test owns, `-nobrowse` keeps it out of the operator's Finder.
#[cfg(target_os = "macos")]
fn build_volume(folding: Folding, label: &str) -> Result<OnVolume, String> {
    let directory =
        std::env::temp_dir().join(format!("selfhost-volume-{}-{label}", std::process::id()));
    let mountpoint = directory.join("mnt");
    // A run killed hard enough to skip a `Drop` leaves a volume attached here,
    // and a mount point cannot be removed while something is mounted on it — so
    // the detach comes before the cleanup rather than after it, and both are
    // allowed to fail on the ordinary path where there is nothing to undo.
    let _ = std::process::Command::new("/usr/bin/hdiutil")
        .arg("detach")
        .arg(&mountpoint)
        .arg("-force")
        .output();
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&mountpoint)
        .map_err(|error| format!("no room for a disk image and its mount point: {error}"))?;

    let stem = text(&directory.join("image"))?;
    hdiutil(&[
        "create",
        "-size",
        "16m",
        "-fs",
        folding.apfs_flavour(),
        "-volname",
        "SelfhostTest",
        "-type",
        "SPARSE",
        &stem,
    ])?;
    // `hdiutil create` appends the extension its image type uses.
    let image = text(&directory.join("image.sparseimage"))?;
    let at = text(&mountpoint)?;
    hdiutil(&["attach", &image, "-mountpoint", &at, "-nobrowse", "-owners", "off"])?;

    // Constructed before the check, so a volume that turns out to be the wrong
    // kind is still detached by this value's `Drop` on the way out.
    let mount = Mounted::Image { directory, mountpoint: mountpoint.clone() };
    let found = folding_of(&mountpoint)?;
    if found != folding {
        return Err(format!(
            "an image formatted {:?} mounted as {found:?} rather than {folding:?}",
            folding.apfs_flavour()
        ));
    }
    Ok(OnVolume { scratch: Scratch::under(&mountpoint, label), _mount: mount })
}

/// No unprivileged way to build one here.
///
/// Mounting a filesystem on Linux needs root, and turning on per-directory case
/// sensitivity on Windows needs an administrator. Both are things a test suite
/// must never have, so the honest answer is this message rather than a skip
/// nobody sees.
#[cfg(not(target_os = "macos"))]
fn build_volume(folding: Folding, _label: &str) -> Result<OnVolume, String> {
    Err(format!(
        "no unprivileged way to build a {folding:?} volume on {}: mounting one needs root on \
         Linux, and per-directory case sensitivity on Windows needs an administrator",
        std::env::consts::OS
    ))
}

/// A path as an argument, or the reason it cannot be one.
///
/// `hdiutil` is driven by strings; a temporary directory whose name is not UTF-8
/// is a real if unlikely answer, and it must not become a panic that reads like
/// a failure of the property under test.
#[cfg(target_os = "macos")]
fn text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("{} is not a name hdiutil can be given", path.display()))
}

/// Runs `hdiutil` and turns a non-zero exit into the text it printed.
///
/// The output matters: a volume that could not be built has to explain itself
/// inside the panic that follows, or the operator is left guessing at which of
/// disk space, entitlements or a full `/tmp` stopped it.
#[cfg(target_os = "macos")]
fn hdiutil(arguments: &[&str]) -> Result<(), String> {
    let output = std::process::Command::new("/usr/bin/hdiutil")
        .args(arguments)
        .output()
        .map_err(|error| format!("hdiutil could not be run: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "`hdiutil {}` failed ({}): {}{}",
        arguments.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stderr).trim(),
        String::from_utf8_lossy(&output.stdout).trim()
    ))
}

/// The scratch directory a test needs, or a failure that says what is untested.
///
/// This is where the decision about silence is made. The default is a panic,
/// because a case-folding property that nothing exercised is indistinguishable —
/// from the outside, which is where people read test results — from one that
/// held. [`ACKNOWLEDGED_UNTESTED_VOLUMES`] is the deliberate escape for a host
/// that genuinely cannot help, and it costs whoever sets it a visible line in a
/// CI configuration rather than costing a future reader their confidence in a
/// green run.
fn volume_that_folds(folding: Folding, label: &str) -> Option<OnVolume> {
    match scratch_that_folds(folding, label) {
        Ok(volume) => Some(volume),
        Err(why) if std::env::var_os(ACKNOWLEDGED_UNTESTED_VOLUMES).is_some() => {
            // Written **straight to the stream**, not through `eprintln!`.
            // `libtest` captures the printing macros and shows what they wrote
            // only for a test that fails, so a banner announcing that a passing
            // test did not really run is exactly the message the capture would
            // swallow. A direct `Stderr` write is not captured, so this line
            // appears in an ordinary `cargo test` run, in front of the `ok`.
            let banner = format!(
                "SKIPPED: no {folding:?} volume for `{label}` on this host ({why}).\n\
                 The half of S3 it guards did NOT run; \
                 {ACKNOWLEDGED_UNTESTED_VOLUMES} is set, so this run is green without it.\n"
            );
            let mut stderr = std::io::stderr();
            let _ = std::io::Write::write_all(&mut stderr, banner.as_bytes());
            let _ = std::io::Write::flush(&mut stderr);
            None
        }
        Err(why) => panic!(
            "this half of S3 needs a volume on which two names differing only in case are \
             {folding:?}, and this host provided none: {why}.\n\
             Point {} at such a volume, or set {ACKNOWLEDGED_UNTESTED_VOLUMES} to record, \
             somewhere a reviewer will see it, that the property is going untested here.",
            folding.override_variable()
        ),
    }
}

// ---------------------------------------------------------------------------
// S1. The share's cached size counts bytes that are on the disk, and no others.
// ---------------------------------------------------------------------------

#[test]
fn s1_an_upload_that_dies_without_being_abandoned_adds_nothing_to_the_share() {
    // The next spelling of the first review's third finding. `Receiver::abandon`
    // calls `Reservation::rollback` before dropping, and its documentation says
    // in terms that "the `rollback` is not optional: without it an abandoned
    // 5 GB upload would add 5 GB to the share's cached size". That is a rule
    // held by one call site, and there are three others that never reach it:
    //
    //  - the idle sweep in `Sessions`, which simply drops the entry;
    //  - the whole session table being dropped;
    //  - `Receiver::write` returning an I/O error, which the admin writer task
    //    propagates with `?` rather than abandoning.
    //
    // In every one of them `Upload`'s own `Drop` removes the partial file — and
    // `Reservation`'s `Drop` credits the bytes of that removed file to the
    // share. The share then reports and *enforces* a size that includes bytes
    // nothing holds, so a client that keeps losing its tunnel walks the share up
    // to its quota without ever storing a thing.
    let root = Scratch::new("s1-sweep");
    let vault = volume("vault", root.path(), Some(64 * 1024));

    // Measure once, so the ledger holds a fresh figure the later reads will use
    // rather than re-measuring the directory and hiding the drift.
    assert_eq!(vault.usage().expect("measured").used_bytes, 0);

    let at = vault.resolve("/interrupted.bin").expect("a legal path");
    let sessions = Sessions::new();
    let receiver = vault.receive(&owner(), &at, Existing::Refuse, 8192).expect("admitted");
    let ticket = sessions.begin(receiver).expect("a ticket");
    sessions.append(ticket.as_str(), 0, &vec![7u8; 8192]).expect("written");

    // The tunnel drops and nobody ever comes back: the sweep removes the entry.
    drop(sessions);

    assert!(
        !root.path().join("interrupted.bin").exists(),
        "the partial file should have gone with the session"
    );
    assert_eq!(
        vault.usage().expect("measured").used_bytes,
        0,
        "the share was charged for bytes that are not on the disk"
    );
}

#[test]
fn s1b_a_write_that_fails_charges_the_share_for_nothing() {
    // The same cause reached through the path the admin route actually takes: a
    // `Receiver` dropped because `write` returned an error, with no abandon in
    // between. Driven here by dropping the receiver outright, which is what `?`
    // does to it.
    let root = Scratch::new("s1-drop");
    let vault = volume("vault", root.path(), Some(64 * 1024));
    assert_eq!(vault.usage().expect("measured").used_bytes, 0);

    let at = vault.resolve("/half.bin").expect("a legal path");
    let mut receiver = vault.receive(&owner(), &at, Existing::Refuse, 4096).expect("admitted");
    receiver.write(&vec![3u8; 4096]).expect("written");
    drop(receiver);

    assert!(!root.path().join("half.bin").exists(), "the partial file should have gone");
    assert_eq!(
        vault.usage().expect("measured").used_bytes,
        0,
        "the share was charged for a file that was removed"
    );
}

#[test]
fn s1c_an_upload_that_completes_still_moves_the_share_size() {
    // The control. A ledger that credited nothing at all would pass the two
    // tests above and quietly stop enforcing the quota under concurrency, which
    // is the shape of the fix that is worse than the bug.
    let root = Scratch::new("s1-control");
    let vault = volume("vault", root.path(), Some(64 * 1024));
    assert_eq!(vault.usage().expect("measured").used_bytes, 0);

    let at = vault.resolve("/kept.bin").expect("a legal path");
    let mut receiver = vault.receive(&owner(), &at, Existing::Refuse, 1024).expect("admitted");
    receiver.write(&vec![1u8; 1024]).expect("written");
    receiver.commit().expect("committed");

    assert_eq!(
        vault.usage().expect("measured").used_bytes,
        1024,
        "a published upload must move the cached size without a re-measure"
    );
}

// ---------------------------------------------------------------------------
// S2. Forgetting a share's *measurement* does not forget what it has promised.
// ---------------------------------------------------------------------------

#[test]
fn s2_a_delete_during_an_upload_does_not_hand_the_quota_out_twice() {
    // `Ledger::forget` is called by `delete`, by `move_to` and by `copy_to`,
    // and its job is to drop a cached *measurement* this code can no longer
    // compute. It drops the whole entry — including `in_flight_bytes`, the
    // number that makes the quota true under concurrency and the one thing in
    // that entry which is not a measurement at all.
    //
    // So any delete issued while an upload is running gives that upload's
    // promise back to the quota, and the next upload is admitted against room
    // the first one has already spent. Two 600-byte uploads then fit in a
    // 1000-byte share.
    let root = Scratch::new("s2");
    let vault = volume("vault", root.path(), Some(1000));

    let first = vault.resolve("/first.bin").expect("a legal path");
    let _running = vault.receive(&owner(), &first, Existing::Refuse, 600).expect("admitted");

    // Any delete at all. A person tidying the share while an upload runs is not
    // an attack, and it must not be one.
    let junk = vault.resolve("/junk").expect("a legal path");
    vault.create_directory(&owner(), &junk).expect("created");
    vault.delete(&owner(), &junk).expect("removed");

    let second = vault.resolve("/second.bin").expect("a legal path");
    let refused = vault.receive(&owner(), &second, Existing::Refuse, 600);
    assert!(
        refused.is_err(),
        "600 + 600 bytes were admitted into a 1000-byte share because a delete \
         forgot what the first upload had promised"
    );
}

#[test]
fn s2b_forgetting_a_measurement_still_forces_a_fresh_one() {
    // The control: `forget`'s actual job must survive the fix. A share whose
    // entry is kept for its in-flight bytes must still be re-measured rather
    // than answering from the figure that was just invalidated.
    let root = Scratch::new("s2-control");
    let vault = volume("vault", root.path(), None);
    let at = vault.resolve("/a.bin").expect("a legal path");
    let mut receiver = vault.receive(&owner(), &at, Existing::Refuse, 2048).expect("admitted");
    receiver.write(&vec![9u8; 2048]).expect("written");
    receiver.commit().expect("committed");
    assert_eq!(vault.usage().expect("measured").used_bytes, 2048);

    // A delete this code cannot compute the size of: the cache is dropped and
    // the next question is answered by walking the directory.
    vault.delete(&owner(), &at).expect("removed");
    assert_eq!(
        vault.usage().expect("measured").used_bytes,
        0,
        "the share must be measured again rather than answering from a stale figure"
    );
}

// ---------------------------------------------------------------------------
// S3. A rename onto a spelling of its own name still refuses an occupied
//     destination.
// ---------------------------------------------------------------------------

/// The next spelling of the first review's fourth finding, run on **both** kinds
/// of volume by a suite that builds whichever one this host is missing.
///
/// Fixing that finding added a branch to `Dir::rename_into`: when the only name
/// folding onto the destination is the source itself, a two-step rename performs
/// the capitalisation change. The branch returns *before* the function's central
/// occupancy check, and its second step is `Existing::Replace`. On a folding
/// volume the two names are one file and that is right. On a case-sensitive one
/// `Report.pdf` may be a second, unrelated file, and an unguarded branch
/// destroys it and reports success.
///
/// # Why this test builds a filesystem, and does not merely skip
///
/// The property has two halves and each is reachable only on one kind of volume,
/// so *neither* can be asserted "in a way that holds on either" — that framing is
/// what the earlier version of this test used to justify an early return, and the
/// early return is the half it never ran. On this project's development machines
/// `TMPDIR` is folding APFS, so the case-sensitive half — the half that guards
/// against silently destroying a file — had never executed in an ordinary run.
/// It was proved once, by hand, by a person who built a case-sensitive APFS
/// sparse image and pointed `TMPDIR` at it. A property proved by an act nobody
/// repeats is not a regression guard; it is a memory.
///
/// So the act is now the suite's, not a person's: [`volume_that_folds`] returns a
/// scratch directory on a volume with the demanded behaviour, creating and
/// mounting a 16 MB sparse image when the host has no such volume already, and
/// detaching it again on the way out. Both halves therefore run in a plain
/// `cargo test` on macOS, and the case-sensitive half runs natively on ext4.
///
/// Where no volume can be built — Linux, where mounting one needs root, and
/// Windows, where per-directory case sensitivity needs an administrator — the
/// missing half is a **panic** naming what went untested, not a return. The
/// module documentation gives the one acknowledged way past it.
#[test]
fn s3_a_case_only_rename_never_replaces_a_different_file() {
    if let Some(volume) = volume_that_folds(Folding::OneFile, "s3-one-file") {
        a_case_only_rename_fixes_the_capitalisation(volume.path());
    }
    if let Some(volume) = volume_that_folds(Folding::TwoFiles, "s3-two-files") {
        a_case_only_rename_refuses_a_destination_that_is_a_second_file(volume.path());
    }
}

/// The folding half: the two spellings are one file, which is the case the
/// branch was written for, and it must perform the rename.
fn a_case_only_rename_fixes_the_capitalisation(root: &Path) {
    std::fs::write(root.join("report.pdf"), b"the source").expect("a fixture");
    let directory = Dir::open_root(root).expect("the root opens");

    directory.rename_into("report.pdf", &directory, "Report.pdf").expect("the case is fixed");
    assert_eq!(std::fs::read_to_string(root.join("Report.pdf")).expect("read"), "the source");
}

/// The case-sensitive half: the destination is a *different file*, so the
/// occupancy check must fire on the case-only branch and refuse.
///
/// The fixture is created with `create_new`, and the `expect` is now an
/// assertion rather than a fork in the road — the volume has already been proved
/// [`Folding::TwoFiles`], so a failure here means the volume changed underneath
/// the test and that is worth a red run.
fn a_case_only_rename_refuses_a_destination_that_is_a_second_file(root: &Path) {
    std::fs::write(root.join("report.pdf"), b"the source").expect("a fixture");
    let mut separate = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join("Report.pdf"))
        .expect("a case-sensitive volume holds both spellings at once");
    std::io::Write::write_all(&mut separate, b"a different file").expect("a second fixture");
    drop(separate);

    let directory = Dir::open_root(root).expect("the root opens");
    let outcome = directory.rename_into("report.pdf", &directory, "Report.pdf");
    assert_eq!(
        std::fs::read_to_string(root.join("Report.pdf")).ok().as_deref(),
        Some("a different file"),
        "a case-only rename destroyed an unrelated file at the destination \
         and reported {outcome:?}"
    );
    assert!(
        matches!(outcome, Err(WriteError::NameTaken)),
        "a rename onto an occupied destination must be refused, not performed: {outcome:?}"
    );
    assert_eq!(
        std::fs::read_to_string(root.join("report.pdf")).ok().as_deref(),
        Some("the source"),
        "the refused rename must leave the source where it was"
    );
}

#[test]
fn s3b_a_case_only_rename_still_works_when_the_destination_is_free() {
    // The control that keeps the fix from becoming a refusal of the ordinary
    // case: fixing a file's capitalisation is a thing a person asks a NAS for.
    // Driven through the primitive, and deliberately left on whatever volume
    // this host runs the suite on: the two-volume coverage of the branch lives
    // in S3 above, and what this adds is that the ordinary request still
    // succeeds — a statement that has to hold on the volume in front of you,
    // whichever it is, and needs no image mounted to say so.
    let root = Scratch::new("s3-control");
    std::fs::write(root.path().join("report.pdf"), b"the only copy").expect("a fixture");
    let directory = Dir::open_root(root.path()).expect("the root opens");

    directory.rename_into("report.pdf", &directory, "Report.pdf").expect("the case is fixed");
    let mut names: Vec<String> = std::fs::read_dir(root.path())
        .expect("readable")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    assert_eq!(names, ["Report.pdf"]);
    assert_eq!(
        std::fs::read_to_string(root.path().join("Report.pdf")).expect("read"),
        "the only copy"
    );
}
