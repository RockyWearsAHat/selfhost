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
//! # The one test that needs a volume this machine may not have
//!
//! [`s3_a_case_only_rename_never_replaces_a_different_file`] needs a
//! **case-sensitive** volume to reach its interesting branch, because the pair it
//! is about — `report.pdf` beside `Report.pdf` — cannot exist on a folding one.
//! It therefore builds its fixture and asks the volume what happened, asserting
//! the property that must hold either way. To run the case-sensitive half on a
//! Mac, point `TMPDIR` at a case-sensitive volume:
//!
//! ```text
//! hdiutil create -size 20m -fs "Case-sensitive APFS" -volname CS /tmp/cs.dmg
//! hdiutil attach /tmp/cs.dmg -mountpoint /tmp/csvol -nobrowse
//! TMPDIR=/tmp/csvol cargo test -p selfhost-storage --test second_review
//! ```

use selfhost_storage::api::{Sessions, Volume};
use selfhost_storage::fs::{Dir, Existing, WriteError};
use selfhost_storage::quota::Ledger;
use selfhost_storage::share::{Grantee, Reserved, Share};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A scratch directory that removes itself, even when a test panics.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("selfhost-review2-{}-{name}", std::process::id()));
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

#[test]
fn s3_a_case_only_rename_never_replaces_a_different_file() {
    // The next spelling of the first review's fourth finding. Fixing it added a
    // branch to `Dir::rename_into`: when the only name folding onto the
    // destination is the source itself, a two-step rename performs the
    // capitalisation change. That branch returns *before* the occupancy check —
    // the check the function's own documentation calls its central decision —
    // and its second step is `Existing::Replace`.
    //
    // On a folding volume the two names are one file and the branch is right. On
    // a case-sensitive one — `ext4`, or a case-sensitive APFS volume, which is
    // precisely the volume the fold scan exists to protect — `Report.pdf` may be
    // a second, unrelated file, and the rename destroys it and reports success.
    //
    // Stated as the property that holds on either volume: after the request,
    // no file has silently lost its contents.
    let root = Scratch::new("s3");
    std::fs::write(root.path().join("report.pdf"), b"the source").expect("a fixture");
    let separate = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.path().join("Report.pdf"));

    let directory = Dir::open_root(root.path()).expect("the root opens");
    let Ok(mut handle) = separate else {
        // A folding volume: the two names are one file, which is the case the
        // branch was written for. It must still perform the rename.
        directory.rename_into("report.pdf", &directory, "Report.pdf").expect("the case is fixed");
        assert_eq!(
            std::fs::read_to_string(root.path().join("Report.pdf")).expect("read"),
            "the source"
        );
        return;
    };
    std::io::Write::write_all(&mut handle, b"a different file").expect("a second fixture");
    drop(handle);

    let outcome = directory.rename_into("report.pdf", &directory, "Report.pdf");
    assert_eq!(
        std::fs::read_to_string(root.path().join("Report.pdf")).ok().as_deref(),
        Some("a different file"),
        "a case-only rename destroyed an unrelated file at the destination \
         and reported {outcome:?}"
    );
    assert!(
        matches!(outcome, Err(WriteError::NameTaken)),
        "a rename onto an occupied destination must be refused, not performed: {outcome:?}"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join("report.pdf")).ok().as_deref(),
        Some("the source"),
        "the refused rename must leave the source where it was"
    );
}

#[test]
fn s3b_a_case_only_rename_still_works_when_the_destination_is_free() {
    // The control that keeps the fix from becoming a refusal of the ordinary
    // case: fixing a file's capitalisation is a thing a person asks a NAS for.
    // Driven through the primitive, so it runs on the small case-sensitive image
    // the test above needs as well as on the ordinary scratch volume.
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
