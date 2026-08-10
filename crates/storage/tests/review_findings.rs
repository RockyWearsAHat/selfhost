//! The adversarial review's findings against the NAS write path, each one now
//! stated as the property that holds.
//!
//! Every test here began as a *review artefact*: a demonstration, run against
//! the code as it stood, that some rule this crate's documentation claimed was
//! in fact absent. Three of them destroyed data on every run. They are kept —
//! under the same numbers, driving the same sequence of calls — and turned
//! inside out, so that the file which recorded the gaps now guards against their
//! return. A failure here is the reappearance of a finding somebody already took
//! the trouble to write down.
//!
//! **The inversion is the point.** As written by the review these tests asserted
//! the *bug*: `assert!(!path.exists(), "BUG: the file was destroyed")` passed
//! precisely because a file had been destroyed, so the suite was green because
//! the defects existed and would have gone red the day somebody fixed them. A
//! test that fails when the code improves is worse than no test, because it
//! teaches the next reader that the behaviour was intended.
//!
//! # What is being tested, and from where
//!
//! These drive [`Volume`] — the engine both the JSON file API and WebDAV run on
//! — rather than a route, because that is the layer where a `MOVE` decides
//! whether to delete something. Nothing here needs a socket, and every case is
//! reproduced against a real directory on the running volume, which matters: the
//! folding rules that make several of these dangerous are properties of a
//! filesystem, not of a function, so each assertion below is written to hold on
//! a case-folding volume (APFS, NTFS) *and* on a case-sensitive one (ext4). An
//! assertion that only holds on this machine is an assertion that means nothing
//! in CI.

use selfhost_storage::api::{Landing, Sessions, Volume};
use selfhost_storage::dav::multistatus::Mount;
use selfhost_storage::fs::{Dir, Existing, MAX_TREE_DEPTH};
use selfhost_storage::listing::Kind;
use selfhost_storage::path::RelativePath;
use selfhost_storage::quota::Ledger;
use selfhost_storage::share::{Grantee, Reserved, Share, ShareId};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// A scratch directory that removes itself, even when a test panics.
///
/// The review's original helper cleaned up on the last line, which a failing
/// assertion never reaches — so a red test left a directory behind and the next
/// run started from somebody else's fixture.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let path =
            std::env::temp_dir().join(format!("selfhost-review-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        // Canonicalised because `Dir::open_root` canonicalises, and on macOS
        // `/tmp` is itself a link to `/private/tmp`.
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

/// An upload through the front door, which is how every fixture here is made.
fn put(volume: &Volume, path: &str, bytes: &[u8]) {
    let at = volume.resolve(path).expect("a legal path");
    let mut receiver = volume
        .receive(&owner(), &at, Existing::Refuse, bytes.len() as u64)
        .expect("admitted");
    receiver.write(bytes).expect("written");
    receiver.commit().expect("committed");
}

/// The names in a directory, as the volume holds them.
fn names(root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(root)
        .expect("readable")
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// ---------------------------------------------------------------------------
// 1. A transfer that fails has not destroyed the destination on its way there.
// ---------------------------------------------------------------------------

#[test]
fn f1_a_move_onto_itself_is_refused_and_the_file_is_still_there() {
    // The finding: `MOVE` with `Overwrite: T` deleted its destination first —
    // which RFC 4918 §9.9.3 does require — and only then discovered that the
    // destination *was* the source. The rename then failed, correctly, on a file
    // that no longer existed. Every call returned a sensible-looking value and
    // the only copy was gone.
    //
    // §9.9.2 answers a destination equal to the source `403`, and the reason it
    // is worth obeying rather than treating as pedantry about a redundant
    // request is exactly this: with the delete first, a no-op is data loss.
    let root = Scratch::new("f1-self");
    let vault = volume("vault", root.path(), None);
    put(&vault, "/important.pdf", b"the only copy");
    let at = vault.resolve("/important.pdf").expect("a legal path");

    for replace in [false, true] {
        let refused = vault.move_to(&owner(), &at, &vault, &at, replace).expect_err("refused");
        assert_eq!(refused.status_code(), 403, "RFC 4918 §9.9.2, replace={replace}");
        assert_eq!(refused.tag(), "same-resource");
        assert_eq!(
            std::fs::read_to_string(root.path().join("important.pdf")).expect("still there"),
            "the only copy",
            "a refused move destroyed the file it refused to move"
        );
    }
}

#[test]
fn f1b_a_move_from_a_source_that_is_not_there_leaves_the_destination_alone() {
    // The finding: the destination was cleared before anything had established
    // that the source existed, so a mistyped source name was a delete of
    // whatever the destination happened to be.
    let root = Scratch::new("f1-missing");
    let vault = volume("vault", root.path(), None);
    put(&vault, "/keep.pdf", b"the only copy");
    let absent = vault.resolve("/typo.pdf").expect("a legal path");
    let keep = vault.resolve("/keep.pdf").expect("a legal path");

    for replace in [false, true] {
        assert!(vault.move_to(&owner(), &absent, &vault, &keep, replace).is_err());
        assert_eq!(
            std::fs::read_to_string(root.path().join("keep.pdf")).expect("still there"),
            "the only copy",
            "a move whose source never existed destroyed the destination"
        );
    }
}

#[test]
fn f1c_a_copy_from_a_source_that_is_not_there_leaves_the_destination_alone() {
    // The same ordering, reached through the other verb — which is how the root
    // cause was told apart from a `MOVE`-specific slip.
    let root = Scratch::new("f1-copy");
    let vault = volume("vault", root.path(), None);
    put(&vault, "/keep.pdf", b"the only copy");
    let absent = vault.resolve("/typo.pdf").expect("a legal path");
    let keep = vault.resolve("/keep.pdf").expect("a legal path");

    for replace in [false, true] {
        assert!(vault.copy_to(&owner(), &absent, &vault, &keep, replace).is_err());
        assert_eq!(
            std::fs::read_to_string(root.path().join("keep.pdf")).expect("still there"),
            "the only copy",
            "a copy whose source never existed destroyed the destination"
        );
    }
}

#[test]
fn f1d_the_control_that_identified_the_trigger_still_holds() {
    // Without `replace` the destination was never cleared, so it survived. That
    // asymmetry is what named the cause; it is kept because a future refactor
    // that reintroduces the early delete would break the `replace` cases above
    // and leave this one passing, which is precisely the shape of the bug.
    let root = Scratch::new("f1-control");
    let vault = volume("vault", root.path(), None);
    put(&vault, "/keep.pdf", b"the only copy");
    let absent = vault.resolve("/typo.pdf").expect("a legal path");
    let keep = vault.resolve("/keep.pdf").expect("a legal path");

    assert!(vault.move_to(&owner(), &absent, &vault, &keep, false).is_err());
    assert!(root.path().join("keep.pdf").exists());
}

// ---------------------------------------------------------------------------
// 2. A collection is never copied into itself, and nothing this API makes is
//    beyond its own ability to remove.
// ---------------------------------------------------------------------------

#[test]
fn f2_a_collection_is_not_copied_into_its_own_subtree() {
    // The finding: `COPY /tree` to `/tree/copy` descended into the copy it was
    // making. Each level copied the level above it, including the copy in
    // progress, until the depth limit stopped it — sixty-four nested `copy`
    // directories and sixty-four duplicates of every file, from one request.
    //
    // RFC 4918 §9.8.1 answers this `403`. The refusal is made before anything is
    // created, so the share is exactly as it was.
    let root = Scratch::new("f2");
    let vault = volume("vault", root.path(), None);
    let tree = vault.resolve("/tree").expect("a legal path");
    vault.create_directory(&owner(), &tree).expect("created");
    put(&vault, "/tree/a.txt", &vec![b'x'; 1024]);
    let inner = vault.resolve("/tree/inner").expect("a legal path");
    vault.create_directory(&owner(), &inner).expect("created");

    // Directly inside, deeper inside, and the collection itself.
    for destination in ["/tree/copy", "/tree/inner/copy", "/tree"] {
        let into = vault.resolve(destination).expect("a legal path");
        for replace in [false, true] {
            let refused =
                vault.copy_to(&owner(), &tree, &vault, &into, replace).expect_err("refused");
            assert_eq!(refused.status_code(), 403, "{destination}, replace={replace}");
            let moved = vault.move_to(&owner(), &tree, &vault, &into, replace);
            assert!(moved.is_err(), "{destination}, replace={replace}: {moved:?}");
        }
    }

    assert_eq!(
        names(&root.path().join("tree")),
        ["a.txt", "inner"],
        "the refusal created nothing"
    );
    assert!(names(&root.path().join("tree/inner")).is_empty());
    assert_eq!(
        std::fs::metadata(root.path().join("tree/a.txt")).expect("still there").len(),
        1024
    );
}

#[test]
fn f2b_a_tree_this_api_can_build_is_a_tree_this_api_can_remove() {
    // The second half of the finding, and the worse one: the wreckage the
    // runaway copy left could not be deleted. `DELETE` refused it with the same
    // depth limit that had stopped the copy, so one request produced a directory
    // the operator could only remove by going to the box over SSH.
    //
    // It does not take a runaway copy to build such a tree — a client that
    // issues `MKCOL` a hundred times has done it through the front door — so the
    // property is stated in those terms: whatever this API can make, it can
    // remove. The recursion is still bounded; the operation is not. `crates/
    // storage/src/fs.rs::remove_tree` explains how both are true at once.
    let root = Scratch::new("f2-deep");
    let vault = volume("vault", root.path(), None);

    let levels = MAX_TREE_DEPTH + 8;
    let mut here = String::new();
    for _ in 0..levels {
        here.push_str("/d");
        let at = vault.resolve(&here).expect("a legal path");
        vault.create_directory(&owner(), &at).expect("created through the front door");
    }
    put(&vault, &format!("{here}/bottom.txt"), b"at the bottom");

    let top = vault.resolve("/d").expect("a legal path");
    vault.delete(&owner(), &top).expect("removed through the same API that made it");
    assert!(names(root.path()).is_empty());
}

// ---------------------------------------------------------------------------
// 3. An upload writes no more than the length every ceiling was measured
//    against.
// ---------------------------------------------------------------------------

#[test]
fn f3_a_receiver_cannot_write_past_the_length_it_was_admitted_against() {
    // The finding: `Receiver::write` re-checked only the quota, so on a share
    // with no quota it re-checked nothing. A client that declared one byte and
    // then sent four megabytes was never refused — and the declaration is what
    // the quota, the in-flight budget *and* the free-space floor were all
    // admitted against, so all three were bypassed together. On this box the
    // same volume holds the mail spool and the TLS key store.
    let root = Scratch::new("f3");
    let vault = volume("vault", root.path(), None);
    let at = vault.resolve("/liar.bin").expect("a legal path");

    let mut receiver = vault.receive(&owner(), &at, Existing::Refuse, 1).expect("admitted");
    receiver.write(b"x").expect("within the declaration");
    let refused = receiver.write(&vec![0u8; 64 * 1024]).expect_err("refused past the declaration");
    assert_eq!(refused.status_code(), 400, "a body longer than its framing is the client's bug");
    assert_eq!(receiver.received(), 1, "a refused chunk is not a chunk that landed");
    receiver.commit().expect("committed");

    assert_eq!(
        std::fs::metadata(root.path().join("liar.bin")).expect("landed").len(),
        1,
        "one byte was declared and one byte is what the share holds"
    );
}

#[test]
fn f3b_the_same_ceiling_holds_through_the_resumable_session_table() {
    // The same hole reached through `Sessions`, which is the path a large upload
    // over a tunnel actually takes. It is the same `Receiver` underneath, and
    // this asserts that it is — a session that re-implemented the check would be
    // a second place for it to be got wrong.
    let root = Scratch::new("f3b");
    let vault = volume("vault", root.path(), None);
    let sessions = Sessions::new();
    let at = vault.resolve("/resumed.bin").expect("a legal path");

    let receiver = vault.receive(&owner(), &at, Existing::Refuse, 4).expect("admitted");
    let ticket = sessions.begin(receiver).expect("a ticket");
    sessions.append(ticket.as_str(), 0, b"abcd").expect("within the declaration");
    let refused = sessions
        .append(ticket.as_str(), 4, &vec![7u8; 32 * 1024])
        .expect_err("refused past the declaration");
    assert_eq!(refused.status_code(), 400);

    // The refusal leaves the session usable and its offset honest, so a client
    // that miscounted can be told where it really is rather than being left with
    // a session whose offset is past the end of its own file.
    assert_eq!(sessions.progress(ticket.as_str()).expect("known").received, 4);
    sessions.finish(ticket.as_str()).expect("published");
    assert_eq!(std::fs::metadata(root.path().join("resumed.bin")).expect("landed").len(), 4);
}

// ---------------------------------------------------------------------------
// 4. A case-only rename is a rename.
// ---------------------------------------------------------------------------

#[test]
fn f4_a_case_only_rename_is_performed_rather_than_refused() {
    // The finding as reported: neither spelling of `MOVE` could fix a file's
    // capitalisation. The fold scan found the source itself and called it a
    // collision, so `report.pdf` to `Report.pdf` was refused on every volume —
    // a perfectly ordinary thing to ask a NAS for.
    //
    // It is the same root cause as the data loss below: the source was not
    // exempt from the rules protecting the destination.
    let root = Scratch::new("f4");
    let vault = volume("vault", root.path(), None);
    put(&vault, "/report.pdf", b"the only copy");
    let lower = vault.resolve("/report.pdf").expect("a legal path");
    let upper = vault.resolve("/Report.pdf").expect("a legal path");

    let landing = vault.move_to(&owner(), &lower, &vault, &upper, false).expect("renamed");
    assert_eq!(landing, Landing::Created, "nothing was replaced; a file was renamed");
    assert_eq!(names(root.path()), ["Report.pdf"]);
    assert_eq!(
        std::fs::read_to_string(root.path().join("Report.pdf")).expect("read"),
        "the only copy"
    );
}

#[test]
fn f4b_a_case_only_rename_with_replace_keeps_the_file() {
    // The finding: on a folding volume the destination `Report.pdf` *was* the
    // source, so `Overwrite: T` deleted it and the rename then failed with
    // `NotFound`. Observed outcome: `Err(NotFound)`, survivors: none. The file
    // was simply gone.
    //
    // Asserted the way it must hold on either kind of volume: after the
    // request, exactly one file exists, it holds the original bytes, and it is
    // not named with the reserved staging prefix — because the two-step rename
    // that performs this on a folding volume must not be able to strand it under
    // a name no listing will show.
    let root = Scratch::new("f4b");
    let vault = volume("vault", root.path(), None);
    put(&vault, "/report.pdf", b"the only copy");
    let lower = vault.resolve("/report.pdf").expect("a legal path");
    let upper = vault.resolve("/Report.pdf").expect("a legal path");

    let outcome = vault.move_to(&owner(), &lower, &vault, &upper, true);
    let survivors = names(root.path());
    assert_eq!(survivors.len(), 1, "outcome={outcome:?} survivors={survivors:?}");
    let survivor = survivors.first().expect("one file");
    assert!(
        survivor == "Report.pdf" || survivor == "report.pdf",
        "the file is under one of the two spellings, not a staged name: {survivor}"
    );
    assert_eq!(
        std::fs::read_to_string(root.path().join(survivor)).expect("read"),
        "the only copy"
    );
}

// ---------------------------------------------------------------------------
// 5. Replacing a name never replaces a different spelling of it.
// ---------------------------------------------------------------------------

#[test]
fn f5_a_put_beside_a_differently_spelled_name_refuses_rather_than_overwriting_it() {
    // The finding: the fold scan ran for `Existing::Refuse` only — which is to
    // say it ran for every path except the one every ordinary upload takes,. A
    // `PUT` is `Existing::Replace`. So `report.pdf` uploaded into a directory
    // holding `Report.pdf` skipped the scan; on a folding volume the exclusive
    // create failed, the staged replace renamed over the destination, and a
    // *different file with a different name* silently became the uploader's
    // bytes. On a case-sensitive volume it produced the pair no Mac or Windows
    // client can hold at once.
    //
    // Driven through `Dir` and `Upload` directly, as the review drove it, so the
    // guard sits on the primitive rather than on one caller of it.
    let root = Scratch::new("f5");
    let directory = Dir::open_root(root.path()).expect("the root opens");
    std::fs::write(root.path().join("Report.pdf"), b"original").expect("a fixture");

    let refused = selfhost_storage::fs::Upload::begin(&directory, "report.pdf", Existing::Replace)
        .expect_err("refused");
    assert!(
        refused.to_string().contains("Report.pdf"),
        "the refusal must name the file it would have destroyed: {refused}"
    );
    assert_eq!(names(root.path()), ["Report.pdf"], "nothing was created");
    assert_eq!(
        std::fs::read_to_string(root.path().join("Report.pdf")).expect("read"),
        "original",
        "an upload of a differently-spelled name overwrote an existing file"
    );

    // And the name the caller actually named is still replaceable: this refuses
    // nothing an overwrite is entitled to do.
    let mut replacing =
        selfhost_storage::fs::Upload::begin(&directory, "Report.pdf", Existing::Replace)
            .expect("the same name replaces");
    std::io::Write::write_all(replacing.file(), b"replacement").expect("written");
    replacing.commit().expect("committed");
    assert_eq!(
        std::fs::read_to_string(root.path().join("Report.pdf")).expect("read"),
        "replacement"
    );
}

// ---------------------------------------------------------------------------
// 6. Nothing can name a resource in an answer without going through the
//    encoder.
// ---------------------------------------------------------------------------

#[test]
fn f6_the_answers_that_carry_a_url_can_only_be_given_an_encoded_one() {
    // The finding: `Href` had no constructor from a `String`, deliberately —
    // and then `proppatch` and `created` took a `&str` and emitted it
    // unencoded. A share can hold a file called `a%2fb`, whose own text in a URL
    // asks for `a/b` one directory down, so the two functions handed clients a
    // URL for a different resource. The type was standing beside the hole rather
    // than closing it.
    //
    // The property is now structural: both take an `Href`, and the only way to
    // make one is `Mount::href`, which encodes every segment. The test that this
    // holds is that the code below is the *only* way to write it — a caller with
    // a hand-spelled string no longer compiles.
    let mount = Mount::for_share(&ShareId::parse("vault").expect("a legal share id"));
    let hostile = RelativePath::default().join("a%2fb").expect("a legal name");
    let href = mount.href(&hostile, Kind::File);
    assert_eq!(href.as_str(), "/dav/vault/a%252fb");

    let response = selfhost_storage::dav::method::proppatch(&href, b"");
    let body = match &response.body {
        selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).into_owned(),
        other => panic!("expected an in-memory body, got {other:?}"),
    };
    assert!(body.contains("<D:href>/dav/vault/a%252fb</D:href>"), "{body}");

    // The URL a client follows resolves back to the file it was rendered from,
    // rather than to a name one directory down.
    let resolved =
        selfhost_storage::path::resolve(Path::new("/srv/vault"), "/a%252fb").expect("resolves");
    assert_eq!(resolved.relative().segments(), ["a%2fb"]);

    let created = selfhost_storage::dav::method::created(&href);
    assert_eq!(created.headers.get_str("location"), Some("/dav/vault/a%252fb"));
}

// ---------------------------------------------------------------------------
// 7. A symlink is listed, and listed as something no URL will fetch.
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[test]
fn f7_a_symlink_is_listed_as_a_name_that_cannot_be_reached() {
    // The finding: a listing reported a symlink pointing outside the share as an
    // ordinary zero-byte file with `reachable == true`, and `PROPFIND` minted an
    // `href` for it. `Kind`'s own documentation had always said a symlink is
    // reported unreachable — the code decided reachability from the *name*, and
    // a link's name is perfectly ordinary.
    //
    // Nothing was ever served through it: the descriptor walk refuses the link,
    // so every `GET` was a `404`. What the listing did was advertise a URL that
    // could not work, and tell the console a name it must grey out was fine.
    let root = Scratch::new("f7");
    let outside = Scratch::new("f7-outside");
    std::fs::write(outside.path().join("secret"), b"secret").expect("a fixture");
    std::os::unix::fs::symlink(outside.path().join("secret"), root.path().join("link.txt"))
        .expect("linked");
    std::os::unix::fs::symlink(outside.path(), root.path().join("dir")).expect("linked");
    std::fs::write(root.path().join("real.txt"), b"real").expect("a fixture");
    let vault = volume("vault", root.path(), None);

    let listing = vault.listing(&owner(), &RelativePath::default()).expect("listed");
    assert_eq!(listing.entries.len(), 3, "a link is shown, not hidden");

    for name in ["link.txt", "dir"] {
        let entry = listing.entries.iter().find(|entry| entry.name == name).expect("listed");
        assert!(!entry.reachable(), "{name} was offered as a name a URL could fetch");
        assert!(entry.blocked.is_some(), "{name} carries no reason for the console to show");

        // No link in the JSON, and no `href` from `PROPFIND` — the two places
        // the claim leaked out into something a client would follow.
        let json = entry.to_json(&RelativePath::default()).to_text();
        assert!(!json.contains(r#""path""#), "{name}: {json}");
        assert!(
            selfhost_storage::dav::propfind::Resource::from_entry(&RelativePath::default(), entry)
                .is_none(),
            "{name} was given a WebDAV href"
        );
    }

    // And the ordinary file beside them is untouched, so this is a rule rather
    // than an outage.
    let real = listing.entries.iter().find(|entry| entry.name == "real.txt").expect("listed");
    assert!(real.reachable());
    assert_eq!(real.size, 4);
    assert_eq!(std::fs::read_to_string(outside.path().join("secret")).expect("read"), "secret");
}

// ---------------------------------------------------------------------------
// Controls: the properties the review could not break, kept so that a fix
// somewhere else cannot quietly take them away.
// ---------------------------------------------------------------------------

#[test]
fn c1_destination_header_cannot_be_talked_out_of_the_mount() {
    use selfhost_storage::dav::method::destination;
    for hostile in [
        "https://admin.example@evil.example/dav/vault/a",
        "https://admin.example:443@evil.example/dav/vault/a",
        "/dav/vault/../../../etc/passwd",
        "//evil.example/dav/vault/a",
        "/dav/../etc/passwd",
        "/dav//vault/a",
        "/dav/vault/a?/../../etc/shadow",
        "/dav/vault/%2e%2e%2f%2e%2e%2fetc",
        "HTTPS://admin.example/dav/vault/a",
        "/dav/vault/a\\..\\..\\etc",
    ] {
        let Ok(parsed) = destination(Some(hostile), Some("admin.example")) else {
            continue;
        };
        let root = Path::new("/srv/vault");
        if let Ok(resolved) = selfhost_storage::path::resolve(root, &parsed.path) {
            assert!(
                resolved.textual_path().starts_with(root),
                "{hostile} escaped as {:?}",
                resolved.textual_path()
            );
        }
    }
}

#[test]
fn c2_a_cross_share_move_cannot_reach_a_share_the_caller_lacks() {
    // The destination volume's own permit runs inside `move_to`, not only at the
    // route: proved with a read-only destination.
    let source_root = Scratch::new("c2-src");
    let target_root = Scratch::new("c2-dst");
    let source = volume("vault", source_root.path(), None);
    let target_share =
        Share::new(&reserved(), "archive", target_root.path(), true, true, None).expect("a share");
    let target = Volume::open(target_share, Arc::new(Ledger::new())).expect("the root opens");
    put(&source, "/a.txt", b"x");

    let from = source.resolve("/a.txt").expect("a legal path");
    let to = target.resolve("/a.txt").expect("a legal path");
    let refused = source.move_to(&owner(), &from, &target, &to, true).expect_err("refused");
    assert_eq!(refused.tag(), "not-permitted");
    assert!(source_root.path().join("a.txt").exists());
}

#[test]
fn c3_the_empty_relative_path_is_the_share_root_and_cannot_be_deleted() {
    let root = Scratch::new("c3");
    let vault = volume("vault", root.path(), None);
    put(&vault, "/a.txt", b"x");

    assert!(vault.delete(&owner(), &RelativePath::default()).is_err());
    assert!(root.path().exists());
    assert!(root.path().join("a.txt").exists());
}

#[test]
fn c4_landing_status_is_what_the_wire_says() {
    assert_eq!(Landing::Created.status().code(), 201);
    assert_eq!(Landing::Replaced.status().code(), 204);
}
