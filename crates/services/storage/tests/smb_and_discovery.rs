//! The two acceptance tests for what this crate hands to other people's software.
//!
//! Everything in `src/smb` and `src/discover` is asserted at the unit level
//! already. What cannot be asserted there is the property the whole SMB module
//! exists for, because it is a statement about *this machine*:
//!
//! > A reconcile leaves every share point selfhost did not create exactly as it
//! > found it.
//!
//! This host is the right place to test that, because it already exports a
//! pre-existing, guest-accessible share point — *"Alex Waldmann's Public
//! Folder"*, `/Users/alexwaldmann/Public`, `smb_guest_access: 1` — which a naive
//! reconcile would either adopt and rewrite or delete outright. So the test runs
//! the real pipeline against the real host and compares the operating system's
//! own listing byte for byte, before and after.
//!
//! It runs in dry-run mode, which is not a weakening of the test but the whole
//! shape of the guarantee: `Apply::DryRun` is the default, it is what a console
//! refresh and a `doctor` check will call, and "the thing the console does on a
//! timer never touches anybody's shares" is exactly the property worth pinning.
//! Applying for real needs root, which a test suite must never have.
//!
//! On a host with no `sharing` — every non-Mac — the SMB tests have no subject:
//! there is no share table for a reconcile to leave alone. They still pass
//! there, because a missing tool is an honest answer and not a failure, but they
//! **say so on stderr** rather than returning quietly. The distinction the code
//! below is careful about is between that host and one which *has* the tool and
//! could not be got an answer out of — a broken tool, a changed `-f json`
//! output, a sandbox that blocks the spawn — because the second is a failure
//! reported as a pass, which is the one thing a regression guard must never do.
//! The discovery tests are pure and run everywhere.

use selfhost_storage::discover::{
    advertisements, publication, records, DavEndpoint, HostIdentity, Publication, ServiceType,
};
use selfhost_storage::share::{Reserved, Share, Shares, SmbExport, SmbName};
use selfhost_storage::smb::plan::{Apply, Owned};
use selfhost_storage::smb::{detect, sync, OwnershipLedger, SmbError, SyncReport};
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};

/// The operating system's share tool. Its *presence* is what decides whether
/// these tests have a subject, which is a different question from whether it
/// answered.
const SHARING_TOOL: &str = "/usr/sbin/sharing";

/// Says out loud that a test found no subject on this host, in a way a plain
/// `cargo test` run shows.
///
/// Written straight to the stream rather than through `eprintln!` on purpose:
/// `libtest` captures the printing macros and reveals what they wrote only for a
/// test that *fails*, so a banner explaining that a passing test asserted nothing
/// is precisely the message the capture would swallow. A test that skips in
/// silence is indistinguishable from one that ran, and this suite guards
/// properties about not deleting other people's shares.
fn announce_no_subject(reason: &str) {
    let banner = format!("SKIPPED: {reason}\n");
    let mut stderr = std::io::stderr();
    let _ = std::io::Write::write_all(&mut stderr, banner.as_bytes());
    let _ = std::io::Write::flush(&mut stderr);
}

/// Reads the operating system's own share table, as text, without going through
/// any of this crate's parsing.
///
/// Deliberately not [`selfhost_storage::smb::SmbBackend::snapshot`]: the point of
/// the acceptance test is to compare what the *operating system* says before and
/// after, so a bug in this crate's parser cannot make the two readings agree.
fn raw_share_table() -> Option<String> {
    let output = std::process::Command::new(SHARING_TOOL).args(["-l", "-f", "json"]).output();
    match output {
        Ok(output) if output.status.success() => {
            Some(String::from_utf8_lossy(&output.stdout).into_owned())
        }
        _ => None,
    }
}

/// The share table, or `None` on a host that genuinely has no such thing.
///
/// The old spelling of every skip in this file was
/// `let Some(table) = raw_share_table() else { return };`, which cannot tell the
/// two failing hosts apart. A machine with no [`SHARING_TOOL`] has nothing to say
/// about share points and skipping is the honest answer; a machine that has the
/// tool and got nothing out of it has an SMB test suite that no longer tests
/// SMB, and it reported that as a green tick. So the tool's presence is asked
/// separately from its answer, and only the first outcome is a skip.
fn share_table_or_no_subject() -> Option<String> {
    if let Some(table) = raw_share_table() {
        return Some(table);
    }
    assert!(
        !Path::new(SHARING_TOOL).exists(),
        "{SHARING_TOOL} is installed on this host but produced no share table. These tests \
         are about what a reconcile does to somebody else's shares, and a host that cannot be \
         asked what its shares are must not report that as a pass."
    );
    announce_no_subject(&format!(
        "this host has no {SHARING_TOOL}, so it exports no SMB share table for a reconcile to \
         leave alone"
    ));
    None
}

/// A dry-run reconcile, or `None` on a host with no SMB driver at all.
///
/// The three acceptance tests below each need this decision and each used to
/// make it themselves, which is how they drifted: the first one's own comment
/// said that "a Mac whose `sharing` answered the raw read but whose plan could
/// not be built is a real failure", while its code accepted `ToolMissing` and
/// `Unsupported` unconditionally and passed. Stated once, and stated against the
/// fact that decides it — whether the operating system just answered a question
/// about its own shares.
async fn dry_run(
    ledger: &OwnershipLedger,
    shares: &Shares,
    host_answered: bool,
) -> Option<SyncReport> {
    match sync(&detect(), ledger, shares, Apply::DryRun).await {
        Ok(report) => Some(report),
        Err(error)
            if !host_answered
                && matches!(
                    error,
                    SmbError::ToolMissing { .. } | SmbError::Unsupported { .. }
                ) =>
        {
            announce_no_subject(&format!("this host has no SMB driver to plan against: {error}"));
            None
        }
        Err(other) => panic!(
            "a dry run failed for a reason that is not 'this host has no SMB driver', so it is \
             a real failure and not an absent subject — the operating system's own share tool \
             {}: {other}",
            if host_answered { "answered a moment ago" } else { "gave no answer" }
        ),
    }
}

/// A scratch data directory, removed by the caller.
fn scratch(label: &str) -> PathBuf {
    let directory =
        std::env::temp_dir().join(format!("selfhost-smb-acceptance-{label}-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("a scratch directory");
    directory
}

/// One share configured exactly as an operator would write it: exported over SMB
/// under a name that is not on this host, and browsable.
fn configured_shares(data_dir: &PathBuf) -> Shares {
    let reserved = Reserved::new(data_dir, None).expect("a legal data directory");
    let share = Share::new(
        &reserved,
        "vault",
        PathBuf::from("/srv/selfhost-vault"),
        false,
        true,
        None,
    )
    .expect("a legal share")
    .with_smb(SmbExport {
        name: SmbName::parse("SelfhostAcceptanceVault").expect("a legal share name"),
        encrypt: true,
        read_only: false,
    });
    Shares::new(vec![share]).expect("a legal share set")
}

#[tokio::test]
async fn a_reconcile_leaves_a_share_point_selfhost_did_not_create_exactly_as_it_found_it() {
    let Some(before) = share_table_or_no_subject() else {
        // A host with no share table at all: there is nothing here that a
        // reconcile could change, and the skip has announced itself.
        return;
    };

    let data_dir = scratch("untouched");
    let shares = configured_shares(&data_dir);
    let ledger = OwnershipLedger::under(&data_dir);

    let report = dry_run(&ledger, &shares, true).await.expect("the share tool just answered");

    let after = raw_share_table().expect("the tool answered a moment ago");
    assert_eq!(before, after, "a reconcile changed somebody else's share table");

    assert!(
        report.plan.remove.is_empty(),
        "nothing may be scheduled for removal on a host we have created nothing on: {:?}",
        report.plan.remove
    );
    assert!(report.performed.iter().all(|step| !step.applied), "a dry run applied a step");
    assert!(
        report.owned.is_empty(),
        "a dry run must not record ownership of anything: {:?}",
        report.owned.names().collect::<Vec<_>>()
    );
    assert!(!ledger.path().exists(), "a dry run must not write the ledger");

    // Whatever this Mac exports, every one of them is somebody else's and must
    // be reported as unmanaged.
    for share in &report.state.shares {
        assert!(!share.managed, "we did not create {:?}", share.name);
        assert!(
            report.plan.untouched.contains(&share.name),
            "{:?} must be named as left alone",
            share.name
        );
    }
    assert!(
        report.state.to_json().to_text().contains("operating-system"),
        "the console's copy of the state must carry the authentication caveat"
    );

    std::fs::remove_dir_all(&data_dir).expect("cleanup");
}

#[tokio::test]
async fn this_hosts_public_folder_is_recognised_as_guest_accessible_and_still_left_alone() {
    // Three nested conditions used to stand between this test and an assertion:
    // no share tool, no `smb_guest_access` in its output, and an `if let Ok` that
    // discarded a failed plan. All three returned green. Two are gone — the plan
    // is now demanded rather than hoped for, and the properties that hold for
    // *every* share this host exports are asserted before guest access is
    // mentioned, so a Mac that shares nothing guest-accessible still tests
    // something. The remaining condition is the honest one: a host with no share
    // table has no shares for this to be about.
    let Some(raw) = share_table_or_no_subject() else {
        return;
    };

    let data_dir = scratch("guest");
    let shares = configured_shares(&data_dir);
    let ledger = OwnershipLedger::under(&data_dir);

    let report = dry_run(&ledger, &shares, true).await.expect("the share tool just answered");
    for share in &report.state.shares {
        assert!(
            report.plan.untouched.iter().any(|other| other == &share.name),
            "{:?} is somebody else's share and must be named as left alone",
            share.name
        );
    }
    assert!(report.plan.update.is_empty(), "we do not repair other people's shares");
    assert!(report.plan.remove.is_empty(), "nor delete them");

    // And the guest-accessible ones specifically, which are the ones a naive
    // reconcile would "fix". Reported by the parser, and cross-checked against
    // the operating system's own text so that a parser which stopped reading the
    // flag could not make this half quietly vacuous.
    let guest_shares: Vec<&str> = report
        .state
        .shares
        .iter()
        .filter(|share| share.guest_access)
        .map(|share| share.name.as_str())
        .collect();
    let compact: String = raw.chars().filter(|character| !character.is_whitespace()).collect();
    assert_eq!(
        !guest_shares.is_empty(),
        compact.contains("\"smb_guest_access\":1"),
        "the parser and the operating system disagree about whether anything on this host is \
         guest-accessible; the parser named {guest_shares:?}"
    );
    for name in &guest_shares {
        assert!(
            report.plan.untouched.iter().any(|other| other == name),
            "{name:?} is guest-accessible and must still be left alone"
        );
    }

    std::fs::remove_dir_all(&data_dir).expect("cleanup");
}

#[tokio::test]
async fn an_empty_ownership_ledger_can_never_produce_a_removal() {
    // The safety property stated without needing a Mac: whatever the host
    // exports, a deployment that has recorded creating nothing removes nothing.
    // The ledger half runs everywhere; the plan half needs a driver, and says so
    // when there is none rather than passing in silence.
    let data_dir = scratch("empty-ledger");
    let ledger = OwnershipLedger::under(&data_dir);
    assert_eq!(ledger.load().await.expect("a missing ledger is empty"), Owned::empty());

    let shares = configured_shares(&data_dir);
    let answered = raw_share_table().is_some();
    if let Some(report) = dry_run(&ledger, &shares, answered).await {
        assert!(report.plan.remove.is_empty(), "{:?}", report.plan.remove);
    }

    std::fs::remove_dir_all(&data_dir).expect("cleanup");
}

#[test]
fn the_derived_records_describe_the_services_this_deployment_actually_serves() {
    let data_dir = scratch("discover");
    let shares = configured_shares(&data_dir);
    let host = HostIdentity::new(
        "selfhost",
        "Xserve",
        vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8))],
    )
    .expect("a legal identity");
    let dav = DavEndpoint::new("admin.example.com", 443, true).expect("a legal endpoint");

    let ads = advertisements(&shares, &host, Some(&dav));
    let services: Vec<ServiceType> = ads.iter().map(|ad| ad.service).collect();
    assert_eq!(
        services,
        vec![ServiceType::Smb, ServiceType::WebDavSecure, ServiceType::DeviceInfo],
        "one SMB registration, one WebDAV registration, and the device description"
    );
    assert_eq!(ads[0].instance, "SelfhostAcceptanceVault", "the name the OS answers to");
    assert_eq!(ads[1].txt, vec!["path=/dav/vault".to_owned()], "the path WebDAV really serves");

    // PTR + SRV + TXT for two browsable services, TXT alone for the device
    // description, and one address record for the one address given.
    assert_eq!(records(&shares, &host, Some(&dav)).len(), 3 + 3 + 1 + 1);

    std::fs::remove_dir_all(&data_dir).expect("cleanup");
}

#[test]
fn nothing_is_advertised_for_a_share_the_operator_did_not_mark_browsable() {
    let data_dir = scratch("not-browsable");
    let reserved = Reserved::new(&data_dir, None).expect("legal");
    let share = Share::new(&reserved, "vault", PathBuf::from("/srv/v"), false, false, None)
        .expect("a legal share")
        .with_smb(SmbExport {
            name: SmbName::parse("Vault").expect("legal"),
            encrypt: true,
            read_only: true,
        });
    let shares = Shares::new(vec![share]).expect("a legal set");
    let host = HostIdentity::new("selfhost", "Xserve", Vec::new()).expect("legal");

    assert!(advertisements(&shares, &host, None).is_empty());
    assert!(records(&shares, &host, None).is_empty());

    std::fs::remove_dir_all(&data_dir).expect("cleanup");
}

#[test]
fn this_platform_says_plainly_whether_anything_will_publish_the_records() {
    let here = publication(std::env::consts::OS);
    assert!(!here.explanation().is_empty());
    match here {
        Publication::Bonjour | Publication::Avahi => assert!(here.publishes_dns_sd()),
        Publication::WindowsShareOnly | Publication::None => {
            assert!(!here.publishes_dns_sd(), "and the console must not imply otherwise");
        }
    }
}
