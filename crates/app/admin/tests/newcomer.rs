//! The three questions an operator asks before letting anybody else near this box.
//!
//! 1. **A stranger.** Somebody who holds nothing, or holds a wrong guess at
//!    something — can they reach anything at all, and can they learn anything
//!    from the refusal?
//! 2. **A newcomer.** Can a real second person be given a real credential and a
//!    named, bounded set of powers, walking the doors an operator actually walks?
//! 3. **Enforcement.** Once they hold it, is the boundary the one that was
//!    written down — on *every* route, not the handful somebody remembered?
//!
//! The three are one file because they are one property: the difference between
//! what the newcomer may reach and what the stranger may reach is exactly the
//! grant, and nothing else. Both halves are swept over the same table, which is
//! the point — a route that is added and forgotten fails
//! [`the_table_below_is_the_whole_api_surface`] before it can fail silently.
//!
//! Driven through [`Api::handle`] rather than a socket, like `api.rs`. The
//! credential ceremonies are real: a P-256 authenticator signs, the invitation
//! is minted by the owner through the API and redeemed by the newcomer's own
//! device, and every request below is answered by the code that answers the
//! browser's.

use selfhost_admin::{Api, ConsolePassword, Sessions, Store, Token};
use selfhost_http::{Body, Request, Response};
use selfhost_identity::{Capability, Grants, NodeName, Opening, People, PersonName, ShareId};
use selfhost_json::Json;
use selfhost_admin::storage_api::Volumes;
use selfhost_storage::api::Volume;
use selfhost_storage::quota::Ledger;
use selfhost_storage::share::{Mode, Reserved, Share};
use selfhost_supervisor::Supervisor;
use std::sync::Arc;

/// The bearer token in `<data_dir>/admin.token`: this box's own machine
/// credential, and — since the narrowing — not the operator.
const TOKEN: &str = "0123456789abcdef";

/// The console password. No test below guesses it; the stranger tests guess
/// *wrong* at it on purpose.
const PASSWORD: &str = "hunter2";

/// The relying party the console speaks for, and the origin the authenticators
/// below claim.
const RP: &str = "console.example.com";

/// The newcomer. A real second person, not the owner.
const NEWCOMER: &str = "guest";

/// The share the newcomer is given read access to.
const SHARE: &str = "vault";

/// The share they are given nothing on, to prove a grant is per-target.
const OTHER_SHARE: &str = "photos";

// ─── The surface ──────────────────────────────────────────────────────────────

/// What a route is expected to do when the caller is not permitted.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Reach {
    /// The newcomer's grant covers this: the answer is not a 401.
    Granted,
    /// The newcomer's grant does not cover this: the answer is the identical
    /// 401 a stranger gets.
    Withheld,
}

/// Every route `Route::of` serves, with what the newcomer's grant should reach.
///
/// Hand-derived from the match in `crates/app/admin/src/lib.rs`, and kept honest
/// by [`the_table_below_is_the_whole_api_surface`], which re-counts the arms in
/// that function on every run. The list is the test: a sweep over a table
/// somebody curated is a sweep over what they remembered, and the count is what
/// turns it back into a sweep over what exists.
const SURFACE: &[(&str, &str, Reach)] = &[
    // Capability::ConsoleRead — everything the console *shows*.
    ("GET", "/api/services", Reach::Granted),
    ("GET", "/api/services/anything", Reach::Granted),
    ("GET", "/api/services/anything/logs", Reach::Granted),
    ("GET", "/api/firewall", Reach::Granted),
    ("POST", "/api/desktop/ticket", Reach::Granted),
    ("GET", "/api/desktop", Reach::Granted),
    ("GET", "/api/desktop/nodes", Reach::Granted),
    ("GET", "/api/desktop/agent", Reach::Granted),
    ("GET", "/api/storage/shares", Reach::Granted),
    // Capability::FilesRead(vault) — held, on this share only.
    ("GET", "/api/storage/shares/vault/list", Reach::Granted),
    ("GET", "/api/storage/shares/vault/stat", Reach::Granted),
    // Capability::FilesWrite(vault) — not held. Reading a share is not writing
    // to it, and this is the pair that proves the ladder is a ladder.
    ("POST", "/api/storage/shares/vault/mkdir", Reach::Withheld),
    ("POST", "/api/storage/shares/vault/rename", Reach::Withheld),
    ("DELETE", "/api/storage/shares/vault/entry", Reach::Withheld),
    ("POST", "/api/storage/shares/vault/sessions", Reach::Withheld),
    ("GET", "/api/storage/shares/vault/sessions/ticket", Reach::Withheld),
    ("POST", "/api/storage/shares/vault/sessions/ticket", Reach::Withheld),
    // Capability::ServiceControl — everything that changes the machine.
    ("PUT", "/api/services/anything", Reach::Withheld),
    ("DELETE", "/api/services/anything", Reach::Withheld),
    ("POST", "/api/services/anything/deploy", Reach::Withheld),
    ("POST", "/api/services/anything/restart", Reach::Withheld),
    ("POST", "/api/self-update/deploy", Reach::Withheld),
    ("POST", "/api/firewall/reconcile", Reach::Withheld),
    // Demand::OwnerReads — the record of everybody else.
    ("GET", "/api/audit", Reach::Withheld),
    ("GET", "/api/webauthn/credentials", Reach::Withheld),
    // Demand::Enrolment — the owner's recovery path, by whichever credential
    // they still hold. A person is not the owner, so it is closed to them.
    ("POST", "/api/webauthn/register/challenge", Reach::Withheld),
    ("POST", "/api/webauthn/register", Reach::Withheld),
    // Demand::OwnerOnly — minting and destroying authority.
    ("DELETE", "/api/webauthn/credentials/anything", Reach::Withheld),
    ("GET", "/api/people", Reach::Withheld),
    ("PUT", "/api/people/guest", Reach::Withheld),
    ("DELETE", "/api/people/guest", Reach::Withheld),
    ("POST", "/api/people/guest/invite", Reach::Withheld),
    ("GET", "/api/people/invites", Reach::Withheld),
    ("DELETE", "/api/people/invites/guest", Reach::Withheld),
    // Demand::Authenticated — what the caller is, answered to the caller.
    ("GET", "/api/whoami", Reach::Granted),
    ("GET", "/api/people/capabilities", Reach::Granted),
];

/// The doors that stand *ahead* of the wall by design, and must therefore be
/// refused on their own terms rather than by the wall.
const DOORS: &[(&str, &str)] = &[
    ("POST", "/api/session"),
    ("GET", "/api/session"),
    ("DELETE", "/api/session"),
    ("POST", "/api/invite/challenge"),
    ("POST", "/api/invite/register"),
    ("POST", "/api/webauthn/login/challenge"),
    ("POST", "/api/webauthn/login"),
];

// ─── Question one: the stranger ───────────────────────────────────────────────

#[tokio::test]
async fn the_table_below_is_the_whole_api_surface() {
    // A sweep is only a sweep if the table is complete, and a hand-written table
    // rots the moment somebody adds a route. So: count the arms of `Route::of`
    // in the source and compare. This fails loudly on a new route, which is the
    // only moment anybody would remember to decide what it demands.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("this crate's own source");
    let body = source
        .split_once("    fn of(method: &Method, segments: &[&'a str]) -> Option<Self> {")
        .expect("Route::of still exists")
        .1
        .split_once("\n            _ => None,")
        .expect("Route::of still ends in a catch-all")
        .0;
    // `Some(Self::` rather than `=> Some(Self::`: several arms wrap their body
    // in a block to fit the line, and matching on the arrow would silently miss
    // exactly those — a counter that undercounts is worse than none, because it
    // passes.
    let arms = body.matches("Some(Self::").count();
    assert_eq!(
        arms,
        SURFACE.len(),
        "`Route::of` has {arms} arms and this file sweeps {}. A route was added \
         or removed and nobody said what a newcomer may do with it — add it to \
         `SURFACE` with a deliberate `Reach`.",
        SURFACE.len(),
    );
}

#[tokio::test]
async fn a_stranger_reaches_nothing_and_learns_nothing_from_being_refused() {
    // The threat model is the plainest one there is: somebody who is not
    // supposed to be here, at the door, with whatever they can make up. Four
    // kinds of nothing — no credential at all, a guessed bearer token, a forged
    // session cookie, and a cookie shaped like a real one — swept over every
    // route this API serves.
    //
    // Two properties, not one. Refused is the obvious half. The half that gets
    // forgotten is that every refusal must be *the same* refusal: if "no such
    // service" and "not for you" differ, the wall becomes a directory of what
    // is behind it, and an attacker maps the deployment without ever getting in.
    let (api, _dir) = deployment("stranger").await;

    let strangers: &[(&str, Vec<(&str, String)>)] = &[
        ("nothing at all", vec![]),
        ("a guessed bearer token", vec![("Authorization", "Bearer letmein".into())]),
        ("the token with one byte wrong", vec![("Authorization", format!("Bearer {TOKEN}x"))]),
        ("a forged cookie", vec![("Cookie", "selfhost_session=forged".into())]),
        (
            "a cookie shaped like a real one",
            vec![("Cookie", format!("selfhost_session={}", "a".repeat(43)))],
        ),
        (
            "a forged cookie carrying the CSRF header",
            vec![
                ("Cookie", "selfhost_session=forged".into()),
                ("X-Selfhost-Console", "1".into()),
            ],
        ),
    ];

    let mut canonical: Option<String> = None;
    for (who, headers) in strangers {
        let headers: Vec<(&str, &str)> =
            headers.iter().map(|(k, v)| (*k, v.as_str())).collect();
        for (method, target, _) in SURFACE {
            let response = call_with(&api, method, target, &headers, "{}").await;
            assert_eq!(
                response.status.code(),
                401,
                "{method} {target} answered a stranger holding {who}",
            );
            let body = body_json(&response).to_text();
            match &canonical {
                None => canonical = Some(body),
                Some(first) => assert_eq!(
                    &body, first,
                    "{method} {target} told a stranger holding {who} something the \
                     other refusals did not",
                ),
            }
        }
    }

    // And the one route that is deliberately open, so the sweep above is a
    // statement about the wall rather than about a deployment that answers
    // nothing at all.
    let health = call_with(&api, "GET", "/api/health", &[], "").await;
    assert_eq!(health.status.code(), 200, "the liveness probe is open by design");
}

#[tokio::test]
async fn the_doors_ahead_of_the_wall_refuse_a_stranger_on_their_own_terms() {
    // Four paths answer before `authorised()` runs, because they are how a
    // caller *becomes* authorised. Each is its own attack surface and none of
    // them may hand out anything to somebody who guesses.
    let (api, _dir) = deployment("stranger-doors").await;

    for (method, target) in DOORS {
        // Without the console header, every one of them is a flat 401: they
        // cannot be driven from a hostile page that cannot set a custom header.
        //
        // `DELETE /api/session` is the one exception and it is deliberate. It
        // is logout: it revokes whatever cookie the caller presented and can
        // therefore only ever take a credential *away*. Forging it from a
        // hostile page signs the operator out, which is a nuisance and not an
        // escalation, and demanding the header would mean a browser that has
        // lost its console context cannot clear its own session. Stated here so
        // that a future 200 on any of the others is a failure rather than a
        // shrug.
        let expected = if (*method, *target) == ("DELETE", "/api/session") { 200 } else { 401 };
        let bare = call_with(&api, method, target, &[], "{}").await;
        assert_eq!(
            bare.status.code(),
            expected,
            "{method} {target} answered a caller with no console header",
        );
        if expected == 200 {
            assert!(
                bare.headers.get_str("set-cookie").is_some_and(|c| c.contains("Max-Age=0")),
                "logout without a credential should still only ever clear a cookie",
            );
        }
    }

    // A wrong password is the same 401 as no password, and mints nothing.
    let wrong = call_with(
        &api,
        "POST",
        "/api/session",
        &[("X-Selfhost-Console", "1")],
        r#"{"password":"not-the-password"}"#,
    )
    .await;
    assert_eq!(wrong.status.code(), 401);
    assert!(
        wrong.headers.get_str("set-cookie").is_none(),
        "a failed login handed out a cookie",
    );

    // A guessed invitation code opens nothing, and does not say whether the
    // name it names exists.
    let guessed = call_with(
        &api,
        "POST",
        "/api/invite/challenge",
        &[("X-Selfhost-Console", "1")],
        r#"{"code":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
    )
    .await;
    assert_eq!(guessed.status.code(), 401, "a guessed invitation code was answered");

    // And a login assertion from a device this deployment has never seen is
    // refused even though the challenge route will talk to anybody.
    let stranger_device = Authenticator::new();
    let challenge = call_with(
        &api,
        "POST",
        "/api/webauthn/login/challenge",
        &[("X-Selfhost-Console", "1")],
        "",
    )
    .await;
    if challenge.status.code() == 200 {
        let challenge = body_json(&challenge)
            .get("challenge")
            .and_then(Json::as_str)
            .expect("a challenge")
            .to_owned();
        let forged = call_with(
            &api,
            "POST",
            "/api/webauthn/login",
            &[("X-Selfhost-Console", "1")],
            &stranger_device.login_body(&challenge),
        )
        .await;
        assert_eq!(forged.status.code(), 401, "an unknown device was logged in");
        assert!(
            forged.headers.get_str("set-cookie").is_none(),
            "an unknown device was handed a session",
        );
    }
}

#[tokio::test]
async fn the_boxs_own_token_is_the_machine_and_not_the_operator() {
    // The finding this narrowing came from: a secret in a file used to be full
    // ownership with no name attached. It operates the box; it does not get to
    // decide who else may use it.
    let (api, _dir) = deployment("token-is-not-owner").await;
    let auth = [("Authorization", format!("Bearer {TOKEN}").as_str())]
        .map(|(k, v)| (k, v.to_owned()));
    let headers: Vec<(&str, &str)> = auth.iter().map(|(k, v)| (*k, v.as_str())).collect();

    for (method, target) in [
        ("GET", "/api/people"),
        ("PUT", "/api/people/guest"),
        ("DELETE", "/api/people/guest"),
        ("POST", "/api/people/guest/invite"),
        ("GET", "/api/people/invites"),
        ("DELETE", "/api/webauthn/credentials/anything"),
        ("POST", "/api/webauthn/register"),
    ] {
        let response = call_with(&api, method, target, &headers, "{}").await;
        assert_eq!(
            response.status.code(),
            401,
            "{method} {target} let a token in a file mint or destroy authority",
        );
    }

    // It does still run the box, or the CLI and the native console stop working.
    let listed = call_with(&api, "GET", "/api/services", &headers, "").await;
    assert_eq!(listed.status.code(), 200, "the machine credential still operates the box");
}

// ─── Question two: provisioning a newcomer ────────────────────────────────────

#[tokio::test]
async fn the_owner_provisions_a_newcomer_and_the_newcomer_walks_their_own_door() {
    // The whole operator path, end to end, through the routes a browser uses:
    // the owner enrols, names a second person, writes exactly what they may do,
    // mints them a one-time code, and then the *newcomer's own device* — a
    // different keypair, which has never touched this deployment — redeems it
    // and logs in under the name the invitation carried.
    let (api, dir, sessions) = deployment_with_sessions("newcomer").await;

    // ── The owner gets a credential that names them.
    let owner_cookie = password_login(&api).await;
    let owner_device = Authenticator::new();
    register_passkey(&api, &owner_cookie, &owner_device, "owner's laptop").await;
    let owner = passkey_login(&api, &owner_device).await;

    // From here the console password is no longer root: a passkey exists, so a
    // password login holds console.read and nothing else. That is the demotion
    // the model promises, and it is worth proving here rather than trusting.
    let demoted = call_with(
        &api,
        "PUT",
        "/api/people/guest",
        &[("Cookie", &owner_cookie), ("X-Selfhost-Console", "1")],
        r#"{"grants":["console.read"]}"#,
    )
    .await;
    assert_eq!(
        demoted.status.code(),
        401,
        "the console password was still able to mint authority after a passkey existed",
    );

    // ── The owner writes the grant. Whole set, never an increment.
    let granted = call_with(
        &api,
        "PUT",
        &format!("/api/people/{NEWCOMER}"),
        &[("Cookie", &owner), ("X-Selfhost-Console", "1")],
        &format!(r#"{{"grants":["console.read","files.read:{SHARE}"]}}"#),
    )
    .await;
    assert_eq!(granted.status.code(), 200, "{:?}", body_json(&granted).to_text());
    let held: Vec<String> = body_json(&granted)
        .get("grants")
        .and_then(Json::as_array)
        .expect("the grants that were written")
        .iter()
        .filter_map(|g| Json::as_str(g).map(str::to_owned))
        .collect();
    assert_eq!(held, vec!["console.read".to_owned(), format!("files.read:{SHARE}")]);

    // ── The owner mints the way in.
    let minted = call_with(
        &api,
        "POST",
        &format!("/api/people/{NEWCOMER}/invite"),
        &[("Cookie", &owner), ("X-Selfhost-Console", "1")],
        r#"{"hours":6}"#,
    )
    .await;
    assert_eq!(minted.status.code(), 200, "{:?}", body_json(&minted).to_text());
    let code = body_json(&minted)
        .get("code")
        .and_then(Json::as_str)
        .expect("the code, returned exactly once")
        .to_owned();

    // The code is not stored anywhere it can be read back — the file holds a
    // digest. A stolen data directory is not a stolen invitation.
    let stored = std::fs::read_to_string(dir.path().join("console.invites")).expect("the file");
    assert!(!stored.contains(&code), "the invitation file contains the code itself");
    assert!(stored.contains(NEWCOMER), "the invitation file should name who it is for");

    // ── The newcomer's own device, which has never been here.
    let their_device = Authenticator::new();
    let challenge = call_with(
        &api,
        "POST",
        "/api/invite/challenge",
        &[("X-Selfhost-Console", "1")],
        &format!(r#"{{"code":"{code}"}}"#),
    )
    .await;
    assert_eq!(challenge.status.code(), 200, "{:?}", body_json(&challenge).to_text());
    let challenge_value = body_json(&challenge)
        .get("challenge")
        .and_then(Json::as_str)
        .expect("a challenge")
        .to_owned();

    // The name comes from the invitation, never from the request. Claiming to
    // be the owner in the body must change nothing.
    let body = format!(
        r#"{{"user":"owner","code":"{code}",{}"#,
        their_device
            .register_body(&challenge_value, "the newcomer's phone")
            .trim_start_matches('{')
    );
    let registered =
        call_with(&api, "POST", "/api/invite/register", &[("X-Selfhost-Console", "1")], &body)
            .await;
    assert_eq!(registered.status.code(), 200, "{:?}", body_json(&registered).to_text());

    // ── They log in with it, and the session names them — not the owner.
    let theirs = passkey_login(&api, &their_device).await;
    let whoami = call_with(&api, "GET", "/api/whoami", &[("Cookie", &theirs)], "").await;
    assert_eq!(whoami.status.code(), 200);
    let me = body_json(&whoami);
    assert_eq!(
        me.get("name").and_then(Json::as_str),
        Some(NEWCOMER),
        "the invitation's name did not survive a request that claimed to be the owner",
    );
    assert_eq!(
        me.get("owner").and_then(Json::as_bool),
        Some(false),
        "a redeemed invitation produced an owner",
    );

    // ── The code works once.
    let replayed = call_with(
        &api,
        "POST",
        "/api/invite/challenge",
        &[("X-Selfhost-Console", "1")],
        &format!(r#"{{"code":"{code}"}}"#),
    )
    .await;
    assert_eq!(replayed.status.code(), 401, "a redeemed invitation code was accepted again");

    // Nothing above needed the injected session store; holding it keeps the
    // fixture honest about which sessions exist.
    drop(sessions);
}

// ─── Question three: enforcement ──────────────────────────────────────────────

#[tokio::test]
async fn the_newcomer_reaches_exactly_what_was_granted_and_nothing_else() {
    // The same table the stranger was swept over, walked again by somebody who
    // is genuinely known to this deployment and genuinely holds two grants. The
    // difference between the two sweeps is the whole permission system.
    let (api, _dir, sessions) = deployment_with_sessions("newcomer-enforcement").await;
    grant(
        &_dir,
        NEWCOMER,
        &[Capability::ConsoleRead, Capability::FilesRead(share(SHARE))],
    );
    let id = sessions.create(NEWCOMER, Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");
    let headers = [("Cookie", cookie.as_str()), ("X-Selfhost-Console", "1")];

    // What a stranger gets, so "withheld" can be asserted as *identical to*
    // rather than merely "also a 401".
    let anonymous = body_json(&call_with(&api, "GET", "/api/services", &[], "").await).to_text();

    for (method, target, reach) in SURFACE {
        let response = call_with(&api, method, target, &headers, "{}").await;
        let code = response.status.code();
        match reach {
            Reach::Granted => assert_ne!(
                code, 401,
                "{method} {target} refused a person who holds the capability it demands",
            ),
            Reach::Withheld => {
                assert_eq!(
                    code, 401,
                    "{method} {target} was reachable by a person granted only \
                     console.read and files.read:{SHARE}",
                );
                assert_eq!(
                    body_json(&response).to_text(),
                    anonymous,
                    "{method} {target} told a known person more than it tells a stranger",
                );
            }
        }
    }
}

#[tokio::test]
async fn a_grant_is_per_target_and_does_not_spread_to_the_neighbouring_share() {
    // `files.read:vault` is not `files.read`. The commonest way a capability
    // model fails in practice is that the target is checked at the door and
    // then dropped, so everything behind the door is one namespace.
    let (api, _dir, sessions) = deployment_with_sessions("per-target").await;
    grant(
        &_dir,
        NEWCOMER, &[Capability::ConsoleRead, Capability::FilesRead(share(SHARE))]);
    let id = sessions.create(NEWCOMER, Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");
    let headers = [("Cookie", cookie.as_str())];

    let mine =
        call_with(&api, "GET", &format!("/api/storage/shares/{SHARE}/list?path=/"), &headers, "")
            .await;
    assert_ne!(mine.status.code(), 401, "the granted share was refused");

    let theirs = call_with(
        &api,
        "GET",
        &format!("/api/storage/shares/{OTHER_SHARE}/list?path=/"),
        &headers,
        "",
    )
    .await;
    assert_eq!(
        theirs.status.code(),
        401,
        "a grant on one share reached the next one along",
    );

    // And a share that does not exist is refused the same way one they may not
    // touch is, so the API is not a directory of what this box stores.
    let invented =
        call_with(&api, "GET", "/api/storage/shares/no-such-share/list?path=/", &headers, "").await;
    assert_eq!(invented.status.code(), 401);
    assert_eq!(
        body_json(&invented).to_text(),
        body_json(&theirs).to_text(),
        "a share that exists and one that does not answer differently, which \
         makes this route a way to enumerate the box's storage",
    );
}

#[tokio::test]
async fn the_newcomer_cannot_widen_their_own_grant_by_any_route_that_exists() {
    // The escalation every permission model has to refuse by construction: the
    // holder of a bounded grant reaching for the thing that writes grants. The
    // vocabulary deliberately has no word for "may grant", so there should be
    // no path at all — including the indirect ones.
    let (api, dir, sessions) = deployment_with_sessions("no-escalation").await;
    grant(&dir, NEWCOMER, &[Capability::ConsoleRead, Capability::FilesRead(share(SHARE))]);
    let id = sessions.create(NEWCOMER, Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");
    let headers = [("Cookie", cookie.as_str()), ("X-Selfhost-Console", "1")];

    let attempts: &[(&str, &str, &str)] = &[
        // Straight at the registry, for themselves and for somebody new.
        ("PUT", "/api/people/guest", r#"{"grants":["service.control","files.admin"]}"#),
        ("PUT", "/api/people/accomplice", r#"{"grants":["service.control"]}"#),
        // Delete the person, hoping the absence reads as the owner.
        ("DELETE", "/api/people/guest", ""),
        // Mint themselves a second way in, under a name they choose.
        ("POST", "/api/people/accomplice/invite", r#"{"hours":24}"#),
        ("POST", "/api/people/guest/invite", r#"{"hours":24}"#),
        // Enrol another authenticator — a credential that outlives the grant.
        ("POST", "/api/webauthn/register/challenge", ""),
        // Take the owner's authenticator away and leave the password as root.
        ("DELETE", "/api/webauthn/credentials/anything", ""),
        // Drive the machine instead of asking it.
        ("POST", "/api/services/anything/start", "{}"),
        ("PUT", "/api/services/backdoor", r#"{"name":"backdoor","program":"/bin/sh"}"#),
        ("POST", "/api/firewall/reconcile", ""),
        // Read who else is here, to pick a better target.
        ("GET", "/api/people", ""),
        ("GET", "/api/audit", ""),
        ("GET", "/api/webauthn/credentials", ""),
    ];

    for (method, target, body) in attempts {
        let response = call_with(&api, method, target, &headers, body).await;
        assert_eq!(
            response.status.code(),
            401,
            "{method} {target} was a route out of a bounded grant",
        );
    }

    // And the registry on disk is untouched: no partial write, no new person.
    let people = People::load(dir.path());
    let entry = people
        .find(&PersonName::parse(NEWCOMER).expect("a legal name"))
        .expect("the newcomer is still there");
    let words: Vec<String> = entry.grants.iter().map(ToString::to_string).collect();
    assert_eq!(
        words,
        vec!["console.read".to_owned(), format!("files.read:{SHARE}")],
        "the grant changed while its holder was trying to change it",
    );
    assert!(
        people.find(&PersonName::parse("accomplice").expect("a legal name")).is_none(),
        "a person who was never granted anything now exists",
    );
}

#[tokio::test]
async fn taking_the_grant_away_takes_the_access_away_on_the_next_request() {
    // A permission system that only decides at login is a permission system
    // that cannot revoke. The session outlives the grant on purpose here: the
    // question is whether the *request* re-reads it.
    let (api, dir, sessions) = deployment_with_sessions("revocation").await;
    grant(&dir, NEWCOMER, &[Capability::ConsoleRead, Capability::FilesRead(share(SHARE))]);
    let id = sessions.create(NEWCOMER, Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");
    let headers = [("Cookie", cookie.as_str())];

    let before = call_with(&api, "GET", "/api/services", &headers, "").await;
    assert_ne!(before.status.code(), 401, "the grant did not work to begin with");

    People::load(dir.path())
        .set_grants(&PersonName::parse(NEWCOMER).expect("a legal name"), Grants::none())
        .expect("the grant is withdrawn");

    let after = call_with(&api, "GET", "/api/services", &headers, "").await;
    assert_eq!(
        after.status.code(),
        401,
        "a withdrawn grant was still being honoured on a live session",
    );

    // They are still a person, and can still be told so — which is the
    // difference between "revoked" and "deleted", and the reason `whoami` is
    // not behind a capability.
    let whoami = call_with(&api, "GET", "/api/whoami", &headers, "").await;
    assert_eq!(whoami.status.code(), 200);
    assert_eq!(
        body_json(&whoami).get("grants").and_then(Json::as_array).map(<[Json]>::len),
        Some(0),
    );
}

#[tokio::test]
async fn a_person_granted_a_desktop_may_watch_only_the_node_they_were_named_for() {
    // The one capability that drives a machine rather than serving data from
    // it, and the one whose target is a node rather than a share. Three
    // questions in one fixture: does a view grant stop at viewing, does it stop
    // at the node it names, and does the ticket route decide each requested
    // ability separately rather than handing back whatever the body asked for.
    //
    // `allow_input` is deliberately **on** here. With it off every control
    // request is refused by the deployment's own switch before the permission
    // model is consulted, and the test would pass without proving anything
    // about the grant.
    let (api, dir, sessions) = deployment_with_sessions("desktop-target").await;
    let api = api.with_desktop(
        selfhost_config::Desktop {
            enabled: true,
            allow_input: true,
            reauth_window_secs: 120,
            ..selfhost_config::Desktop::default()
        },
        Arc::new(TestFleet),
    );
    grant(
        &dir,
        NEWCOMER,
        &[
            Capability::ConsoleRead,
            Capability::DesktopView(NodeName::parse("alex-desktop").expect("a legal node")),
        ],
    );
    let id = sessions.create(NEWCOMER, Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");
    let headers = [("Cookie", cookie.as_str()), ("X-Selfhost-Console", "1")];

    let watching = call_with(
        &api,
        "POST",
        "/api/desktop/ticket",
        &headers,
        r#"{"peer":"alex-desktop","want":["desktop.view"]}"#,
    )
    .await;
    assert_eq!(
        watching.status.code(),
        200,
        "the node they were named for was refused: {:?}",
        body_json(&watching).to_text(),
    );

    // Control is never implied by view — you may not type on a machine merely
    // because you may look at it.
    let typing = call_with(
        &api,
        "POST",
        "/api/desktop/ticket",
        &headers,
        r#"{"peer":"alex-desktop","want":["desktop.control"]}"#,
    )
    .await;
    assert_eq!(
        typing.status.code(),
        401,
        "a view grant minted a ticket that can type on the keyboard",
    );

    // Nor does the clipboard come along with the screen: it is implied by
    // nothing, because the last thing copied on a machine is routinely a secret.
    let copying = call_with(
        &api,
        "POST",
        "/api/desktop/ticket",
        &headers,
        r#"{"peer":"alex-desktop","want":["desktop.clipboard"]}"#,
    )
    .await;
    assert_eq!(copying.status.code(), 401, "a view grant reached the clipboard");

    // And the grant names one machine, not "a desktop".
    let elsewhere = call_with(
        &api,
        "POST",
        "/api/desktop/ticket",
        &headers,
        r#"{"peer":"self","want":["desktop.view"]}"#,
    )
    .await;
    assert_eq!(
        elsewhere.status.code(),
        401,
        "a grant naming one node minted a ticket for another",
    );

    // The mixed request is the one that catches a route deciding the set rather
    // than each member of it: one ability they hold, one they do not.
    let mixed = call_with(
        &api,
        "POST",
        "/api/desktop/ticket",
        &headers,
        r#"{"peer":"alex-desktop","want":["desktop.view","desktop.control"]}"#,
    )
    .await;
    assert_eq!(
        mixed.status.code(),
        401,
        "asking for a held ability alongside a withheld one minted a ticket for both",
    );
}

/// A fleet that drives nothing, so every rule above is exercised on a laptop
/// with no capture backend and no peer link.
struct TestFleet;

impl selfhost_admin::Fleet for TestFleet {
    fn nodes(&self) -> Vec<selfhost_admin::NodeReport> {
        vec![
            selfhost_admin::NodeReport::local(),
            selfhost_admin::NodeReport {
                node: "alex-desktop".to_owned(),
                live: false,
                last_seen_secs: Some(90),
                reason: Some("the link was closed by the peer".to_owned()),
            },
        ]
    }

    fn agent(&self, node: &str) -> selfhost_admin::AgentReport {
        selfhost_admin::AgentReport::absent(node, "no capture backend is built for this host")
    }

    fn serve<'a>(
        &'a self,
        _session: selfhost_admin::Handover,
    ) -> selfhost_admin::desk_api::Task<'a, String> {
        Box::pin(async { "the test fleet drives nothing".to_owned() })
    }
}

// ─── The trail, and the words that open nothing ───────────────────────────────

#[tokio::test]
async fn every_act_of_authority_leaves_exactly_one_line_in_the_trail() {
    // The gap this closed. `AuditRecord` was keyed on a `Capability`, and the
    // routes that mint and destroy authority are owner-only precisely *because*
    // no capability names them — so the one act an audit trail exists for was
    // the one act it did not record. A permission model whose grants leave no
    // trace cannot answer "who let them in", which is the first question asked
    // after anything goes wrong.
    //
    // `docs/SECURITY.md` asks for a property checkable with `grep -c ''`: one
    // line per control action. So this counts lines, not just content.
    let (api, dir, _sessions) = deployment_with_sessions("authority-trail").await;
    // Captured before the owner enrols, because enrolling a passkey is itself
    // an act of authority and belongs in the count.
    let before = trail_lines(&dir);
    let owner_cookie = password_login(&api).await;
    let device = Authenticator::new();
    register_passkey(&api, &owner_cookie, &device, "owner's laptop").await;
    let owner = passkey_login(&api, &device).await;
    let headers = [("Cookie", owner.as_str()), ("X-Selfhost-Console", "1")];

    let granted = call_with(
        &api,
        "PUT",
        &format!("/api/people/{NEWCOMER}"),
        &headers,
        &format!(r#"{{"grants":["console.read","files.read:{SHARE}"]}}"#),
    )
    .await;
    assert_eq!(granted.status.code(), 200);
    let minted = call_with(
        &api,
        "POST",
        &format!("/api/people/{NEWCOMER}/invite"),
        &headers,
        r#"{"hours":6}"#,
    )
    .await;
    assert_eq!(minted.status.code(), 200);
    let code =
        body_json(&minted).get("code").and_then(Json::as_str).expect("a code").to_owned();

    // The newcomer's own device redeems it — the one line here that is not the
    // owner acting.
    let their_device = Authenticator::new();
    let challenge = call_with(
        &api,
        "POST",
        "/api/invite/challenge",
        &[("X-Selfhost-Console", "1")],
        &format!(r#"{{"code":"{code}"}}"#),
    )
    .await;
    let challenge_value = body_json(&challenge)
        .get("challenge")
        .and_then(Json::as_str)
        .expect("a challenge")
        .to_owned();
    let registered = call_with(
        &api,
        "POST",
        "/api/invite/register",
        &[("X-Selfhost-Console", "1")],
        &format!(
            r#"{{"code":"{code}",{}"#,
            their_device
                .register_body(&challenge_value, "the newcomer's phone")
                .trim_start_matches('{')
        ),
    )
    .await;
    assert_eq!(registered.status.code(), 200, "{:?}", body_json(&registered).to_text());

    let forgotten =
        call_with(&api, "DELETE", &format!("/api/people/{NEWCOMER}"), &headers, "").await;
    assert_eq!(forgotten.status.code(), 200);

    // Enrolling the owner's passkey happened above too, so five acts in all.
    let lines = trail_lines(&dir);
    let written: Vec<&String> = lines.iter().skip(before.len()).collect();
    let acts: Vec<&str> = written
        .iter()
        .filter_map(|line| line.split(" act=").nth(1))
        .map(|rest| rest.split(' ').next().unwrap_or(""))
        .collect();
    assert_eq!(
        acts,
        vec![
            "authority.enrol",
            "authority.grants",
            "authority.invite",
            "authority.redeem",
            "authority.forget",
        ],
        "one line per act, in order: {written:?}",
    );

    // The enrolment was made with the console password, and the trail says so:
    // "who was holding what when this credential was created" is the question
    // this line exists to answer.
    assert!(
        written[0].contains("identity=owner") && written[0].contains("credential=session.password"),
        "the enrolment does not record the credential that made it: {}",
        written[0],
    );
    // The grant line says what they now hold, spelled the way the console
    // spells it, so an operator can compare the two without interpreting.
    assert!(
        written[1].contains("target=guest") && written[1].contains("now:console.read,files.read:vault"),
        "the grant line does not say what was granted: {}",
        written[1],
    );
    // The redemption is recorded as the person, by the passkey they just made —
    // not as the owner, who was not present for it.
    assert!(
        written[3].contains("identity=person")
            && written[3].contains("who=guest")
            && written[3].contains("credential=passkey"),
        "the redemption is not recorded as the person: {}",
        written[3],
    );
    // And no invitation code is anywhere in the trail. The store keeps a
    // digest precisely so the code lives in one readable place; a log file in
    // the same directory would be a second.
    assert!(
        !lines.iter().any(|line| line.contains(&code)),
        "the audit log contains an invitation code",
    );
}

#[tokio::test]
async fn a_refused_authority_route_writes_nothing_at_all() {
    // The other half of "one line per act": a stranger sweeping every
    // owner-only route must not be able to fill the operator's audit log with
    // their own attempts. These routes record what *happened*, and nothing
    // happened.
    let (api, dir, sessions) = deployment_with_sessions("authority-refused").await;
    grant(&dir, NEWCOMER, &[Capability::ConsoleRead]);
    let id = sessions.create(NEWCOMER, Opening::Passkey).expect("a session");
    let cookie = format!("selfhost_session={id}");
    let before = trail_lines(&dir).len();

    for headers in [
        vec![("Cookie", cookie.as_str()), ("X-Selfhost-Console", "1")],
        vec![("X-Selfhost-Console", "1")],
    ] {
        for (method, target, body) in [
            ("PUT", "/api/people/accomplice", r#"{"grants":["service.control"]}"#),
            ("DELETE", "/api/people/guest", ""),
            ("POST", "/api/people/accomplice/invite", ""),
            ("DELETE", "/api/people/invites/guest", ""),
            ("DELETE", "/api/webauthn/credentials/anything", ""),
        ] {
            let response = call_with(&api, method, target, &headers, body).await;
            assert_eq!(response.status.code(), 401, "{method} {target}");
        }
    }
    assert_eq!(trail_lines(&dir).len(), before, "a refused attempt wrote a line");
}

#[tokio::test]
async fn a_capability_no_route_honours_cannot_be_granted() {
    // `site.admin`, `dns.admin` and `mail.admin` are real words in a real
    // vocabulary that no handler asks for. Granting one wrote a row an operator
    // reads as "she can manage the DNS" with no code path that agrees — a
    // promise, and the worst kind, because the failure surfaces as nothing
    // happening at all rather than as an error.
    let (api, dir, _sessions) = deployment_with_sessions("unhonoured").await;
    let owner_cookie = password_login(&api).await;
    let headers = [("Cookie", owner_cookie.as_str()), ("X-Selfhost-Console", "1")];

    for word in ["site.admin", "dns.admin", "mail.admin"] {
        let refused = call_with(
            &api,
            "PUT",
            &format!("/api/people/{NEWCOMER}"),
            &headers,
            &format!(r#"{{"grants":["console.read","{word}"]}}"#),
        )
        .await;
        assert_eq!(refused.status.code(), 400, "{word} was accepted as a grant");
        let said = body_json(&refused).to_text();
        assert!(said.contains(word), "the refusal does not name the word: {said}");
        assert!(said.contains("honours"), "the refusal does not say why: {said}");
    }

    // The whole set is refused, not the set minus the bad word — the same rule
    // an unknown word already followed. Nothing was written.
    assert!(
        People::load(dir.path()).find(&PersonName::parse(NEWCOMER).unwrap()).is_none(),
        "a refused grant set created the person anyway",
    );

    // And a client is told before it offers the toggle, rather than after.
    let vocabulary = call_with(&api, "GET", "/api/people/capabilities", &headers, "").await;
    let words = body_json(&vocabulary);
    let listed = words.as_array().expect("an array of words");
    let ungrantable: Vec<&str> = listed
        .iter()
        .filter(|entry| entry.get("grantable").and_then(Json::as_bool) == Some(false))
        .filter_map(|entry| entry.get("word").and_then(Json::as_str))
        .collect();
    assert_eq!(ungrantable, vec!["site.admin", "dns.admin", "mail.admin"]);
}

#[tokio::test]
async fn no_unhonoured_word_is_named_by_any_routes_demand() {
    // What keeps `Capability::is_honoured` from becoming a lie in the other
    // direction: the day somebody wires `site.admin` to a route and forgets to
    // flip the flag, that capability is demanded by a handler and refused at
    // the granting seam, so the feature ships dead. Read out of the source, for
    // the same reason `the_table_below_is_the_whole_api_surface` is.
    let source = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs"),
    )
    .expect("this crate's own source");
    let demands = source
        .split_once("    fn demand(&self) -> Demand {")
        .expect("Route::demand still exists")
        .1
        .split_once("
    }")
        .expect("Route::demand still ends")
        .0;
    for (variant, word) in
        [("SiteAdmin", "site.admin"), ("DnsAdmin", "dns.admin"), ("MailAdmin", "mail.admin")]
    {
        assert!(
            !demands.contains(&format!("Capability::{variant}")),
            "{word} is demanded by a route but `Capability::is_honoured` still says nothing              honours it — flip it to true, or the route can never be reached",
        );
    }
}

/// The audit log's lines, oldest first, or none if nothing has been written.
fn trail_lines(dir: &ScratchDir) -> Vec<String> {
    std::fs::read_to_string(dir.path().join("audit.log"))
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

// ─── The fixture ──────────────────────────────────────────────────────────────

/// A deployment with a console password, passkey login, a people registry, two
/// shares and an audit log — everything the three questions need.
async fn deployment(name: &str) -> (Api, ScratchDir) {
    let (api, dir, _sessions) = deployment_with_sessions(name).await;
    (api, dir)
}

/// The same, handing back the session store so a test can mint one directly
/// instead of walking a ceremony it is not the subject of.
async fn deployment_with_sessions(name: &str) -> (Api, ScratchDir, Sessions) {
    let dir = ScratchDir::new(name);
    let token = write_token(dir.path(), TOKEN);
    let sessions = Sessions::new();
    ConsolePassword::write(dir.path(), PASSWORD).expect("a console password");

    let ledger = Arc::new(Ledger::new());
    // The share's own access list names the newcomer, so what these tests vary
    // is the *capability*. Both layers are real and both have to pass.
    let on_the_share = vec![
        selfhost_storage::share::Grant::parse(NEWCOMER, Mode::Write).expect("a legal grant"),
    ];
    let volumes = Volumes::from_opened(vec![
        open_share(dir.path(), SHARE, &ledger, false, on_the_share.clone()),
        open_share(dir.path(), OTHER_SHARE, &ledger, false, on_the_share),
    ]);

    let api = Api::new(
        Supervisor::new(dir.path()),
        Store::new(dir.path()),
        token,
        selfhost_git::Watches::default(),
        firewall_manager(),
    )
    .with_console_auth_parts(ConsolePassword::load(dir.path()), sessions.clone())
    .with_console_webauthn(RP, dir.path())
    .with_people(People::load(dir.path()))
    .with_invites(selfhost_admin::invite::Invites::load(dir.path()))
    .with_audit(selfhost_identity::AuditLog::in_dir(dir.path()))
    .with_storage(volumes);
    (api, dir, sessions)
}

/// Writes a grant straight into the registry the API reads.
///
/// The owner-driven route is walked by
/// [`the_owner_provisions_a_newcomer_and_the_newcomer_walks_their_own_door`];
/// the enforcement tests use this so that a failure in one is never read as a
/// failure in the other.
fn grant(dir: &ScratchDir, person: &str, capabilities: &[Capability]) {
    let people = People::load(dir.path());
    let mut grants = Grants::none();
    for capability in capabilities {
        grants.grant(capability.clone()).expect("room for the grant");
    }
    people
        .set_grants(&PersonName::parse(person).expect("a legal name"), grants)
        .expect("grants are written");
}

fn share(id: &str) -> ShareId {
    ShareId::parse(id).expect("a legal share id")
}

fn open_share(
    dir: &std::path::Path,
    id: &str,
    ledger: &Arc<Ledger>,
    read_only: bool,
    grants: Vec<selfhost_storage::share::Grant>,
) -> Volume {
    let base = std::fs::canonicalize(dir).expect("a real scratch directory");
    let root = base.join(id);
    std::fs::create_dir_all(&root).expect("a share root");
    let reserved = Reserved::new(base.join("reserved-data"), None).expect("a reserved set");
    let share = Share::new(&reserved, id, root, read_only, false, None)
        .expect("a legal share")
        .with_grants(grants);
    Volume::open(share, Arc::clone(ledger)).expect("the root opens")
}

fn firewall_manager() -> selfhost_firewall::Manager {
    let config = selfhost_config::Config::parse(
        "version = 1\n\
         [server]\n\
         http_bind = \"127.0.0.1:8080\"\n\
         https_bind = \"127.0.0.1:8443\"\n\
         acme_email = \"a@b.com\"\n\
         acme = \"self-signed\"\n\
         data_dir = \"./data\"\n\
         [[nodes]]\n\
         name = \"home\"\n\
         role = \"owner\"\n\
         [[sites]]\n\
         name = \"hello\"\n\
         domains = [\"localhost\"]\n\
         static_root = \"./sites/hello\"\n",
    )
    .expect("a minimal valid config");
    selfhost_firewall::Manager::for_config(&config)
}

fn write_token(dir: &std::path::Path, value: &str) -> Token {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(selfhost_admin::token::TOKEN_FILENAME), value).unwrap();
    Token::load_or_create(dir).expect("loads the token we just wrote")
}

// ─── Requests ─────────────────────────────────────────────────────────────────

fn request_with(
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> (Request, Vec<u8>) {
    let mut text = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\n");
    for (name, value) in headers {
        text.push_str(&format!("{name}: {value}\r\n"));
    }
    if !body.is_empty() {
        text.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    text.push_str("\r\n");
    let parsed = Request::parse(text.as_bytes()).expect("well-formed request");
    (parsed.request, body.as_bytes().to_vec())
}

async fn call_with(
    api: &Api,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Response {
    let (request, body) = request_with(method, target, headers, body);
    api.handle(&request, &body).await
}

fn body_json(response: &Response) -> Json {
    match &response.body {
        Body::Bytes(bytes) => selfhost_json::parse(std::str::from_utf8(bytes).unwrap_or("null"))
            .unwrap_or(Json::Null),
        _ => Json::Null,
    }
}

fn session_cookie_pair(response: &Response) -> String {
    let header = response.headers.get_str("set-cookie").expect("a Set-Cookie header");
    let pair = header.split(';').next().expect("cookie pair").trim();
    assert!(pair.starts_with("selfhost_session="), "unexpected cookie: {header}");
    pair.to_owned()
}

async fn password_login(api: &Api) -> String {
    let response = call_with(
        api,
        "POST",
        "/api/session",
        &[("X-Selfhost-Console", "1")],
        &format!(r#"{{"password":"{PASSWORD}"}}"#),
    )
    .await;
    assert_eq!(response.status.code(), 200, "{:?}", body_json(&response).to_text());
    session_cookie_pair(&response)
}

async fn register_passkey(api: &Api, cookie: &str, device: &Authenticator, label: &str) {
    let challenge = call_with(
        api,
        "POST",
        "/api/webauthn/register/challenge",
        &[("Cookie", cookie), ("X-Selfhost-Console", "1")],
        "",
    )
    .await;
    assert_eq!(challenge.status.code(), 200, "{:?}", body_json(&challenge).to_text());
    let challenge =
        body_json(&challenge).get("challenge").and_then(Json::as_str).expect("a challenge").to_owned();
    let registered = call_with(
        api,
        "POST",
        "/api/webauthn/register",
        &[("Cookie", cookie), ("X-Selfhost-Console", "1")],
        &device.register_body(&challenge, label),
    )
    .await;
    assert_eq!(registered.status.code(), 200, "{:?}", body_json(&registered).to_text());
}

async fn passkey_login(api: &Api, device: &Authenticator) -> String {
    let challenge = call_with(
        api,
        "POST",
        "/api/webauthn/login/challenge",
        &[("X-Selfhost-Console", "1")],
        "",
    )
    .await;
    assert_eq!(challenge.status.code(), 200, "{:?}", body_json(&challenge).to_text());
    let challenge =
        body_json(&challenge).get("challenge").and_then(Json::as_str).expect("a challenge").to_owned();
    let reply = call_with(
        api,
        "POST",
        "/api/webauthn/login",
        &[("X-Selfhost-Console", "1")],
        &device.login_body(&challenge),
    )
    .await;
    assert_eq!(reply.status.code(), 200, "{:?}", body_json(&reply).to_text());
    session_cookie_pair(&reply)
}

// ─── The authenticator ────────────────────────────────────────────────────────

fn b64url(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let bits = (chunk[0] as u32) << 16
            | (*chunk.get(1).unwrap_or(&0) as u32) << 8
            | *chunk.get(2).unwrap_or(&0) as u32;
        out.push(B64[(bits >> 18 & 0x3f) as usize] as char);
        out.push(B64[(bits >> 12 & 0x3f) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[(bits >> 6 & 0x3f) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(bits & 0x3f) as usize] as char);
        }
    }
    out
}

/// A stand-in platform authenticator: a real P-256 keypair answering ceremonies
/// for [`RP`] the way a browser's `PublicKeyCredential` would. Each one is a
/// distinct device with a distinct credential id, so "the owner's laptop" and
/// "the newcomer's phone" are genuinely two things.
struct Authenticator {
    keys: ring::signature::EcdsaKeyPair,
    id: String,
}

impl Authenticator {
    fn new() -> Self {
        use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).expect("keypair");
        let keys = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .expect("keypair parses");
        // Distinct per device: two authenticators must never collide in the
        // store, or "the newcomer logged in" and "the owner logged in" become
        // the same lookup.
        let mut id = [0u8; 16];
        ring::rand::SecureRandom::fill(&rng, &mut id).expect("random credential id");
        Self { keys, id: b64url(&id) }
    }

    fn auth_data(flags: u8) -> Vec<u8> {
        let mut out = ring::digest::digest(&ring::digest::SHA256, RP.as_bytes()).as_ref().to_vec();
        out.push(flags);
        out.extend_from_slice(&[0, 0, 0, 1]);
        out
    }

    fn client_data(ceremony: &str, challenge: &str) -> Vec<u8> {
        Json::object([
            ("type", Json::string(ceremony)),
            ("challenge", Json::string(challenge)),
            ("origin", Json::string(format!("https://{RP}"))),
        ])
        .to_text()
        .into_bytes()
    }

    fn register_body(&self, challenge: &str, label: &str) -> String {
        use ring::signature::KeyPair;
        let mut spki = vec![
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
            0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
        ];
        spki.extend_from_slice(self.keys.public_key().as_ref());
        Json::object([
            ("id", Json::string(&self.id)),
            ("algorithm", Json::Number(-7.0)),
            ("publicKey", Json::string(b64url(&spki))),
            (
                "clientDataJSON",
                Json::string(b64url(&Self::client_data("webauthn.create", challenge))),
            ),
            ("authenticatorData", Json::string(b64url(&Self::auth_data(0x45)))),
            ("label", Json::string(label)),
        ])
        .to_text()
    }

    fn login_body(&self, challenge: &str) -> String {
        let client = Self::client_data("webauthn.get", challenge);
        let auth = Self::auth_data(0x05);
        let mut message = auth.clone();
        message.extend_from_slice(ring::digest::digest(&ring::digest::SHA256, &client).as_ref());
        let signature = self
            .keys
            .sign(&ring::rand::SystemRandom::new(), &message)
            .expect("signing with the test key");
        Json::object([
            ("id", Json::string(&self.id)),
            ("clientDataJSON", Json::string(b64url(&client))),
            ("authenticatorData", Json::string(b64url(&auth))),
            ("signature", Json::string(b64url(signature.as_ref()))),
        ])
        .to_text()
    }
}

// ─── Scratch ──────────────────────────────────────────────────────────────────

struct ScratchDir(std::path::PathBuf);

impl ScratchDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!("selfhost-newcomer-{name}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("a scratch directory");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
