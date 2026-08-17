//! The HTTP surface: four routes, one of which is open to the internet — plus, when
//! [`Config::accounts`] is set, the account subsystem's own doors.
//!
//! ```text
//! POST <route>?<service>        file a report        open to anyone, rate limited
//! GET  <route>/health           is the intake up     open, says nothing about content
//! GET  <route>/feed?<service>   every open report    owner token
//! POST <route>/close?<service>  a report is fixed    owner token
//! GET  <route>/projects         which services take reports    open, rate limited
//! ```
//!
//! # The account routes, off unless configured
//!
//! `Config::accounts: Option<AccountsConfig>` is `None` by default, and every route below
//! answers the same `404` an unknown path gets until it is set — the identical shape
//! [`check_token`](Service::check_token) already gives the feed/close routes on a box with no
//! token, so shipping this subsystem changes nothing about a deployment that has not opted in.
//! `crate::accounts`, `crate::sessions`, `crate::webauthn` and `crate::oauth` are each the
//! authority on their own piece; this module only wires their JSON in and out of HTTP and never
//! re-implements a rule any of them already state.
//!
//! ```text
//! POST <route>/register                     email + password           account door
//! POST <route>/login                        email + password           account door
//! POST <route>/logout                       ends the session           page budget
//! GET  <route>/verify?token=…                the page; the JSON redeem only if asked for.
//!                                            The budget follows the answer: a browser's GET
//!                                            is a page visit, a redeeming GET is the account
//!                                            door, because only one of them spends a token
//! POST <route>/verify/confirm                spends the token           account door
//! POST <route>/verify/resend                 session required          account door
//! GET  <route>/me                            whoami                    session, page budget
//! POST <route>/me/password                   sets/replaces a password  session, account door
//! GET  <route>/mine                          this account's reports    session, page budget
//! POST <route>/mine/withdraw                 close one's own report    session, account door
//! POST <route>/passkey/register/start        issues a challenge        account door
//! POST <route>/passkey/register/finish       completes registration    account door
//! POST <route>/passkey/login/start           issues a challenge        account door
//! POST <route>/passkey/login/finish          completes sign-in         account door
//! GET  <route>/oauth/<provider>/start        redirects to the provider account door
//! GET  <route>/oauth/<provider>/callback     completes sign-in; 303s a browser to the page
//! GET  <route>/download                      the source archive        session, page budget
//! GET  <route>/capabilities                  what this box's door offers  open, page budget
//! GET  <route>/                              the register/login page   open, page budget
//! GET  <route>/index.html                    the same page             open, page budget
//! GET  <route>/app.css                       the page's stylesheet     open, page budget
//! GET  <route>/app.js                        the page's script         open, page budget
//! GET  <route>/favicon.svg                   the page's icon           open, page budget
//! ```
//!
//! # No invite code, because nothing here is readable outside the account it belongs to
//!
//! This subsystem never gates itself behind an invite. Registering is open to anyone — nothing
//! a report account can see or do (its own filed reports, its own password, its own passkeys)
//! is visible to anyone but the account itself, so there is nothing an invite would need to
//! protect. Invite-gating is reserved for *direct server access* — the NAS, the VPN, the admin
//! console, the mesh — services built into the box itself, with real roles and grants behind
//! them, owned by `crates/admin`'s own invite door. Confusing the two once already cost a
//! redesign: an earlier draft of this subsystem linked a reports account to a
//! `selfhost_identity::PersonName` and displayed that name's `People::grants_for` back to it,
//! on the theory that "download the source" was a privileged act. It never was — downloading
//! source code is not server access — so that entire wire (`invite.rs`, `Account::linked_person`,
//! the `linkedPerson`/`grants` fields below) was removed rather than kept as an unused option.
//!
//! # The one page this crate serves, and the three files it is made of
//!
//! Every route above is pure JSON — reached by curl or a future client, never a browser
//! address bar. The page routes are the exception: `<route>/`, `<route>/index.html` and (for a
//! browser only) `<route>/verify` answer a
//! static HTML shell ([`Response`]-wrapped [`include_str!`] of `assets/index.html`), and
//! `<route>/app.css`, `<route>/app.js` and `<route>/favicon.svg` answer the three files that
//! shell references, so registering and downloading the application is a link a non-technical
//! human can click rather than an API only a developer could drive. They are open — no session,
//! no token — but they still answer `404` when accounts are off, same as every route they exist
//! to front: a login page has no reason to exist on a deployment with nowhere to log in to.
//!
//! **Open is not unbounded.** These five shipped with no rate limit at all, which contradicts
//! "what an open intake must bound" below by about 87 KB a request on a box with a real public
//! IP — and the `308` a browser gets from the bare `<route>` now points at them. They are
//! metered on their own budget, [`Config::per_page_visitor`], sized for a page load rather than
//! for one API call: see [`Service::page`]. `<route>/health` is the one route with no allowance
//! to spend, because a health check that can be rate-limited is a site that drops out of
//! rotation because somebody else was rude. Every other route on this crate's surface — the
//! `308` a browser gets from the bare `<route>` included, since that is a page load's first
//! request — spends one of the four budgets below. A wrong *method* on a route that is on one
//! of those lists spends that route's allowance too, and so does a `404` under `oauth/`,
//! because the allowance is spent before the method is dispatched — deliberately, so that a
//! wrong method is not a free probe. Only three answers are genuinely free: `<route>/health`,
//! a method refusal on a page file, and a `404` for a suffix this crate has never heard of,
//! all three of which are decided from the request line before anything is read or looked up.
//!
//! # Four budgets, and which one a route belongs on
//!
//! A rate limit is not one number, because the traffic here is not one shape. Four buckets,
//! each sized for its own unit of work, and a route belongs to whichever *frequency* it is
//! called at rather than to whichever module answers it:
//!
//! - **filing** ([`Config::per_source`]) — `POST <route>`. The unit is a written-up report:
//!   three at once, one every twenty seconds. Anonymous and it writes to disk, so it is the
//!   tightest bucket here.
//! - **reading** ([`Config::per_reader`]) — `<route>/feed` and `<route>/close`, the two owner-
//!   token routes and nothing else. The unit is a poll from a subscribed checkout, and the
//!   bucket exists to make *guessing at the token* expensive.
//! - **the account door** ([`AccountsConfig::per_action`]) — every route that checks or issues
//!   a credential: register, login, the verification token, both halves of every passkey
//!   ceremony, the OAuth legs, and the two `POST`s a signed-in person makes that change
//!   security-relevant state, `me/password` and `mine/withdraw`. The unit is an *attempt*, it
//!   is deliberately small (five, then one every twelve seconds), and the reason it is small is
//!   the reason nothing at page-load frequency may share it.
//! - **the page visit** ([`Config::per_page_visitor`]) — the four static files, the `verify`
//!   landing, and the JSON a drawn page calls at page-load frequency: `capabilities`,
//!   `projects`, `me`, `mine`, `download`, `logout`. The unit is *one page load*, which is
//!   eight requests, and every one of them is cheap and repeat-safe.
//!
//! **A page load must cost one coherent budget, or the page degrades instead of being
//! refused.** `capabilities` and `projects` used to sit on the reader's ten-token bucket while
//! the four files they are fetched alongside sat on the page budget's sixty, so the sixth
//! consecutive load from one address got `200`s for the files and `429`s for the two JSON
//! calls — and `assets/app.js` draws that combination as its honest-looking fallback: a box
//! with no passkeys, no OAuth providers and no projects. A visitor cannot tell that from a box
//! that really has none, which makes a half-spent budget strictly worse than a clean refusal.
//! Both now spend the same allowance as the files, so a load is served whole or refused whole.
//!
//! **The six session routes used to spend nothing at all.** `me`, `mine`, `download`,
//! `logout`, `me/password` and `mine/withdraw` appeared in neither the account door's list nor
//! any other, so five hundred requests from one address got five hundred answers — and `me` is
//! the one the page calls on every load, answering `401` to a stranger with no credential at
//! all. That is precisely the unbounded public endpoint "what an open intake must bound" below
//! names as *the* vulnerability. Splitting them across two budgets rather than one is the whole
//! point: a person reloading their own account page must never be able to spend the small
//! bucket that stands in front of sign-in, and a `POST` that rotates a password or closes a
//! report is an attempt at the account door in every sense except which cookie it carries.
//!
//! **The stylesheet and the script are their own routes precisely so the page needs no
//! `'unsafe-inline'`.** An earlier draft inlined both into the shell, which forced
//! that page's policy to allow `script-src 'unsafe-inline'` — and a policy that allows
//! inline script allows *every* inline script, including one an injection put there, which is
//! the whole attack a Content-Security-Policy exists to stop. Splitting the two files out costs
//! two dispatch arms and buys back [`PAGE_POLICY`], which names `'self'` and nothing else. All
//! four are referenced **relatively** by the shell, so they resolve under whatever
//! [`Config::route`] this crate is mounted at, and they are served only from under the trailing
//! slash — which is why a browser asking for the bare `<route>` is redirected to `<route>/`
//! rather than answered there.
//!
//! # Every page a signed-in person can see must live under `<route>/`
//!
//! The session cookie is written with `Path=<route>` ([`crate::sessions::set_cookie_header`]),
//! and a browser attaches a cookie only to requests whose path is under that prefix. So a page
//! served from anywhere else — `/account`, `/verify`, a sibling of `<route>` — is a page the
//! browser reaches *without* the session, which does not read as "signed out" to whoever wrote
//! it: the page loads, `GET <route>/me` from it still works (that request *is* under the
//! prefix), and the mismatch only shows up later as a signed-in person seeing a signed-out view
//! on one route and not another. Widening the cookie's `Path` to `/` is the other way to make
//! that consistent and is the wrong one: this crate is mounted behind a proxy that serves other
//! applications from the same hostname, and a cookie on `/` is a cookie sent to all of them.
//! So the rule is the narrow one — the cookie's path stays `<route>`, and every page this crate
//! will ever serve is a suffix under `<route>/`. `<route>/verify` is where the verification
//! landing lives for exactly that reason, rather than a prettier address off the site root.
//!
//! # No `GET` under `<route>/` changes state
//!
//! Reading is safe to repeat and safe to do on somebody else's behalf; writing is neither, which
//! is why every mutation here is a `POST` that [`Service::cross_origin_post`] and the session
//! cookie's `SameSite=Lax` can both refuse. `GET <route>/verify?token=…` was the one exception
//! and this pass retires it: it redeemed a single-use token on `GET`, so a link checker, a mail
//! scanner, or a corporate gateway that prefetches URLs in incoming mail burned the token before
//! the person it was sent to ever clicked it — and the person then saw "this verification link
//! is invalid or has expired" on their first and only attempt.
//!
//! **The rule is stated as an allow-list, not a deny-list**, because the first attempt at it
//! was a deny-list and did not hold: it served the page to an `Accept` naming `text/html` and
//! redeemed for everything else, which still redeemed for `Accept: */*`, for a request with no
//! `Accept` header at all, and for the `image/…,*/*;q=0.8` a `<img src>` in a mail body makes
//! the reader's own browser send. So: a `GET` of that address **redeems only when the caller
//! explicitly asks for JSON** ([`redeems_on_get`]) and is answered with the landing page in
//! every other case, spending nothing. The page then redeems the token with
//! `POST <route>/verify/confirm`, which a prefetcher does not make. A prefetch of the landing
//! address is now what it should always have been: a page load.
//!
//! # A cross-site POST is refused twice, by two mechanisms that fail differently
//!
//! The session cookie is `SameSite=Lax`, so a browser will not attach it to a POST another
//! site started — that is the first wall, and it lives in [`crate::sessions`]. The second is
//! [`Service::cross_origin_post`]: a browser stamps `Origin` on every POST it makes and cannot
//! be talked out of it, so a POST to `<route>` **or** any path under `<route>/` carrying an
//! `Origin` that is not this box's own configured address is refused `403` before any
//! credential, body or allowance is touched. The check is applied at the top of
//! [`Service::answer`] rather than inside [`Service::accounts_answer`] for exactly that reason:
//! it read as "everything under `<route>/`" while covering only the account doors, leaving the
//! filing route — `POST <route>`, which the page itself posts reports to and which attributes a
//! report to whatever live session the cookie carries — outside a wall the documentation
//! claimed was around it. It runs only on a box with accounts configured, because
//! [`AccountsConfig::public_base_url`] is the address being compared against; a box with no
//! account door has no session cookie for a cross-site POST to ride in the first place.
//! Two walls rather than one because they fail differently — a cookie policy is a rule the
//! browser applies to itself and a future browser bug or a relaxed default silently removes it,
//! whereas the `Origin` check is this process reading a header and deciding. A request with no
//! `Origin` at all is allowed through: that is curl, the CLI and every agent this endpoint was
//! built for, none of which a cross-site attack can drive.
//!
//! # The address is the base, and the service is the query
//!
//! One box holds every service's reports, and which database a call means is the **bare query
//! key** — `…/report?dx` — never a path segment and never `project=`. A path segment would make
//! the proxy's routing prefix depend on the tenant; a named parameter would invite a second
//! spelling of the same thing. A bare word is also the whole of registering a service: the
//! first report filed to `…/report?billing` creates it ([`crate::store`] bounds that door).
//!
//! The reporter's own repository holds the other half of this contract, written from the wire
//! outward: `docs/intake.dx` in the dx workspace. What is stated there is stated here in code
//! and in the tests below, and nowhere else twice.
//!
//! # Where this listens, and what stands in front of it
//!
//! On loopback, always — [`bind`] refuses anything else, exactly as
//! [`selfhost_admin::bind`] does and for the same reason. The public door is the reverse
//! proxy on 443, which terminates TLS and forwards `<route>` here; `docs/SECURITY.md` §3.2
//! (PUB-06) requires an app behind that proxy to set its own security headers, so every
//! response from here carries them.
//!
//! # The client address is the *last* forwarded value, not the first
//!
//! The proxy relays the request's own headers and then appends its own
//! `X-Forwarded-For: <peer>`. A client that sends `X-Forwarded-For: 1.2.3.4` therefore
//! produces two such headers, and the trustworthy one is the last — the one this box wrote.
//! Reading the first would let anyone rotate a header value to get an unlimited rate.
//!
//! # What an open intake must bound, and does
//!
//! The request head and body ([`MAX_BODY`]), the rate per source and in total
//! ([`crate::limit`]), the number of sources remembered, the size and count of stored records
//! ([`crate::store`]), and how often a notification may be sent. A public endpoint that
//! allocates or spends without a bound is the vulnerability, whatever else it gets right.
//!
//! # Nothing here reflects what a stranger sent
//!
//! Answers are JSON built from fixed strings, the report's own fingerprint, and its sighting
//! count. A refusal names the field that was wrong, never the value — so this endpoint cannot
//! be used to serve a payload of somebody else's choosing to somebody else's browser. That
//! holds for the account doors too, which are the ones an actual page renders errors from:
//! [`crate::accounts::AccountError::BadEmail`] carries the *reason* an address did not parse
//! and never the address, for exactly this reason.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use selfhost_http::{BodyLength, Method, ParseError, Request, Response, Status};
use selfhost_json::Json;
use selfhost_mail::OutboundQueue;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::accounts::{self, Account, AccountError, Accounts};
use crate::clock;
use crate::limit::{Decision, Limiter, Meter, Rate};
use crate::notify::{self, Mailbox};
use crate::oauth::{self, OAuthError};
use crate::report::{self, Refusal, Report, project_key};
use crate::sessions::{self, Sessions};
use crate::store::{self, Store, StoreError};
use crate::verify::Verifications;
use crate::webauthn::{self, Webauthn};

/// The largest request body accepted. A report is prose; sixteen kilobytes is a generous
/// essay, and refusing more before reading it is what keeps an anonymous POST from choosing
/// this process's memory use.
pub const MAX_BODY: usize = 16 * 1024;

/// How long a client has to finish sending its request head and body.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);

/// How often undelivered reports are retried into the owner's mailbox.
pub const RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// How many reports one delivery pass will attempt.
const DELIVERY_BATCH: usize = 5;

/// The source archive GitHub serves for any branch of a public repository, no
/// release-engineering required. This is genuinely the only download artifact this project
/// has — see the module documentation on the one page this crate serves — so `<route>/download`
/// hands this address out rather than inventing packaging that does not exist.
const DOWNLOAD_URL: &str = "https://github.com/RockyWearsAHat/selfhost/archive/refs/heads/main.zip";

/// This project's own repository, alongside [`DOWNLOAD_URL`].
const REPOSITORY_URL: &str = "https://github.com/RockyWearsAHat/selfhost";

/// The branch [`DOWNLOAD_URL`] archives — the one `crates/cli/src/self_update.rs`'s own fetch
/// already tracks, and the one this box always builds.
const DOWNLOAD_BRANCH: &str = "main";

/// What running the download actually takes: the same clone-then-build recipe
/// `crates/cli/src/self_update.rs` already runs, stated once so `<route>/download`'s answer and
/// this doc comment can never drift from each other.
const DOWNLOAD_SETUP: &str = "Clone the repository (or unzip the downloaded archive), then run \
     `cargo build --release` from its root.";

/// The page this crate serves and the three files it references, compiled into the binary.
///
/// [`include_str!`] rather than a path read at runtime for the same reason the rest of this
/// crate has no asset directory: a deployment is one binary, and a page that can go missing
/// because a file was not copied is a page that will. They are `&'static str` rather than
/// `&[u8]` because all four are text this repository owns — the compiler refusing a
/// non-UTF-8 byte in one of them is a check, not a limitation.
const LANDING_PAGE: &str = include_str!("../assets/index.html");

/// The stylesheet [`LANDING_PAGE`] references, served at `<route>/app.css`.
const APP_CSS: &str = include_str!("../assets/app.css");

/// The script [`LANDING_PAGE`] references, served at `<route>/app.js`.
const APP_JS: &str = include_str!("../assets/app.js");

/// The icon [`LANDING_PAGE`] references, served at `<route>/favicon.svg`.
const FAVICON_SVG: &str = include_str!("../assets/favicon.svg");

/// How the intake is configured.
#[derive(Debug, Clone)]
pub struct Config {
    /// The path the proxy forwards, without a trailing slash — `/report`.
    pub route: String,
    /// The service a call that names none in its address is about.
    pub default_project: String,
    /// What one source may file.
    pub per_source: Rate,
    /// What everyone together may file.
    pub global: Rate,
    /// What one source may *read* — the two owner-token routes, `<route>/feed` and
    /// `<route>/close`, counted separately so that a checkout syncing on a timer can never
    /// spend the allowance an agent needs to file.
    ///
    /// It is small on purpose, because what it actually stands in front of is *guessing at the
    /// token*. That is why `<route>/capabilities` and `<route>/projects` no longer spend it:
    /// they are page-load-frequency, they are open, and a bucket sized to make a token
    /// expensive to guess is by construction too small to carry a page. They spend
    /// [`Self::per_page_visitor`] now, alongside the files the page fetches them with.
    pub per_reader: Rate,
    /// What *everyone together* may read, the shared half of the reading limiter.
    ///
    /// Separate from [`Self::global`] — which bounds filing — for the reason
    /// [`AccountsConfig::global_action`] spells out at length, hit here a second time and
    /// missed. Reading used to share filing's bucket: twenty tokens refilling at one a second,
    /// sized for a box that takes a few reports a minute. Then `<route>/capabilities` and
    /// `<route>/projects` joined it, and those are called by the page on *every load*, by every
    /// visitor. Twelve strangers opening the login page once each therefore emptied the bucket
    /// and the owner's own token-gated `<route>/feed` answered `429` — a public page turning
    /// into a denial of service against the one person who is supposed to be able to read.
    /// A per-source rate is the wall against one client looping; this one is the wall against
    /// many clients each behaving.
    ///
    /// Those two open reads have since moved off this limiter entirely and onto
    /// [`Self::global_pages`], which is the same fix taken one step further: the page's traffic
    /// is now bounded by the page's own bucket rather than by a widened version of the owner's.
    /// This one stays wide anyway — it costs nothing to leave headroom in front of two token
    /// routes, and narrowing it back to the reader's own rate would re-create the coupling by
    /// hand the first time another open read is added here in a hurry.
    pub global_reading: Rate,
    /// What one visitor may spend on *page loads* — the static files (`<route>/`, `index.html`,
    /// `app.css`, `app.js`, `favicon.svg`), the `<route>/verify` landing, and the JSON a drawn
    /// page calls at that same frequency: `capabilities`, `projects`, `me`, `mine`, `download`
    /// and `logout`.
    ///
    /// The files shipped unmetered, on a box with a real public IP, carrying about 87 KB
    /// between them — which is exactly what this crate's own module documentation calls the
    /// vulnerability ("a public endpoint that allocates or spends without a bound"), and the
    /// `308` from the bare `<route>` now actively steers browsers at them. They are metered on
    /// their own budget rather than on [`Self::per_reader`] because the unit here is a *page
    /// load* rather than an API call.
    ///
    /// **The unit is the whole load, so everything the load asks for is on it.** A real visit
    /// is eight requests — the `308` off the bare route, the four files, then `capabilities`,
    /// `me` and (when the filing form draws) `projects` — and the first draft budgeted only the
    /// four files here, leaving the JSON on a reader's allowance of ten. The sixth consecutive
    /// load from one address inside two minutes therefore served every file and refused both
    /// JSON calls, which `assets/app.js` renders as a working page with no capabilities and no
    /// projects. Half a budget buys a lie; a whole one buys either a page or a `429`.
    ///
    /// A signed-in person's own reads sit here for the same reason and one more: they are
    /// page-frequency too (`me` on every load, `mine` whenever the list redraws), and the only
    /// other bucket they could plausibly go on is [`AccountsConfig::per_action`], which is five
    /// tokens deep because it stands in front of sign-in. Letting a reload spend that is letting
    /// a person lock themselves out of their own door by pressing refresh.
    ///
    /// Everything on this budget is cheap and repeat-safe: the files answer `304` to a revisit
    /// ([`page_response`]), and the JSON calls are small fixed answers about one session. So the
    /// burst can be generous without the bytes being.
    pub per_page_visitor: Rate,
    /// What everyone together may fetch of that same page, the shared half of the page limiter
    /// — the wall against many visitors each staying inside [`Self::per_page_visitor`].
    pub global_pages: Rate,
    /// Where notifications go, when the box has a mailbox for them.
    pub mail: Option<Mailbox>,
    /// How often a notification may be sent, however many reports arrive.
    pub mail_rate: Rate,
    /// The owner's bearer token for the reading routes. Without one they do not exist.
    pub token: Option<String>,
    /// The account subsystem — registration, sessions, passkeys, OAuth sign-in. `None` (the
    /// default) means every route under it answers `404`, exactly like a box with no
    /// [`Self::token`]: shipping this code changes nothing about a deployment that has not
    /// opted in.
    pub accounts: Option<AccountsConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            route: "/report".to_string(),
            default_project: "dx".to_string(),
            // Three at once, then one every twenty seconds: an agent writing up two related
            // reports is never refused, and a loop gets nowhere.
            per_source: Rate::new(3, 3.0),
            // The whole box: a burst of twenty, then one a second sustained.
            global: Rate::new(20, 60.0),
            // Reading is cheap and a subscribed checkout does it on a timer, so the burst is
            // larger; it exists to make guessing at the token expensive, not to ration syncs.
            per_reader: Rate::new(10, 30.0),
            // Two hundred at once, then two a second, sized like `global_action` and for the
            // same reason: the open reads are page-load-frequency now, and a shared bucket the
            // size of one visitor's is a `429` anybody can hand the owner with a browser tab.
            global_reading: Rate::new(200, 120.0),
            // A page load is eight requests, not the six the first draft counted, and this
            // budget now also carries a signed-in person's own reads. A hundred and twenty at
            // once is fifteen loads back to back — several tabs, a hard refresh, and a few
            // actions on top — then four a second sustained. Wide on purpose: everything on it
            // answers `304` or a small fixed JSON, and the thing this wall exists to stop is a
            // loop pulling 87 KB, not a person using the page.
            per_page_visitor: Rate::new(120, 240.0),
            // And everyone's together: seventy-five concurrent first-time page loads, then ten
            // a second. Wide, because a revisit is a `304` and this is a login page, and still a
            // ceiling rather than no ceiling at all.
            global_pages: Rate::new(600, 600.0),
            mail: None,
            // At most one message a minute, so a flood is a database problem, not an inbox one.
            mail_rate: Rate::new(3, 1.0),
            token: None,
            accounts: None,
        }
    }
}

/// How the account subsystem is configured. Constructing one and setting it on [`Config`] is
/// the whole of turning the door on.
#[derive(Debug, Clone)]
pub struct AccountsConfig {
    /// Where `accounts.json`, `sessions.json`, `passkeys.json` and `verify.json` live.
    ///
    /// Deliberately **not** [`crate::store::Store`]'s own directory: a project key may contain
    /// dots and this box lets a stranger bring a project into existence by naming it, so a
    /// fixed filename inside that directory is a name a project key could someday collide with.
    /// A sibling directory makes the collision structurally impossible rather than merely
    /// unlikely.
    pub data_dir: PathBuf,
    /// The name shown in a verification email and nowhere else load-bearing.
    pub site_name: String,
    /// This box's own public address with no trailing slash — `https://rockywearsahat.com` —
    /// used to build the verification link and the OAuth `redirect_uri`. Both must be absolute:
    /// a provider is configured with an exact redirect address and refuses anything else.
    pub public_base_url: String,
    /// The WebAuthn relying party id — this box's own hostname. `None` disables the passkey
    /// routes (they answer the same `404` as an unconfigured token route) while leaving
    /// password and OAuth sign-in unaffected.
    pub rp_id: Option<String>,
    /// Every configured "sign in with…" provider, keyed by [`oauth::Provider::name`] in the
    /// route. Empty means no OAuth route exists.
    pub oauth_providers: Vec<oauth::Provider>,
    /// The `From` address on a verification email — must be a domain this box can send as.
    pub verify_from: String,
    /// The HELO name this box announces when spooling a verification email.
    pub verify_helo: String,
    /// The daemon's own data directory, so a verification email can be spooled into
    /// `<mail_data_dir>/mail/queue` for the daemon's outbound sweep to actually send. `None`
    /// means accounts still work but no verification email is ever sent — the same degraded-but-
    /// working shape [`Config::mail`] being `None` gives report notifications.
    pub mail_data_dir: Option<PathBuf>,
    /// What one source may attempt of register/login/passkey/OAuth-start in total — counted
    /// separately from [`Config::per_source`] and [`Config::per_reader`] so a credential-
    /// stuffing attempt against this door can never spend a filer's or a reader's allowance,
    /// and cannot itself be starved by one either.
    pub per_action: Rate,
    /// What *everyone together* may attempt at the account door, the same way [`Config::global`]
    /// bounds everyone's filing.
    ///
    /// Separate from [`Self::per_action`] and necessarily much wider. An earlier draft built the
    /// limiter as `Limiter::new(per_action, per_action)`, which made the shared bucket exactly
    /// one visitor's worth: two people signing in at once spent it, and the third — and everyone
    /// after — got `429` from a box that was doing nothing. A per-source rate is a wall against
    /// one agent looping; a global rate is a wall against a thousand of them each staying inside
    /// that wall, and sizing the second like the first turns a rate limiter into a denial of
    /// service anybody can trigger with a browser tab.
    pub global_action: Rate,
}

/// The account subsystem's live state — every store [`AccountsConfig`] describes, opened once
/// and shared for the life of the [`Service`].
struct AccountsRuntime {
    config: AccountsConfig,
    accounts: Accounts,
    sessions: Sessions,
    webauthn: Option<Webauthn>,
    oauth_providers: std::collections::HashMap<String, oauth::Provider>,
    oauth_pending: oauth::Pending,
    // Built once at startup; a `rustls` configuration failure is exceedingly unlikely (it does
    // not touch the network) but is not a reason to make `Service::new` fallible when every
    // other store here already fails closed on its own — the OAuth routes report it themselves
    // instead, once, the first time they are reached.
    oauth_client: Result<oauth::HttpsClient, String>,
    verify: Verifications,
    mail_queue: Option<OutboundQueue>,
    limiter: Mutex<Limiter>,
}

impl AccountsRuntime {
    fn open(config: AccountsConfig) -> Self {
        let accounts = Accounts::load(&config.data_dir);
        let sessions = Sessions::load(&config.data_dir);
        // The ceremony origin is derived from this deployment's own `public_base_url` rather
        // than taken as a second configuration value, and rather than rebuilt out of the
        // relying party id. Not a knob, because two knobs for one fact is how they come to
        // disagree — and because the rebuilt form (`https://<rp_id>`) drops the port, which
        // shut the passkey door on every deployment not served on 443. See
        // [`crate::webauthn::Webauthn`].
        //
        // A `public_base_url` this crate cannot read an origin out of leaves the passkey
        // routes off rather than on-and-unopenable: `crates/cli` refuses such a value at
        // startup, so reaching this arm means the service was built by something other than
        // the CLI, and the honest answer there is the `404` a box with no `rp_id` already
        // gives — not a door whose every ceremony fails identically to a forged one.
        let webauthn = match (
            config.rp_id.as_deref(),
            origin_of(&config.public_base_url).as_deref(),
        ) {
            (Some(rp_id), Some(origin)) => Some(Webauthn::load(rp_id, origin, &config.data_dir)),
            (Some(_), None) => {
                eprintln!(
                    "[{}] reports: --public-base-url {} is not an absolute address, so no \
                     passkey ceremony could ever be verified against it — the passkey routes \
                     stay off",
                    selfhost_mail::stamp(),
                    config.public_base_url
                );
                None
            }
            (None, _) => None,
        };
        let oauth_providers = config
            .oauth_providers
            .iter()
            .cloned()
            .map(|provider| (provider.name.clone(), provider))
            .collect();
        let verify = Verifications::load(&config.data_dir);
        let mail_queue = config
            .mail_data_dir
            .as_deref()
            .and_then(|dir| match OutboundQueue::open(dir) {
                Ok(queue) => Some(queue),
                Err(error) => {
                    eprintln!(
                        "[{}] reports: could not open the outbound mail queue at {}: {error} — \
                         verification email is disabled",
                        selfhost_mail::stamp(),
                        dir.display()
                    );
                    None
                }
            });
        let limiter = Mutex::new(Limiter::new(config.per_action, config.global_action));
        Self {
            oauth_client: oauth::HttpsClient::new().map_err(|error| error.to_string()),
            config,
            accounts,
            sessions,
            webauthn,
            oauth_providers,
            oauth_pending: oauth::Pending::new(),
            verify,
            mail_queue,
            limiter,
        }
    }
}

// Deliberately not a derived `Debug`: `oauth_client` and `mail_queue` do not implement it, and
// even if they did, an account list or a session table in a log line is a target list — the
// same reasoning every credential store in this crate and `crates/admin` gives its own `Debug`.
impl std::fmt::Debug for AccountsRuntime {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "AccountsRuntime {{ accounts: {:?}, sessions: {:?}, webauthn: {}, oauth_providers: {}, verify: {:?} }}",
            self.accounts,
            self.sessions,
            if self.webauthn.is_some() {
                "configured"
            } else {
                "disabled"
            },
            self.oauth_providers.len(),
            self.verify,
        )
    }
}

/// The intake, as one shareable value.
#[derive(Debug)]
pub struct Service {
    store: Store,
    config: Config,
    filing: Mutex<Limiter>,
    reading: Mutex<Limiter>,
    /// The page visit's own budget: the static files *and* the JSON a drawn page calls at the
    /// same frequency. See [`Config::per_page_visitor`] for why it is not the reading one, and
    /// why a page load has to come out of a single bucket.
    pages: Mutex<Limiter>,
    mail_meter: Mutex<Meter>,
    accounts: Option<AccountsRuntime>,
}

impl Service {
    /// An intake over `store`, configured by `config`.
    #[must_use]
    pub fn new(store: Store, config: Config) -> Self {
        let filing = Mutex::new(Limiter::new(config.per_source, config.global));
        // Deliberately `global_reading` and not `global`: sharing filing's bucket made the open
        // page's own calls able to close the owner's feed. See [`Config::global_reading`].
        let reading = Mutex::new(Limiter::new(config.per_reader, config.global_reading));
        let pages = Mutex::new(Limiter::new(config.per_page_visitor, config.global_pages));
        let mail_meter = Mutex::new(Meter::new(config.mail_rate));
        let accounts = config.accounts.clone().map(AccountsRuntime::open);
        Self {
            store,
            config,
            filing,
            reading,
            pages,
            mail_meter,
            accounts,
        }
    }

    /// The configuration this intake runs with.
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// The database behind it.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Answers one request from `client`, at `now` on the monotonic clock and `wall` on the
    /// calendar.
    ///
    /// The surface [`serve`] actually calls. Every route but one is synchronous — see
    /// [`Self::answer`] — and this is a thin wrapper that awaits only that one:
    /// `<route>/oauth/<provider>/callback`, which cannot answer without trading the
    /// provider's authorization code for a token over the network. Every other path, including
    /// a callback for an unconfigured or unknown provider, is handled by [`Self::answer`]
    /// unchanged — so a box with accounts turned off pays nothing extra reaching this function
    /// on every request, and every already-proven synchronous route stays exactly as tested.
    pub async fn answer_async(
        &self,
        request: &Request,
        body: &[u8],
        client: &str,
        now: Instant,
        wall: SystemTime,
    ) -> Response {
        if let Some(runtime) = &self.accounts {
            let (path, query) = split_target(&request.target);
            let route = self.config.route.as_str();
            if let Some(provider_name) = path
                .strip_prefix(&format!("{route}/oauth/"))
                .and_then(|rest| rest.strip_suffix("/callback"))
            {
                if request.method != Method::Get {
                    return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET");
                }
                if let Decision::Refuse(seconds) = self.admit(&runtime.limiter, client, now) {
                    return retry_after(seconds);
                }
                return self
                    .oauth_callback(runtime, provider_name, query, request)
                    .await;
            }
        }
        self.answer(request, body, client, now, wall)
    }

    /// Answers one request from `client`, at `now` on the monotonic clock and `wall` on the
    /// calendar.
    ///
    /// Both clocks are parameters so the whole surface is testable without sleeping and
    /// without a stamp that changes between runs. Nothing in here awaits: a report is stored
    /// and answered, and the mail it produces is delivered by [`deliver_pending`] afterwards,
    /// so a slow SMTP server can never hold a reporter's connection open. The one route that
    /// must await network I/O — the OAuth callback — is therefore not reachable through this
    /// function at all; see [`Self::answer_async`].
    pub fn answer(
        &self,
        request: &Request,
        body: &[u8],
        client: &str,
        now: Instant,
        wall: SystemTime,
    ) -> Response {
        let (path, query) = split_target(&request.target);
        let route = self.config.route.as_str();

        // The `Origin` wall, in front of *every* `POST` this service answers rather than only
        // the account doors. It used to sit at the top of [`Self::accounts_answer`], which
        // reads as "everything under `<route>/`" but is not: `<route>` itself — the filing
        // route, the one the page actually posts reports to, and the one that attributes a
        // report to whatever live session the cookie carries — is dispatched below and never
        // reached it, and neither did `<route>/close`. So the module documentation's claim was
        // wider than the code, and the gap was on the route where a session is spent. Hoisting
        // it here closes both and keeps the ordering the check needs: before the allowance, so
        // that a POST forged by another site cannot spend the *victim's* budget.
        //
        // Only when accounts are configured, because the value compared against is the account
        // subsystem's own `public_base_url` — a box with no account door has no configured
        // address, no session cookie to ride, and nothing a cross-site POST could reach.
        // Only for this crate's own paths, so an unrelated address still answers `404` rather
        // than telling a stranger which prefix this process cares about.
        if let Some(runtime) = &self.accounts {
            if path == route || path.starts_with(&format!("{route}/")) {
                if let Some(refusal) = self.cross_origin_post(runtime, request) {
                    return refusal;
                }
            }
        }

        if path == route {
            // A person who typed this box's report address into an address bar gets sent to
            // the page rather than a refusal they cannot act on. Only a browser: the test is
            // an `Accept` that names `text/html` ([`wants_html`]), so curl, the CLI and every
            // agent keep the exact `405` and the exact sentence they have always had — nothing
            // that already speaks to this endpoint has to learn to follow a redirect.
            //
            // Only when there is somewhere to land, too. With accounts off, `<route>/` is a
            // `404`, and sending a human from an answer that says what to do to one that says
            // nothing is worse than the refusal it replaced.
            if request.method == Method::Get && self.accounts.is_some() && wants_html(request) {
                // On the page budget, because this *is* the first request of a page load — the
                // browser follows it straight into the four files and the three JSON calls that
                // all spend the same bucket. Leaving it free would have left one more answered
                // route with no allowance to spend, which is the claim the module documentation
                // makes about `<route>/health` alone.
                if let Some(refusal) = self.page_visit(client, now) {
                    return refusal;
                }
                return permanent_redirect(&format!("{route}/"));
            }
            return match request.method {
                Method::Post => self.file(request, body, query, client, now, wall),
                Method::Options => refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes POST"),
                _ => refuse(Status::METHOD_NOT_ALLOWED, "file a report with POST"),
            };
        }
        if path == format!("{route}/health") {
            // The one route with no allowance to spend — and, since the six session routes
            // under `<route>/` were given budgets, that sentence is true again. It is what the
            // proxy's health check calls on its own timer, and a health check that can be
            // rate-limited is a site that drops out of rotation because somebody else was rude.
            return self.health(request);
        }
        // Everything else costs an allowance *before* the token is looked at, so a stranger
        // cannot try tokens at line speed. A subscribed checkout syncs every few minutes and
        // never comes near the burst.
        if path == format!("{route}/feed") || path == format!("{route}/close") {
            if let Decision::Refuse(seconds) = self.admit(&self.reading, client, now) {
                return retry_after(seconds);
            }
            return if path.ends_with("/feed") {
                self.feed(request, query)
            } else {
                self.close(request, query, body)
            };
        }
        if path == format!("{route}/projects") {
            // The page budget, not the reader's. This is one of the three JSON calls
            // `assets/app.js` makes while drawing — it fills the filing form's project picker —
            // so it arrives once per load from every visitor, and a reader's ten tokens are
            // spent by the fifth. The page then drew an empty picker while its own files kept
            // serving, which reads as "this box has no projects" rather than as a limit. Same
            // bucket as the files it is fetched with; see [`Config::per_page_visitor`].
            if let Some(refusal) = self.page_visit(client, now) {
                return refusal;
            }
            return self.projects(request);
        }
        if let Some(suffix) = path.strip_prefix(&format!("{route}/")) {
            if let Some(runtime) = &self.accounts {
                return self
                    .accounts_answer(runtime, suffix, query, request, body, client, now, wall);
            }
        }
        refuse(Status::NOT_FOUND, "no such endpoint")
    }

    /// `POST <route>?<service>` — the one open door.
    ///
    /// Attributed to a signed-in account when the request carries a live session — additive
    /// only: a request with no cookie, an expired one, or accounts turned off entirely files
    /// exactly as it always has.
    fn file(
        &self,
        request: &Request,
        body: &[u8],
        query: &str,
        client: &str,
        now: Instant,
        wall: SystemTime,
    ) -> Response {
        if let Decision::Refuse(seconds) = self.admit(&self.filing, client, now) {
            return retry_after(seconds);
        }
        let Ok(text) = std::str::from_utf8(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not UTF-8 JSON");
        };
        let Ok(value) = selfhost_json::parse(text) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let service = match self.service_of(query, Some(&value)) {
            Ok(service) => service,
            Err(refusal) => return refuse(Status::BAD_REQUEST, refusal.message()),
        };
        let mut report = match Report::parse(
            &value,
            &service,
            clock::iso8601(wall),
            crate::report::source_hash(client),
        ) {
            Ok(report) => report,
            Err(refusal) => return refuse(Status::BAD_REQUEST, refusal.message()),
        };
        let account = self
            .accounts
            .as_ref()
            .and_then(|runtime| self.caller(runtime, request));
        report.account_id = account.as_ref().map(|account| account.id.clone());

        match self.store.record(&report) {
            Ok(recorded) => {
                if recorded.fresh {
                    if let Some(account) = &account {
                        if let Some(runtime) = &self.accounts {
                            if let Err(error) = runtime.accounts.record_filed(
                                &account.id,
                                &recorded.entry.project,
                                &recorded.entry.id,
                            ) {
                                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                            }
                        }
                    }
                }
                answer(
                    Status::OK,
                    Json::object([
                        ("filed", Json::string(&recorded.entry.id)),
                        ("project", Json::string(&recorded.entry.project)),
                        ("sightings", Json::Number(recorded.entry.sightings as f64)),
                        ("known", Json::Bool(!recorded.fresh)),
                    ]),
                )
            }
            Err(StoreError::NoProject(message)) => refuse(Status::NOT_FOUND, &message),
            Err(StoreError::Full(message)) => refuse(Status::SERVICE_UNAVAILABLE, &message),
            Err(error) => {
                // The reporter is told the truth without being told this box's paths.
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "the report could not be stored",
                )
            }
        }
    }

    /// `GET <route>/projects` — the services this box currently accepts reports about, so a
    /// dashboard can offer a filer a choice rather than a blank field. Names only: no count, no
    /// content — [`Self::health`] already exposes a total count and nothing has ever exposed
    /// which services exist by name, so this is a deliberate, narrow widening of that, not an
    /// accident of implementation.
    fn projects(&self, request: &Request) -> Response {
        if request.method != Method::Get {
            return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET");
        }
        match self.store.projects() {
            Ok(keys) => answer(
                Status::OK,
                Json::object([("projects", Json::array(keys.into_iter().map(Json::string)))]),
            ),
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "the project list could not be read",
                )
            }
        }
    }

    /// The account a request's session cookie names, if any — live, not expired, found. Used
    /// only to *attribute* a filing; its absence is never a refusal.
    fn caller(&self, runtime: &AccountsRuntime, request: &Request) -> Option<Account> {
        let presented = sessions::cookie_value(request.headers.get_str("cookie"));
        let account_id = runtime.sessions.account_of(presented.as_deref()?)?;
        runtime.accounts.find_by_id(&account_id)
    }

    /// The refusal a cross-site `POST` under `<route>/` gets, or `None` for a request that may
    /// proceed. See the module documentation's "a cross-site POST is refused twice".
    ///
    /// A browser attaches `Origin` to every `POST` it makes, whatever the page that made it,
    /// and no page can suppress or forge it. So an `Origin` that is not this box's own
    /// [`AccountsConfig::public_base_url`] is a submission from another site, and is refused
    /// before the body is read, the allowance is spent, or a credential is looked at.
    ///
    /// A request carrying **no** `Origin` is allowed, deliberately. That is curl, `selfhost
    /// report`, and every agent this endpoint was built for — refusing them would refuse the
    /// majority of this crate's traffic to close a hole only a browser can be walked into. It
    /// also keeps this check strictly subtractive: it can refuse a request the session cookie
    /// would have accepted, and it can never accept one the cookie would have refused, which is
    /// the only correct shape for a second wall.
    ///
    /// A box whose configured base URL is not an absolute address has no origin to compare
    /// against, and a request that *did* send an `Origin` is refused rather than waved through —
    /// the misconfiguration is the CLI's to refuse at startup (`check_public_base_url`), and
    /// failing open here would make this wall disappear silently on exactly the deployment
    /// that got its own address wrong.
    fn cross_origin_post(&self, runtime: &AccountsRuntime, request: &Request) -> Option<Response> {
        if request.method != Method::Post {
            return None;
        }
        let sent = request.headers.get_str("origin")?;
        let ours = origin_of(&runtime.config.public_base_url);
        if ours.is_some_and(|ours| sent.eq_ignore_ascii_case(&ours)) {
            return None;
        }
        Some(refuse(
            Status::FORBIDDEN,
            "this request came from another site",
        ))
    }

    /// One of the compiled-in page files, metered on the page budget.
    ///
    /// The five page routes shipped with no bound at all, on a box with a real public IP,
    /// carrying about 87 KB between them — and the `308` a browser now gets from the bare
    /// `<route>` steers traffic straight at them. This crate's own module documentation names
    /// that shape as the vulnerability: "a public endpoint that allocates or spends without a
    /// bound is the vulnerability, whatever else it gets right." So they have one.
    ///
    /// [`Config::per_page_visitor`] rather than [`Config::per_reader`] because the unit here is
    /// a page load, not a read — see that field for the arithmetic. The bound is deliberately
    /// generous, and it can afford to be: [`page_response`] answers `304` to anything that
    /// already has the bytes, so a repeat visitor costs a comparison and an empty body, and
    /// what this wall exists to stop is somebody pulling the full 87 KB in a loop.
    fn page(
        &self,
        request: &Request,
        client: &str,
        now: Instant,
        content_type: &str,
        body: &'static str,
    ) -> Response {
        if let Some(refusal) = self.page_visit(client, now) {
            return refusal;
        }
        page_response(request, content_type, body.as_bytes())
    }

    /// Spends one page-visit allowance, answering `Some(429)` when there is none left.
    ///
    /// Split out of [`Self::page`] because the budget is a *page load*, and a page load is not
    /// only the files: `assets/app.js` calls `capabilities`, `me` and `projects` on boot, and a
    /// signed-in person's `mine`, `download` and `logout` arrive at the same frequency from the
    /// same browser. Those answer JSON rather than a static file, so they cannot go through
    /// [`Self::page`] — but they must come out of the same bucket, or a load is half-refused.
    /// See [`Config::per_page_visitor`] for why that is worse than being refused outright.
    fn page_visit(&self, client: &str, now: Instant) -> Option<Response> {
        match self.admit(&self.pages, client, now) {
            Decision::Refuse(seconds) => Some(retry_after(seconds)),
            Decision::Admit => None,
        }
    }

    /// `GET <route>/capabilities` — which doors this particular box actually has, so the page
    /// can draw the buttons that work and none of the ones that do not.
    ///
    /// Open and session-free, because the page needs it *before* it has drawn anything and
    /// before anyone could have signed in. It says only what the deployment's own configuration
    /// already answers to anyone who presses a button and reads the status: whether
    /// [`AccountsConfig::rp_id`] was set (so passkeys exist), which providers are named, whether
    /// mail can be spooled (so "resend the link" is worth offering), and the bounds the fields
    /// are checked against. Never anything about who is registered, what they filed, or how
    /// many of them there are.
    ///
    /// Every bound below is read from the constant that actually enforces it — `MIN_PASSWORD`
    /// from [`crate::accounts`], `MAX_TITLE` from [`crate::report`], and so on — rather than
    /// restated here. A page that tells a person "at least 8 characters" while the door refuses
    /// at 10 is worse than a page that says nothing, and a second copy of a number is how that
    /// happens.
    ///
    /// With accounts off this route answers `404` like every other route below `<route>/`,
    /// which is not a gap: the page reads `capabilities` and `me` both answering `404` as "this
    /// box has no account door" and draws that, so the `404` *is* the answer.
    fn capabilities(&self, runtime: &AccountsRuntime) -> Response {
        // A hash map's iteration order is not an order. These are rendered as a row of sign-in
        // buttons, and buttons that swap places between two page loads are a bug somebody
        // eventually reports.
        let mut providers: Vec<&str> = runtime.oauth_providers.keys().map(String::as_str).collect();
        providers.sort_unstable();
        answer(
            Status::OK,
            Json::object([
                ("accounts", Json::Bool(true)),
                ("passkeys", Json::Bool(runtime.webauthn.is_some())),
                (
                    "oauthProviders",
                    Json::array(providers.into_iter().map(Json::string)),
                ),
                ("mailConfigured", Json::Bool(runtime.mail_queue.is_some())),
                ("route", Json::string(&self.config.route)),
                (
                    "limits",
                    Json::object([
                        ("passwordMin", Json::Number(accounts::MIN_PASSWORD as f64)),
                        ("passwordMax", Json::Number(accounts::MAX_PASSWORD as f64)),
                        ("titleMax", Json::Number(report::MAX_TITLE as f64)),
                        ("detailMax", Json::Number(report::MAX_DETAIL as f64)),
                        ("reproMax", Json::Number(report::MAX_REPRO as f64)),
                        (
                            "passkeysPerAccount",
                            Json::Number(webauthn::MAX_PASSKEYS_PER_ACCOUNT as f64),
                        ),
                        ("maxAccounts", Json::Number(accounts::MAX_ACCOUNTS as f64)),
                        ("maxProjects", Json::Number(store::MAX_PROJECTS as f64)),
                    ]),
                ),
            ]),
        )
    }

    /// Dispatches every route under `<route>/` once accounts are configured — everything
    /// [`Self::answer`] itself does not already own (`health`, `feed`, `close`, `projects`).
    ///
    /// `suffix` is the path with `<route>/` already stripped, so `"register"` here is
    /// `<route>/register` to a caller. The one route this never answers is
    /// `oauth/<provider>/callback` — it needs to await a network exchange, and `answer` is
    /// synchronous; [`Self::answer_async`] intercepts that one path before ever reaching here.
    ///
    /// # Four lists, and adding a route means touching all four
    ///
    /// A suffix appears in **one** of the two rate-limit `matches!` below — the account door's
    /// or the page visit's, and which one is the design decision, not a formality — in the arm
    /// that answers it, and in one of the two method-refusal groups after them. Appearing in
    /// neither budget list is how six routes came to spend nothing at all; see the module
    /// documentation's "Four budgets". Miss the method-refusal group and the route exists
    /// for `GET` but falls through to `404 "no such endpoint"` for every other method — which
    /// is the sentence this crate uses for *accounts are turned off*, so a client cannot tell a
    /// wrong method from a box with no account door at all.
    /// `every_new_page_route_answers_a_method_refusal_rather_than_a_misleading_404` walks every
    /// route added since the page was split into files across four methods for exactly that.
    #[allow(clippy::too_many_arguments)]
    fn accounts_answer(
        &self,
        runtime: &AccountsRuntime,
        suffix: &str,
        query: &str,
        request: &Request,
        body: &[u8],
        client: &str,
        now: Instant,
        wall: SystemTime,
    ) -> Response {
        // The `Origin` wall used to stand here; it now stands at the top of [`Self::answer`],
        // in front of every `POST` this service answers rather than only the ones below — see
        // the comment there. It still runs before any allowance is spent, which is the ordering
        // it needs: a cross-site POST is counted against the *victim's* address, because it is
        // the victim's browser that sends it, and spending their budget on a request forged by
        // somebody else would let a third-party page rate-limit a person out of their own
        // account door.

        // The verification landing page, before the account door's limiter rather than behind
        // it. Serving a compiled-in static file is not a credential attempt and should not cost
        // one: `per_action` is five in production, and a corporate gateway that prefetches a
        // link plus the human behind the same egress address share one bucket, so metering the
        // *page* meant the human's first click could answer `429` instead of the page the mail
        // promised them. It is metered on the page budget instead — a page load is what it is —
        // and the redeem that follows it, `POST <route>/verify/confirm`, keeps the account
        // door's meter, because spending a single-use credential is what deserves one. Which of
        // the two answers a `GET` here gets is [`redeems_on_get`]'s decision, made once.
        if suffix == "verify" && request.method == Method::Get && !redeems_on_get(request) {
            return self.page(
                request,
                client,
                now,
                "text/html; charset=utf-8",
                LANDING_PAGE,
            );
        }

        // Every account-door attempt spends this allowance before anything else runs, so a
        // credential-stuffing run against `login` can never spend the allowance an ordinary
        // filer or a subscribed checkout needs — the same separation `filing`/`reading` already
        // give each other.
        //
        // The two `finish` routes are on this list because they are the half of a ceremony that
        // actually verifies something: a `start` is a challenge this box hands out, a `finish`
        // is a signature this box checks, and the checking is where the cost is. Leaving them
        // unmetered meant the expensive half of the passkey door was the free one.
        // `verify` and `verify/confirm` are on it because a verification token is a credential
        // like any other, and guessing at one is the same act as guessing at a password.
        //
        // `me/password` and `mine/withdraw` are on it because a session cookie does not stop
        // something being an attempt at the account door. One replaces the credential every
        // other door on this list checks — and signs every other session out doing it — and the
        // other destroys a record. Both are `POST`s a person makes a handful of times ever, so
        // five-then-one-every-twelve-seconds costs a real user nothing, while an agent that has
        // got hold of a cookie is bounded on exactly the bucket that already bounds an agent
        // trying to get hold of one. They spent nothing at all before this pass.
        if matches!(
            suffix,
            "register"
                | "login"
                | "verify"
                | "verify/confirm"
                | "verify/resend"
                | "me/password"
                | "mine/withdraw"
                | "passkey/register/start"
                | "passkey/register/finish"
                | "passkey/login/start"
                | "passkey/login/finish"
        ) || suffix.starts_with("oauth/")
        {
            if let Decision::Refuse(seconds) = self.admit(&runtime.limiter, client, now) {
                return retry_after(seconds);
            }
        }

        // The page-visit budget, for the routes a drawn page calls at page-load frequency. The
        // static files below spend it inside [`Self::page`]; these five answer JSON, so they
        // spend it here, before the method is dispatched — the same ordering the account door
        // above uses, so a wrong method costs an allowance rather than being a free probe.
        //
        // Why not the account door for these: `me` is the first call the page makes on every
        // load and `mine` is the second whenever the report list redraws, so counting them
        // against a five-token credential bucket would mean a person who refreshes twice cannot
        // then sign in — the exact failure the `capabilities` arm below was already written to
        // avoid, generalised. `download` hands back a fixed URL and a sentence; it is a read.
        //
        // Why `logout` is here rather than on the account door, despite being a state-changing
        // `POST`: it is the one refusal on this surface that leaves the box *less* safe than
        // admitting would have. A `429` on sign-out is a live session left behind on a machine
        // whose user has already walked away, and a stranger cannot use this route as a lever
        // anyway — with no live cookie it destroys nothing. So it gets a bound, because
        // unbounded is not an option, but it gets the widest one available.
        //
        // All five answered five hundred requests from one address before this pass, spending
        // nothing; `me` did it while replying `401` to a caller holding no credential at all.
        if matches!(suffix, "me" | "mine" | "download" | "logout" | "capabilities") {
            if let Some(refusal) = self.page_visit(client, now) {
                return refusal;
            }
        }

        match suffix {
            "register" if request.method == Method::Post => {
                self.register_password(runtime, body, wall)
            }
            "login" if request.method == Method::Post => self.login_password(runtime, body),
            "logout" if request.method == Method::Post => self.logout(runtime, request),
            "verify" if request.method == Method::Get => self.verify_email(runtime, query),
            "verify/confirm" if request.method == Method::Post => {
                self.verify_confirm(runtime, body)
            }
            "verify/resend" if request.method == Method::Post => {
                self.resend_verification(runtime, request, wall)
            }
            "me" if request.method == Method::Get => self.whoami(runtime, request),
            "me/password" if request.method == Method::Post => {
                self.set_account_password(runtime, request, body)
            }
            "mine" if request.method == Method::Get => self.mine(runtime, request),
            "mine/withdraw" if request.method == Method::Post => {
                self.withdraw(runtime, request, body)
            }
            "passkey/register/start" if request.method == Method::Post => {
                self.passkey_register_start(runtime, request, body)
            }
            "passkey/register/finish" if request.method == Method::Post => {
                self.passkey_register_finish(runtime, body)
            }
            "passkey/login/start" if request.method == Method::Post => {
                self.passkey_login_start(runtime)
            }
            "passkey/login/finish" if request.method == Method::Post => {
                self.passkey_login_finish(runtime, body)
            }
            "download" if request.method == Method::Get => self.download(runtime, request),
            // Its allowance is already spent, on the page-visit budget above — deliberately not
            // the account door's (a person who refreshes twice must still be able to sign in)
            // and, since this pass, deliberately not the reader's either: a reader's ten tokens
            // are five page loads, after which the files still served and this answered `429`,
            // and `assets/app.js` draws that as a box with no passkeys and no providers.
            "capabilities" if request.method == Method::Get => self.capabilities(runtime),
            // The landing page and the three files it is made of: no session, and their own
            // allowance — not the account door's (they are not in the `matches!` list above)
            // and not the reader's. See [`Config::per_page_visitor`] and the module
            // documentation's "one page this crate serves, and the three files it is made of".
            "" | "index.html" if request.method == Method::Get => self.page(
                request,
                client,
                now,
                "text/html; charset=utf-8",
                LANDING_PAGE,
            ),
            "app.css" if request.method == Method::Get => {
                self.page(request, client, now, "text/css; charset=utf-8", APP_CSS)
            }
            "app.js" if request.method == Method::Get => self.page(
                request,
                client,
                now,
                "text/javascript; charset=utf-8",
                APP_JS,
            ),
            "favicon.svg" if request.method == Method::Get => {
                self.page(request, client, now, "image/svg+xml", FAVICON_SVG)
            }
            "register"
            | "login"
            | "logout"
            | "verify/confirm"
            | "verify/resend"
            | "me/password"
            | "mine/withdraw"
            | "passkey/register/start"
            | "passkey/register/finish"
            | "passkey/login/start"
            | "passkey/login/finish" => {
                refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes POST")
            }
            "verify" | "me" | "mine" | "download" | "capabilities" | "" | "index.html"
            | "app.css" | "app.js" | "favicon.svg" => {
                refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET")
            }
            _ if suffix.starts_with("oauth/") => self.oauth_route(runtime, suffix, request),
            _ => refuse(Status::NOT_FOUND, "no such endpoint"),
        }
    }

    /// `POST <route>/register` — email and password, the baseline account door.
    fn register_password(
        &self,
        runtime: &AccountsRuntime,
        body: &[u8],
        wall: SystemTime,
    ) -> Response {
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        match self.create_password_account(runtime, &value) {
            Ok(account) => {
                self.send_verification(runtime, &account, wall);
                self.session_response(runtime, &account.id)
            }
            Err(response) => response,
        }
    }

    /// The email/password validation and account creation [`Self::register_password`] uses.
    fn create_password_account(
        &self,
        runtime: &AccountsRuntime,
        value: &Json,
    ) -> Result<Account, Response> {
        let email = text_field(value, "email");
        let password = text_field(value, "password");
        if email.is_empty() || password.is_empty() {
            return Err(refuse(
                Status::BAD_REQUEST,
                "`email` and `password` are required",
            ));
        }
        runtime
            .accounts
            .create_with_password(email, password)
            .map_err(|error| account_error_response(&error))
    }

    /// `POST <route>/login` — email and password. Every way of failing answers the same
    /// sentence: an agent guessing at an email cannot tell a wrong password from no such
    /// account, exactly as `Webauthn::verify_login` refuses every bent assertion identically.
    fn login_password(&self, runtime: &AccountsRuntime, body: &[u8]) -> Response {
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let email = text_field(&value, "email");
        let password = text_field(&value, "password");
        let wrong = || refuse(Status::UNAUTHORIZED, "wrong email or password");
        let Ok(address) = selfhost_mail::Address::parse(email) else {
            return wrong();
        };
        let Some(account) = runtime.accounts.find_by_email(&address) else {
            return wrong();
        };
        if !runtime.accounts.verify_password(&account, password) {
            return wrong();
        }
        self.session_response(runtime, &account.id)
    }

    /// `POST <route>/logout` — ends the presented session, if any. Never an error: a caller
    /// with no cookie, or one that names nothing live, reaches the same signed-out state either
    /// way.
    fn logout(&self, runtime: &AccountsRuntime, request: &Request) -> Response {
        if let Some(cookie) = sessions::cookie_value(request.headers.get_str("cookie")) {
            runtime.sessions.end(&cookie);
        }
        let mut response = answer(Status::OK, Json::object([("signedOut", Json::Bool(true))]));
        let _ = response.headers.set(
            "Set-Cookie",
            sessions::clear_cookie_header(&self.config.route, self.cookies_secure(runtime)),
        );
        response
    }

    /// `GET <route>/verify?token=…` — the redeeming half of the address written into a
    /// verification email, reached **only** when the caller explicitly asked for JSON.
    ///
    /// Every other `GET` of this address — a browser, a mail scanner, a link checker, a
    /// `<img src>` — never arrives here at all: [`Self::accounts_answer`] answers it with the
    /// page before this function or the account door's limiter is reached. [`redeems_on_get`]
    /// is the one place that decision is made and the one place to read for the rule.
    ///
    /// The page it gets instead is byte for byte the same shell `<route>/` serves, and nothing
    /// else. The token is not read, not redeemed, and above all not written into the markup:
    /// the shell is a `&'static str` compiled into this binary, so there is no seam here where a
    /// query value could become part of a page, which is the only way this route could ever have
    /// served somebody else's bytes to somebody else's browser. The page reads the token out of
    /// `location.search` itself and spends it with `POST <route>/verify/confirm`.
    ///
    /// A caller that does ask for JSON — curl, this project's CLI, an agent — gets the redeem
    /// it has always got, byte for byte, including both of its refusals.
    ///
    /// # Redeeming on `GET` was a bug with a very ordinary cause
    ///
    /// A verification token is single-use, and this route spent it on a `GET`. Mail gateways,
    /// link checkers, and preview generators fetch every URL in an incoming message before a
    /// human sees it, and none of them are attacking anyone — but the first one to arrive burned
    /// the token, so the person the mail was addressed to clicked their link and were told it
    /// was invalid or expired, on their first attempt, with nothing they could have done
    /// differently. The general rule that prevents this is the module documentation's "no `GET`
    /// under `<route>/` changes state"; this route was its one exception and no longer is.
    fn verify_email(&self, runtime: &AccountsRuntime, query: &str) -> Response {
        let Some(token) = query_param(query, "token") else {
            return refuse(Status::BAD_REQUEST, "`token` is required");
        };
        self.redeem_verification(runtime, &token)
    }

    /// `POST <route>/verify/confirm` — `{"token": "…"}`, the half of `<route>/verify` that
    /// actually spends the token, now that the address a mail scanner prefetches does not.
    ///
    /// A `POST` rather than a second `GET` because a prefetcher does not make one, and because
    /// this is a state change: [`Service::cross_origin_post`] and the session cookie's
    /// `SameSite=Lax` both apply to it and neither applies to a navigation.
    fn verify_confirm(&self, runtime: &AccountsRuntime, body: &[u8]) -> Response {
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let token = text_field(&value, "token");
        if token.is_empty() {
            return refuse(Status::BAD_REQUEST, "`token` is required");
        }
        self.redeem_verification(runtime, token)
    }

    /// Spends one verification token and marks its account's address confirmed — the one body
    /// of this behaviour, shared by the JSON half of [`Self::verify_email`] and by
    /// [`Self::verify_confirm`], so the two doors cannot come to disagree about what redeeming
    /// means or about which sentence a spent token gets.
    fn redeem_verification(&self, runtime: &AccountsRuntime, token: &str) -> Response {
        let Some(account_id) = runtime.verify.redeem(token) else {
            return refuse(
                Status::BAD_REQUEST,
                "this verification link is invalid or has expired — ask for a new one",
            );
        };
        if let Err(error) = runtime.accounts.mark_verified(&account_id) {
            eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
            return refuse(Status::INTERNAL_SERVER_ERROR, "could not confirm the email");
        }
        answer(Status::OK, Json::object([("verified", Json::Bool(true))]))
    }

    /// `POST <route>/verify/resend` — a fresh link, for an account that lost the first one.
    fn resend_verification(
        &self,
        runtime: &AccountsRuntime,
        request: &Request,
        wall: SystemTime,
    ) -> Response {
        let Some(account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        if account.email_verified {
            return answer(
                Status::OK,
                Json::object([("alreadyVerified", Json::Bool(true))]),
            );
        }
        self.send_verification(runtime, &account, wall);
        answer(Status::OK, Json::object([("sent", Json::Bool(true))]))
    }

    /// Mints a verification token and spools the email, when this box has somewhere to spool
    /// it. Silent when it does not — the same degraded-but-working shape an unconfigured
    /// [`Config::mail`] gives report notifications: the account still works, it is simply
    /// unverified until an operator wires up mail or the account sets a password it can prove
    /// some other way.
    fn send_verification(&self, runtime: &AccountsRuntime, account: &Account, wall: SystemTime) {
        let Some(queue) = &runtime.mail_queue else {
            return;
        };
        let Ok(token) = runtime.verify.mint(&account.id) else {
            return;
        };
        let verify_url = format!(
            "{}{}/verify?token={token}",
            runtime.config.public_base_url, self.config.route
        );
        let _ = wall; // reserved: a future retry policy may want the moment this was requested
        if let Err(error) = crate::verify::send_verification(
            queue,
            &runtime.config.verify_from,
            &account.email,
            &runtime.config.verify_helo,
            &runtime.config.site_name,
            &verify_url,
        ) {
            eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
        }
    }

    /// `GET <route>/me` — the account's own view of itself.
    fn whoami(&self, runtime: &AccountsRuntime, request: &Request) -> Response {
        let Some(account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        answer(Status::OK, self.me_json(runtime, &account))
    }

    /// The `me`-shaped body [`Self::whoami`] answers with.
    fn me_json(&self, runtime: &AccountsRuntime, account: &Account) -> Json {
        let passkeys = runtime
            .webauthn
            .as_ref()
            .map(|webauthn| webauthn.passkeys().list_for(&account.id))
            .unwrap_or_default();
        Json::object([
            ("id", Json::string(&account.id)),
            ("email", Json::string(&account.email)),
            ("emailVerified", Json::Bool(account.email_verified)),
            ("plan", Json::string(&account.plan)),
            ("hasPassword", Json::Bool(account.password.is_some())),
            (
                "oauthProviders",
                Json::array(
                    account
                        .oauth_links
                        .iter()
                        .map(|link| Json::string(&link.provider)),
                ),
            ),
            (
                "passkeys",
                Json::array(passkeys.iter().map(|passkey| {
                    Json::object([
                        ("id", Json::string(&passkey.id)),
                        ("label", Json::string(&passkey.label)),
                        ("createdUnix", Json::Number(passkey.created_unix as f64)),
                    ])
                })),
            ),
            ("createdUnix", Json::Number(account.created_unix as f64)),
        ])
    }

    /// `GET <route>/download` — session required, the same shape [`Self::whoami`] uses: this
    /// crate has no packaged installer or release artifact anywhere in this repository (see the
    /// module documentation), so this answers exactly what exists — the GitHub source archive
    /// `crates/cli/src/self_update.rs`'s own fetch-and-build recipe already runs against.
    /// Downloading source is not server access and never was, so this carries nothing about
    /// roles or grants — see the module documentation's "no invite code" section.
    fn download(&self, runtime: &AccountsRuntime, request: &Request) -> Response {
        let Some(_account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        answer(
            Status::OK,
            Json::object([
                ("downloadUrl", Json::string(DOWNLOAD_URL)),
                ("repository", Json::string(REPOSITORY_URL)),
                ("branch", Json::string(DOWNLOAD_BRANCH)),
                ("setup", Json::string(DOWNLOAD_SETUP)),
            ]),
        )
    }

    /// `POST <route>/me/password` — sets or replaces the account's password.
    ///
    /// Ends every other session on this account: a credential rotation that leaves an older
    /// session alive on a device this was rotated *away from* is not a rotation.
    fn set_account_password(
        &self,
        runtime: &AccountsRuntime,
        request: &Request,
        body: &[u8],
    ) -> Response {
        let Some(account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let password = text_field(&value, "password");
        match runtime.accounts.set_password(&account.id, password) {
            Ok(()) => {
                runtime.sessions.end_all_for(&account.id);
                self.session_response(runtime, &account.id)
            }
            Err(error) => account_error_response(&error),
        }
    }

    /// `GET <route>/mine` — the reports this account filed, newest first.
    fn mine(&self, runtime: &AccountsRuntime, request: &Request) -> Response {
        let Some(account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        let reports: Vec<Json> = account
            .filed
            .iter()
            .rev()
            .filter_map(|reference| self.store.get(&reference.project, &reference.id).ok())
            .map(|entry| store::to_json(&entry))
            .collect();
        answer(
            Status::OK,
            Json::object([("reports", Json::array(reports))]),
        )
    }

    /// `POST <route>/mine/withdraw` — closes a report this account filed. A report that does
    /// not exist and one that exists but belongs to somebody else answer the identical `404`,
    /// so this route cannot be used to learn whether a given id belongs to another account.
    fn withdraw(&self, runtime: &AccountsRuntime, request: &Request, body: &[u8]) -> Response {
        let Some(account) = self.caller(runtime, request) else {
            return refuse(Status::UNAUTHORIZED, "sign in first");
        };
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let project = text_field(&value, "project");
        let id = text_field(&value, "id");
        if project.is_empty() || id.is_empty() {
            return refuse(Status::BAD_REQUEST, "`project` and `id` are required");
        }
        let not_found = || refuse(Status::NOT_FOUND, "no such report");
        let Ok(entry) = self.store.get(project, id) else {
            return not_found();
        };
        if entry.account_id.as_deref() != Some(account.id.as_str()) {
            return not_found();
        }
        match self.store.close(project, id) {
            Ok(()) => {
                if let Err(error) = runtime.accounts.remove_filed(&account.id, project, id) {
                    eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                }
                answer(Status::OK, Json::object([("withdrawn", Json::string(id))]))
            }
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "the report could not be withdrawn",
                )
            }
        }
    }

    /// `POST <route>/passkey/register/start` — with a live session, adds a device to the
    /// signed-in account; with none, `email` in the body registers a brand-new account.
    ///
    /// # An unauthenticated door must not say who already has an account here
    ///
    /// This route used to answer `400 an account already exists for this email` when the address
    /// was taken, which made it a free membership oracle for anybody with a list of addresses:
    /// one anonymous `POST` per address, and this box says which of your users are mine.
    /// [`Self::login_password`] is the house pattern — every way of failing collapses to one
    /// sentence — and there is no reason a passkey door gets to be chattier than the password
    /// one standing beside it.
    ///
    /// So a taken address gets a challenge too, from
    /// [`webauthn::Webauthn::challenge`](crate::webauthn::Webauthn::challenge) rather than
    /// `start_registration`: the same `{"challenge", "rpId"}` object, the same status, the same
    /// length — but bound to no account, so [`Self::passkey_register_finish`] later refuses it
    /// with the identical "the passkey ceremony could not be verified" that a bent or replayed
    /// ceremony already gets. The only thing a prober can measure is a ceremony that fails the
    /// way every other failing ceremony fails.
    ///
    /// The alternative — minting a throwaway pending account and binding the challenge to *that*
    /// — was rejected because it is a new resource-exhaustion path aimed straight at
    /// [`crate::accounts::MAX_ACCOUNTS`]: the "one account per email" rule is what today bounds
    /// how many rows an anonymous caller can create, and a decoy account for an address that
    /// already has one is precisely a row that rule was refusing. A decoy *challenge* allocates
    /// only an entry in the in-memory pool `crate::webauthn` already caps and expires.
    fn passkey_register_start(
        &self,
        runtime: &AccountsRuntime,
        request: &Request,
        body: &[u8],
    ) -> Response {
        let Some(webauthn) = &runtime.webauthn else {
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        let account_id = match self.caller(runtime, request) {
            Some(account) => Some(account.id),
            None => {
                let Some(value) = parse_json_body(body) else {
                    return refuse(Status::BAD_REQUEST, "the body is not JSON");
                };
                let email = text_field(&value, "email");
                if email.is_empty() {
                    return refuse(
                        Status::BAD_REQUEST,
                        "`email` is required to register a new account with a passkey",
                    );
                }
                match runtime.accounts.create_pending(email) {
                    Ok(account) => Some(account.id),
                    // The one refusal that must not be spoken: see this function's own
                    // documentation. Everything else — an address that is not an address, a box
                    // at its account cap, a filesystem that refused — is about the *request* or
                    // this box, never about who else is registered, and is answered plainly.
                    Err(AccountError::EmailTaken) => None,
                    Err(error) => return account_error_response(&error),
                }
            }
        };
        let issued = match &account_id {
            Some(id) => webauthn.start_registration(id),
            None => webauthn.challenge(webauthn::Purpose::Register),
        };
        match issued {
            Ok(challenge) => answer(Status::OK, challenge),
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "could not start registration",
                )
            }
        }
    }

    /// `POST <route>/passkey/register/finish` — completes the ceremony, always under the
    /// account [`webauthn::Webauthn::start_registration`] bound at issuance.
    fn passkey_register_finish(&self, runtime: &AccountsRuntime, body: &[u8]) -> Response {
        let Some(webauthn) = &runtime.webauthn else {
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        match webauthn.finish_registration(&value) {
            Ok(passkey) => self.session_response(runtime, &passkey.account_id),
            Err(_) => refuse(
                Status::UNAUTHORIZED,
                "the passkey ceremony could not be verified",
            ),
        }
    }

    /// `POST <route>/passkey/login/start` — a discoverable-credential challenge; the browser's
    /// own account picker chooses which registered passkey answers it.
    fn passkey_login_start(&self, runtime: &AccountsRuntime) -> Response {
        let Some(webauthn) = &runtime.webauthn else {
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        if webauthn.is_empty() {
            // Uniform with a failed assertion below: a door with nothing registered on it must
            // not answer any differently than one that has something a guess merely missed.
            return refuse(Status::UNAUTHORIZED, "no passkey is registered");
        }
        match webauthn.challenge(webauthn::Purpose::Login) {
            Ok(challenge) => answer(Status::OK, challenge),
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(Status::INTERNAL_SERVER_ERROR, "could not start sign-in")
            }
        }
    }

    /// `POST <route>/passkey/login/finish` — verifies the assertion and signs in as whichever
    /// account the matched credential belongs to.
    fn passkey_login_finish(&self, runtime: &AccountsRuntime, body: &[u8]) -> Response {
        let Some(webauthn) = &runtime.webauthn else {
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        let Some(value) = parse_json_body(body) else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        match webauthn.verify_login(&value) {
            Ok(passkey) => self.session_response(runtime, &passkey.account_id),
            Err(_) => refuse(
                Status::UNAUTHORIZED,
                "the passkey ceremony could not be verified",
            ),
        }
    }

    /// `GET <route>/oauth/<provider>/start` — the only synchronous half of OAuth sign-in;
    /// [`Self::answer_async`] intercepts `.../callback` before this is ever reached for it.
    fn oauth_route(&self, runtime: &AccountsRuntime, suffix: &str, request: &Request) -> Response {
        let Some(rest) = suffix.strip_prefix("oauth/") else {
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        let Some(provider_name) = rest.strip_suffix("/start") else {
            // `/callback` (and anything else under `oauth/`) has no synchronous answer.
            return refuse(Status::NOT_FOUND, "no such endpoint");
        };
        if request.method != Method::Get {
            return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET");
        }
        let Some(provider) = runtime.oauth_providers.get(provider_name) else {
            return refuse(Status::NOT_FOUND, "no such sign-in provider is configured");
        };
        let redirect_uri = format!(
            "{}{}/oauth/{provider_name}/callback",
            runtime.config.public_base_url, self.config.route
        );
        match oauth::authorize_url(provider, &runtime.oauth_pending, &redirect_uri) {
            Ok((location, nonce)) => {
                let mut response = redirect(&location);
                // The browser's half of the binding — see `crate::oauth`'s module documentation.
                // Set here rather than anywhere else because this is the one moment this box
                // knows which browser started which attempt.
                let _ = response.headers.set(
                    "Set-Cookie",
                    oauth::nonce_cookie_header(
                        &nonce,
                        &self.config.route,
                        self.cookies_secure(runtime),
                    ),
                );
                response
            }
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(Status::INTERNAL_SERVER_ERROR, "could not start sign-in")
            }
        }
    }

    /// `GET <route>/oauth/<provider>/callback?code=…&state=…` — completes the exchange. The
    /// one route in this crate that awaits network I/O, so it is reached only through
    /// [`Self::answer_async`], never through the synchronous [`Self::answer`].
    ///
    /// # Whose answer this is
    ///
    /// Unlike every other route here, this one is reached by a **top-level navigation** the
    /// provider caused: the person who clicked "sign in with…" is looking at their browser's
    /// address bar when it arrives. Answering `200 {"signedIn":true}` left them staring at a
    /// JSON body, which is a working sign-in that looks exactly like a broken one. So a browser
    /// (an `Accept` naming `text/html`, [`wants_html`]) is sent on to the page instead —
    /// [`Self::session_redirect`] on success, [`Self::signin_error_redirect`] on every failure.
    /// Every other client keeps the exact `200` and the exact refusal sentences it has always
    /// had; nothing about the JSON contract moved.
    ///
    /// The failure mapping is deliberately derived from the refusal the JSON path *would* have
    /// answered rather than decided a second time — see [`signin_error_code`]. One place in this
    /// function decides what went wrong; the browser path translates that decision, so the two
    /// answers cannot come to disagree about which failure a request hit.
    async fn oauth_callback(
        &self,
        runtime: &AccountsRuntime,
        provider_name: &str,
        query: &str,
        request: &Request,
    ) -> Response {
        let browser = wants_html(request);
        match self
            .oauth_signin(runtime, provider_name, query, request)
            .await
        {
            Ok(account) if browser => self.session_redirect(runtime, &account.id),
            Ok(account) => self.session_response(runtime, &account.id),
            Err(refusal) if browser => {
                self.signin_error_redirect(signin_error_code(refusal.status))
            }
            Err(refusal) => refusal,
        }
    }

    /// The whole of completing an OAuth sign-in: the account it lands on, or the refusal the
    /// JSON caller gets. Split out of [`Self::oauth_callback`] so that deciding *what happened*
    /// and deciding *how to say it* are two different functions, and only the second one knows
    /// whether it is talking to a browser.
    async fn oauth_signin(
        &self,
        runtime: &AccountsRuntime,
        provider_name: &str,
        query: &str,
        request: &Request,
    ) -> Result<Account, Response> {
        let Some(provider) = runtime.oauth_providers.get(provider_name) else {
            return Err(refuse(
                Status::NOT_FOUND,
                "no such sign-in provider is configured",
            ));
        };
        let client = match &runtime.oauth_client {
            Ok(client) => client,
            Err(error) => {
                eprintln!(
                    "[{}] reports: oauth client unavailable: {error}",
                    selfhost_mail::stamp()
                );
                return Err(refuse(
                    Status::SERVICE_UNAVAILABLE,
                    "sign-in is unavailable right now",
                ));
            }
        };
        let (Some(code), Some(state)) = (query_param(query, "code"), query_param(query, "state"))
        else {
            return Err(refuse(
                Status::BAD_REQUEST,
                "the provider did not return `code` and `state`",
            ));
        };
        // Whatever `<route>/oauth/<provider>/start` left in this browser, if this is the same
        // browser. `None` refuses exactly as a wrong value does — see `crate::oauth`.
        let nonce = oauth::nonce_cookie_value(request.headers.get_str("cookie"));
        let identity = match oauth::complete(
            provider,
            &runtime.oauth_pending,
            client,
            &code,
            &state,
            nonce.as_deref(),
        )
        .await
        {
            Ok(identity) => identity,
            Err(OAuthError::ExpiredState) => {
                return Err(refuse(
                    Status::BAD_REQUEST,
                    "this sign-in attempt has expired — start again",
                ));
            }
            Err(error) => {
                eprintln!(
                    "[{}] reports: oauth exchange failed: {error}",
                    selfhost_mail::stamp()
                );
                return Err(refuse(
                    Status::BAD_GATEWAY,
                    "the sign-in provider could not be reached",
                ));
            }
        };

        self.oauth_account(runtime, provider_name, &identity)
    }

    /// Finds or creates the account an OAuth identity signs in as.
    ///
    /// Looked up by the provider link first — a returning sign-in never re-decides anything.
    /// For a first sign-in, an account found **by email address** is merged into only when *both*
    /// sides of that address have been proven: the provider must vouch for it, and the account
    /// standing here must already carry [`Account::email_proven`]. Anything else mints a fresh
    /// account when the address is free, and refuses when it is not.
    ///
    /// # The exact seam an account takeover ran through
    ///
    /// Two rules, each defensible alone, combined into a way to walk into somebody's account:
    ///
    /// 1. `POST <route>/passkey/register/start` lets an unauthenticated caller name an address
    ///    and get an account for it — reasonable, because a passkey has to be registered
    ///    *somewhere* before the person holding it has any other way to prove who they are.
    /// 2. A provider that vouches for an address may merge into the account already holding that
    ///    address — reasonable, because that is what "sign in with Google" means to a person who
    ///    registered with a password last year and forgot.
    ///
    /// Run together: an attacker posts `victim@example.com` to rule 1, finishes the ceremony
    /// with *their own* authenticator, and now this box holds an account for the victim's
    /// address with the attacker's passkey on it and `email_verified: false`. The victim later
    /// clicks "sign in with Google", the provider truthfully vouches for their own address, and
    /// rule 2 hands them a session on the squatted account — with the attacker's credential
    /// still attached, and every report the victim files from then on readable by whoever holds
    /// it. Nothing anywhere was bypassed; the second rule simply trusted a *record* that the
    /// first rule let a stranger create.
    ///
    /// The fix is to make rule 2 ask what rule 1 never established: not "does this account
    /// exist" but "did anyone ever prove this address belongs to whoever holds it". A password,
    /// a passkey, an unvouched provider link — all of them prove possession of a credential and
    /// none of them prove possession of the address, which is exactly what
    /// [`Account::email_proven`] is named after.
    ///
    /// Legitimate merges are untouched: an account that clicked its verification link, or that
    /// was created by a provider that vouched, still merges. An account that never proved its
    /// address does not, and its holder is told the same sentence an unverified provider claim
    /// gets — byte for byte, so this route cannot be used to sort addresses into "squatted" and
    /// "merely unverified". Its holder can still sign in with the credential they do have, and
    /// verifying the address afterwards makes the merge work.
    fn oauth_account(
        &self,
        runtime: &AccountsRuntime,
        provider_name: &str,
        identity: &oauth::Identity,
    ) -> Result<Account, Response> {
        if let Some(account) = runtime
            .accounts
            .find_by_oauth(provider_name, &identity.subject)
        {
            return Ok(account);
        }
        let Ok(address) = selfhost_mail::Address::parse(&identity.email) else {
            return Err(refuse(
                Status::BAD_GATEWAY,
                "the sign-in provider returned an email this box could not parse",
            ));
        };
        if let Some(existing) = runtime.accounts.find_by_email(&address) {
            if !identity.email_verified || !existing.email_proven() {
                // 409: this box already has an opinion about who that address belongs to, and
                // neither an unverified claim nor an account that never proved the address gets
                // to overrule it. One refusal for both, deliberately: which of the two it was is
                // itself worth knowing to someone probing for a squat that stuck.
                return Err(refuse(
                    Status(409),
                    &OAuthError::UnverifiedEmailConflict.to_string(),
                ));
            }
            if let Err(error) =
                runtime
                    .accounts
                    .link_oauth(&existing.id, provider_name, &identity.subject)
            {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                return Err(refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "could not link this sign-in",
                ));
            }
            return Ok(existing);
        }
        runtime
            .accounts
            .create_with_oauth(
                &identity.email,
                identity.email_verified,
                provider_name,
                &identity.subject,
            )
            .map_err(|error| account_error_response(&error))
    }

    /// Mints a session for `account_id` and returns the whole `Set-Cookie` field value it is
    /// carried on, or `None` when the session store refused.
    ///
    /// The one place a sign-in cookie is built. [`Self::session_response`] and
    /// [`Self::session_redirect`] both call it and neither assembles anything of its own,
    /// because the two are the same act — this box has decided who you are — differing only in
    /// what the *body* of the answer is. A second construction site is how a cookie ends up
    /// `Secure` on one path and not the other, and that is not a difference anyone would notice
    /// until it was a session id in the clear.
    fn session_cookie(&self, runtime: &AccountsRuntime, account_id: &str) -> Option<String> {
        match runtime.sessions.create(account_id) {
            Ok(cookie) => Some(sessions::set_cookie_header(
                &cookie,
                &self.config.route,
                self.cookies_secure(runtime),
            )),
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                None
            }
        }
    }

    /// Mints a session for `account_id` and returns it as the answer's `Set-Cookie` — the
    /// `200 {"signedIn":true}` every API client of this crate has always got.
    fn session_response(&self, runtime: &AccountsRuntime, account_id: &str) -> Response {
        let Some(header) = self.session_cookie(runtime, account_id) else {
            return refuse(Status::INTERNAL_SERVER_ERROR, "could not start a session");
        };
        let mut response = answer(Status::OK, Json::object([("signedIn", Json::Bool(true))]));
        let _ = response.headers.set("Set-Cookie", header);
        response
    }

    /// The same session, handed to a browser: `303 See Other` to this crate's own page, with
    /// the identical `Set-Cookie` [`Self::session_response`] would have carried.
    ///
    /// # The `Location` is built from [`Config::route`] and from nothing else
    ///
    /// Not from a `next=`, a `return_to=`, or any other query parameter, however convenient
    /// that would be for a future "send them back where they were". This is the one response in
    /// the whole crate that mints a session cookie *and* redirects, which makes it the exact
    /// shape an open redirect is worth having: a link that starts a real sign-in at this box and
    /// lands the freshly-signed-in person on an attacker's page, with this box's own address in
    /// the referrer chain and the person's trust already spent. The destination is therefore
    /// literally `<route>/?signedin=1` — a path this process wrote, with no caller input
    /// anywhere in it. "Back where they were" is a thing the page can remember for itself in
    /// `sessionStorage`, on the side of the wire where it cannot be handed in by a stranger.
    ///
    /// `303` rather than `302`: the person arrived here by a `GET` the provider caused, and
    /// `303` says "the answer to that is at this other address, fetch it with `GET`" — which is
    /// exactly what happened — where `302` leaves the method to the client's judgement.
    fn session_redirect(&self, runtime: &AccountsRuntime, account_id: &str) -> Response {
        let Some(header) = self.session_cookie(runtime, account_id) else {
            return self.signin_error_redirect(SIGNIN_UNAVAILABLE);
        };
        let mut response = see_other(&format!("{}/?signedin=1", self.config.route));
        let _ = response.headers.set("Set-Cookie", header);
        response
    }

    /// `303` to `<route>/?signin_error=<code>` — how a browser is told a sign-in did not
    /// complete, since it is looking at an address bar rather than reading a JSON body.
    ///
    /// `code` is one of the five [`signin_error_code`] enumerates and never anything else, and
    /// in particular never a sentence, never a provider's own error text, and never anything
    /// that came in on the request. The page owns the wording; this owns the classification.
    fn signin_error_redirect(&self, code: &str) -> Response {
        see_other(&format!("{}/?signin_error={code}", self.config.route))
    }

    /// Whether the session cookie should carry `Secure`. Derived from the configured public
    /// base URL rather than anything on the request: this service always binds loopback (see
    /// [`bind`]) and never itself terminates TLS, so nothing about a live connection here says
    /// whether the browser reached the proxy over `https://` — but [`AccountsConfig::
    /// public_base_url`] already states, once, whether this deployment is one.
    fn cookies_secure(&self, runtime: &AccountsRuntime) -> bool {
        runtime.config.public_base_url.starts_with("https://")
    }

    /// `GET <route>/health` — enough for the proxy's health check and nothing more.
    fn health(&self, request: &Request) -> Response {
        if request.method != Method::Get {
            return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET");
        }
        let projects = self.store.projects().unwrap_or_default().len();
        answer(
            Status::OK,
            Json::object([
                ("ok", Json::Bool(true)),
                ("projects", Json::Number(projects as f64)),
            ]),
        )
    }

    /// `GET <route>/feed?<service>` — what a subscribed checkout folds into its `reports.dx`.
    fn feed(&self, request: &Request, query: &str) -> Response {
        if request.method != Method::Get {
            return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes GET");
        }
        if let Some(refused) = self.check_token(request) {
            return refused;
        }
        let project = match self.service_of(query, None) {
            Ok(project) => project,
            Err(refusal) => return refuse(Status::BAD_REQUEST, refusal.message()),
        };
        match self.store.list(&project) {
            Ok(entries) => answer(
                Status::OK,
                Json::object([
                    ("project", Json::string(&project)),
                    ("reports", Json::array(entries.iter().map(store::to_json))),
                ]),
            ),
            Err(StoreError::NoProject(message)) => refuse(Status::NOT_FOUND, &message),
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(Status::INTERNAL_SERVER_ERROR, "the feed could not be read")
            }
        }
    }

    /// `POST <route>/close?<service>` — a fixed report leaves the database, so a checkout that
    /// syncs again does not fold it back in.
    fn close(&self, request: &Request, query: &str, body: &[u8]) -> Response {
        if request.method != Method::Post {
            return refuse(Status::METHOD_NOT_ALLOWED, "this endpoint takes POST");
        }
        if let Some(refused) = self.check_token(request) {
            return refused;
        }
        let asked = std::str::from_utf8(body)
            .ok()
            .and_then(|text| selfhost_json::parse(text).ok());
        let Some(value) = asked else {
            return refuse(Status::BAD_REQUEST, "the body is not JSON");
        };
        let project = match self.service_of(query, Some(&value)) {
            Ok(project) => project,
            Err(refusal) => return refuse(Status::BAD_REQUEST, refusal.message()),
        };
        let Some(id) = value.get("id").and_then(Json::as_str) else {
            return refuse(Status::BAD_REQUEST, "`id` is required");
        };
        match self.store.close(&project, id) {
            Ok(()) => answer(
                Status::OK,
                Json::object([
                    ("closed", Json::string(id)),
                    ("project", Json::string(&project)),
                ]),
            ),
            Err(StoreError::Unreadable(message) | StoreError::NoProject(message)) => {
                refuse(Status::NOT_FOUND, &message)
            }
            Err(error) => {
                eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                refuse(
                    Status::INTERNAL_SERVER_ERROR,
                    "the report could not be closed",
                )
            }
        }
    }

    /// Which service this call is about: the address first, then the body, then this box's
    /// default.
    ///
    /// The address wins over the body because the address is where the report was actually
    /// sent — a body claiming `"project": "dx"` on a call to `…/report?billing` is a reporter
    /// with a stale template, not an instruction. The body is consulted at all so that a caller
    /// with no query still files somewhere sensible, and so a record is complete on its own.
    ///
    /// # Errors
    /// The [`Refusal`] [`project_key`] gives, naming what a key may contain.
    fn service_of(&self, query: &str, body: Option<&Json>) -> Result<String, Refusal> {
        if let Some(named) = service_in_query(query) {
            return project_key(named);
        }
        let stated = body
            .and_then(|value| value.get("project"))
            .and_then(Json::as_str)
            .unwrap_or_default()
            .trim();
        if stated.is_empty() {
            return Ok(self.config.default_project.clone());
        }
        project_key(stated)
    }

    /// Whether this request carries the owner's token.
    ///
    /// A box with no token configured answers the reading routes with the same `404` an
    /// unknown path gets: a route that cannot be used should not be a thing to probe.
    fn check_token(&self, request: &Request) -> Option<Response> {
        let Some(expected) = self.config.token.as_deref() else {
            return Some(refuse(Status::NOT_FOUND, "no such endpoint"));
        };
        let offered = request
            .headers
            .get_str("authorization")
            .and_then(|value| value.strip_prefix("Bearer ").map(str::to_string))
            .unwrap_or_default();
        if constant_time_eq(offered.trim().as_bytes(), expected.as_bytes()) {
            return None;
        }
        Some(refuse(
            Status::UNAUTHORIZED,
            "this endpoint needs the owner's token",
        ))
    }

    /// Spends one allowance for `client` out of `limiter`.
    ///
    /// Filing and reading have a limiter each, so a checkout syncing every few minutes and an
    /// agent filing a burst of reports never take each other's allowance — and a stranger
    /// guessing at the token cannot stop either.
    fn admit(&self, limiter: &Mutex<Limiter>, client: &str, now: Instant) -> Decision {
        match limiter.lock() {
            Ok(mut limiter) => limiter.admit(client, now),
            // A poisoned lock means a panic happened while holding it. Under `panic = "abort"`
            // that cannot happen; if it somehow did, refusing is the safe half of the choice.
            Err(_) => Decision::Refuse(RETRY_INTERVAL.as_secs()),
        }
    }

    /// Whether a notification may be sent right now.
    fn may_notify(&self, now: Instant) -> bool {
        self.mail_meter
            .lock()
            .map(|mut meter| meter.take(now).admitted())
            .unwrap_or(false)
    }
}

/// Delivers up to [`DELIVERY_BATCH`] stored-but-untold reports into the owner's mailbox.
///
/// Called right after a report is accepted and again on a timer, so the ordinary case is
/// "the message is already in the inbox before the reporter's next sentence" and the failure
/// case is "it arrives on the next pass". A report is marked delivered only after the mail
/// server accepted it.
pub async fn deliver_pending(service: &Service, now: Instant, wall: SystemTime) {
    let Some(mailbox) = service.config.mail.clone() else {
        return;
    };
    let waiting = match service.store.undelivered(DELIVERY_BATCH) {
        Ok(waiting) => waiting,
        Err(error) => {
            eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
            return;
        }
    };
    for entry in waiting {
        if !service.may_notify(now) {
            // The database still has it and the next pass will send it: a throttled inbox is
            // never a lost report.
            return;
        }
        let message = notify::message(&mailbox, &entry, wall);
        match notify::send(&mailbox, &message).await {
            Ok(()) => {
                if let Err(error) = service.store.mark_delivered(&entry.project, &entry.id) {
                    eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
                }
            }
            Err(reason) => {
                eprintln!(
                    "[{}] reports: {} not delivered — {reason}",
                    selfhost_mail::stamp(),
                    entry.id
                );
                return;
            }
        }
    }
}

/// Retries undelivered reports forever, every [`RETRY_INTERVAL`].
pub async fn retry_forever(service: Arc<Service>) {
    loop {
        tokio::time::sleep(RETRY_INTERVAL).await;
        deliver_pending(&service, Instant::now(), SystemTime::now()).await;
    }
}

/// Binds the intake, refusing any address that is not loopback.
///
/// # Errors
/// The bind error, or a sentence explaining the refusal — the public door is the reverse
/// proxy, and an intake bound to `0.0.0.0` would be a second one with no TLS in front of it.
pub async fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    if !address.ip().is_loopback() {
        return Err(std::io::Error::other(format!(
            "refusing to bind the report intake to {address}: it must be loopback. The public \
             door is the reverse proxy — give the site an `app_paths` entry and an instance on \
             this port instead."
        )));
    }
    TcpListener::bind(address).await
}

/// Serves the intake until the listener fails.
///
/// # Errors
/// The accept error that ended the loop.
pub async fn serve(listener: TcpListener, service: Arc<Service>) -> std::io::Result<()> {
    loop {
        let (stream, peer) = listener.accept().await?;
        let service = Arc::clone(&service);
        tokio::spawn(async move {
            if let Err(error) = handle_connection(stream, peer, service).await {
                if error.kind() != std::io::ErrorKind::UnexpectedEof {
                    eprintln!(
                        "[{}] reports: {peer} ended: {error}",
                        selfhost_mail::stamp()
                    );
                }
            }
        });
    }
}

/// Reads one request, answers it, and closes.
///
/// One request per connection: this endpoint sees a handful of requests an hour, keep-alive
/// buys nothing, and every reused connection is a chance for two answers to disagree about
/// framing.
async fn handle_connection(
    mut stream: TcpStream,
    peer: SocketAddr,
    service: Arc<Service>,
) -> std::io::Result<()> {
    let read = tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await;
    let outcome = match read {
        Err(_) => {
            return write(
                &mut stream,
                &refuse(Status(408), "the request took too long"),
            )
            .await;
        }
        Ok(outcome) => outcome?,
    };
    let (request, body) = match outcome {
        Ok(pair) => pair,
        Err(response) => return write(&mut stream, &response).await,
    };

    let client = client_address(&request, peer);
    let response = service
        .answer_async(&request, &body, &client, Instant::now(), SystemTime::now())
        .await;
    let filed = response.status == Status::OK && request.method == Method::Post;
    write(&mut stream, &response).await?;
    // The reporter is done: close the socket before this task spends up to twenty seconds
    // talking to a mail server, so a slow delivery holds nothing of theirs open.
    let _ = stream.shutdown().await;
    drop(stream);

    if filed {
        // After the answer, never during it: the reporter waits for the database, not for a
        // mail server it has no relationship with.
        deliver_pending(&service, Instant::now(), SystemTime::now()).await;
    }
    Ok(())
}

/// Reads one complete request and its body, or the response that refuses it.
async fn read_request(
    stream: &mut TcpStream,
) -> std::io::Result<Result<(Request, Vec<u8>), Response>> {
    let mut buffer = Vec::with_capacity(1024);
    let mut scratch = [0u8; 4096];

    let (request, consumed) = loop {
        match Request::parse(&buffer) {
            Ok(parsed) => break (parsed.request, parsed.consumed),
            Err(ParseError::Incomplete) => {
                let read = stream.read(&mut scratch).await?;
                if read == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "client closed before sending a complete request",
                    ));
                }
                buffer.extend_from_slice(&scratch[..read]);
                if buffer.len() > MAX_BODY * 2 {
                    return Ok(Err(refuse(
                        Status::CONTENT_TOO_LARGE,
                        "the request is too large",
                    )));
                }
            }
            Err(error) => {
                return Ok(Err(refuse(Status::BAD_REQUEST, &error.to_string())));
            }
        }
    };

    let length = match request.body_length() {
        Ok(BodyLength::None) => 0,
        Ok(BodyLength::Fixed(length)) => length,
        // Chunked is refused rather than decoded: it exists to send a body of unknown size,
        // which is the one thing this endpoint will not accept.
        Ok(BodyLength::Chunked) => {
            return Ok(Err(refuse(
                Status(411),
                "send the report with a Content-Length, not chunked",
            )));
        }
        Err(error) => return Ok(Err(refuse(Status::BAD_REQUEST, &error.to_string()))),
    };
    if length > MAX_BODY as u64 {
        return Ok(Err(refuse(
            Status::CONTENT_TOO_LARGE,
            "a report may be at most 16 KB",
        )));
    }

    let mut body = buffer.split_off(consumed);
    body.truncate(length as usize);
    while (body.len() as u64) < length {
        let read = stream.read(&mut scratch).await?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "client closed before sending the whole body",
            ));
        }
        let wanted = (length as usize) - body.len();
        body.extend_from_slice(&scratch[..read.min(wanted)]);
    }
    Ok(Ok((request, body)))
}

/// Who this request is from, for rate limiting.
///
/// The **last** `X-Forwarded-For` value, which is the one this box's own proxy appended; a
/// client's own forwarded header is relayed too and comes first. With no such header the peer
/// address is used, which is the direct-connection case.
fn client_address(request: &Request, peer: SocketAddr) -> String {
    let forwarded: Vec<String> = request
        .headers
        .iter()
        .filter(|field| field.name().eq_ignore_ascii_case("x-forwarded-for"))
        .filter_map(|field| std::str::from_utf8(field.value()).ok())
        .filter_map(|value| value.rsplit(',').next())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    forwarded
        .last()
        .cloned()
        .unwrap_or_else(|| peer.ip().to_string())
}

/// Splits a request target into its path and query string.
fn split_target(target: &str) -> (&str, &str) {
    match target.split_once('?') {
        Some((path, query)) => (path, query),
        None => (target, ""),
    }
}

/// The service a query names: its first **bare** key, the one with no `=` in it.
///
/// `?dx` names dx. `?dx&verbose=1` still names dx, so a query that grows a parameter one day
/// does not change which database a call means. A query with no bare key names no service, and
/// the caller falls back — deliberately, rather than inventing `project=` as a second spelling.
fn service_in_query(query: &str) -> Option<&str> {
    query
        .split('&')
        .find(|pair| !pair.is_empty() && !pair.contains('='))
}

/// Sets the headers `docs/SECURITY.md` (PUB-06) requires of every response this app sends —
/// upstream heads reach the client verbatim, so the app sets these itself, on every answer
/// including a redirect.
fn set_security_headers(response: &mut Response) {
    let _ = response.headers.set("X-Content-Type-Options", "nosniff");
    let _ = response.headers.set("X-Frame-Options", "DENY");
    let _ = response.headers.set("Referrer-Policy", "no-referrer");
    let _ = response.headers.set(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    );
    let _ = response.headers.set("Cache-Control", "no-store");
}

/// A JSON answer with the headers `docs/SECURITY.md` requires of an app behind the proxy.
fn answer(status: Status, value: Json) -> Response {
    let mut response = match Response::bytes(
        status,
        "application/json; charset=utf-8",
        value.to_text().into_bytes(),
    ) {
        Ok(response) => response,
        Err(_) => Response::empty(Status::INTERNAL_SERVER_ERROR),
    };
    set_security_headers(&mut response);
    response
}

/// An error answer carrying an explanation written for the agent that sent the request.
fn refuse(status: Status, message: &str) -> Response {
    answer(status, Json::object([("error", Json::string(message))]))
}

/// The page surface's `Content-Security-Policy`: this origin, and nothing else, anywhere.
///
/// Every source list is `'self'` or `'none'` — there is no `'unsafe-inline'`, no
/// `'unsafe-eval'`, and no host. That is only possible because the shell carries no inline
/// `<script>` and no inline `<style>`: both live in [`APP_JS`] and [`APP_CSS`], which are
/// routes of this same origin. A policy that allows inline script allows *every* inline
/// script, including the one an injection put there, so `'unsafe-inline'` gives up most of what
/// the header was set for; splitting two files out of the shell is a much smaller price.
///
/// The four beyond the obvious three are each closing a door that is not `script-src`:
/// `form-action 'self'` stops an injected `<form>` from posting a password to another host,
/// which `connect-src` does not cover; `frame-src 'none'` and `object-src 'none'` refuse
/// embedded browsing contexts and plugins outright, because this page has neither and a policy
/// should describe what a page is; `base-uri 'none'` stops an injected `<base>` from
/// re-pointing every relative reference on the page — and every reference on this page is
/// relative, deliberately, so that it works under any [`Config::route`]. `img-src` allows
/// `data:` because an inline SVG or a generated pixel is bytes the page already has, not a
/// fetch, and `frame-ancestors 'none'` restates `X-Frame-Options: DENY` for browsers that
/// prefer the newer spelling.
const PAGE_POLICY: &str = "default-src 'self'; script-src 'self'; style-src 'self'; \
     connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-src 'none'; \
     object-src 'none'; frame-ancestors 'none'; base-uri 'none'";

/// The page and its three assets, carrying every header `docs/SECURITY.md` (PUB-06) requires —
/// with [`PAGE_POLICY`] in place of the JSON API's own, whose `default-src 'none'` would refuse
/// the page its own stylesheet and script. [`set_security_headers`] is untouched by this
/// function, so every JSON route's policy stays exactly as tight as it already was.
///
/// # `no-cache` rather than `no-store`, and why that needs an `ETag` to mean anything
///
/// Every JSON answer this crate sends is `no-store`, because each one is about one account and
/// belongs in no cache anywhere. These four are the opposite: the same bytes for every visitor,
/// compiled into the binary, and about eighty kilobytes of them. `no-store` would re-send all
/// of it on every navigation and every reload. `no-cache` lets a browser keep them and requires
/// it to ask before reusing them — fresh always, cheap usually.
///
/// Only *usually* if the ask can be answered without the body, which is what the `ETag` is for:
/// it is a hash of exactly the bytes being served, so a request that comes back with
/// `If-None-Match` gets a bodyless `304` when nothing changed, and the full file the first time
/// after a rebuild changed one of them. Without a validator, `no-cache` is `no-store` with extra
/// steps — the browser must revalidate and the server has nothing to revalidate against.
fn page_response(request: &Request, content_type: &str, bytes: &'static [u8]) -> Response {
    let tag = entity_tag(bytes);
    let unchanged = request
        .headers
        .get_str("if-none-match")
        .is_some_and(|presented| presented.split(',').any(|value| value.trim() == tag));
    let mut response = if unchanged {
        Response::empty(Status::NOT_MODIFIED)
    } else {
        match Response::bytes(Status::OK, content_type, bytes.to_vec()) {
            Ok(response) => response,
            Err(_) => return Response::empty(Status::INTERNAL_SERVER_ERROR),
        }
    };
    let _ = response.headers.set("X-Content-Type-Options", "nosniff");
    let _ = response.headers.set("X-Frame-Options", "DENY");
    let _ = response.headers.set("Referrer-Policy", "no-referrer");
    let _ = response.headers.set("Content-Security-Policy", PAGE_POLICY);
    let _ = response
        .headers
        .set("Cache-Control", "no-cache, must-revalidate");
    let _ = response.headers.set("ETag", tag);
    response
}

/// A quoted `ETag` for a static asset: FNV-1a over its bytes.
///
/// Not a cryptographic hash and not required to be one — an `ETag` answers "are these the same
/// bytes I already have", asked by a browser about a file this same box served it, and nothing
/// about that question is adversarial. What it must be is *content*-derived: a version number
/// or a build stamp would go stale against an edited asset (this crate's assets change without
/// the crate's version changing), and the length alone would miss an edit that happened to keep
/// it. Hashing eighty kilobytes per page load is a few microseconds on this box and buys a
/// `304` instead of eighty kilobytes on every reload after the first.
fn entity_tag(bytes: &[u8]) -> String {
    let digest = bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    format!("\"{digest:016x}\"")
}

/// The refusal a rate-limited reporter gets, carrying the wait.
fn retry_after(seconds: u64) -> Response {
    let mut response = refuse(
        Status::TOO_MANY_REQUESTS,
        "too many reports from here just now — the wait is in Retry-After",
    );
    let _ = response.headers.set("Retry-After", seconds.to_string());
    response
}

/// A `308` to `location` — how a browser asking for the bare `<route>` is sent to the page at
/// `<route>/`. Still carries the PUB-06 headers, same as every other answer this app sends.
///
/// `308` rather than `302` because this is not a detour: `<route>` and `<route>/` are the same
/// place and always will be. `308` rather than `301` because `301` has decades of history of
/// browsers and proxies rewriting a `POST` into a `GET` when they replay it, and this exact
/// path is the one open door this crate has for `POST` — a redirect that could ever teach an
/// intermediary to change a filer's method is not worth the two characters it saves.
fn permanent_redirect(location: &str) -> Response {
    let mut response = Response::redirect(Status::PERMANENT_REDIRECT, location)
        .unwrap_or_else(|_| Response::empty(Status::INTERNAL_SERVER_ERROR));
    set_security_headers(&mut response);
    response
}

/// Whether this request came from something that renders HTML — the only difference between a
/// person in an address bar and every other client this endpoint serves.
///
/// A browser navigating to an address sends `Accept: text/html,…`; curl sends `*/*` or nothing,
/// and this project's own CLI sends `application/json`. The test is the literal `text/html` and
/// nothing wider — `*/*` deliberately does **not** count, because a client that will take
/// anything is exactly the one that should keep the answer it already had.
fn wants_html(request: &Request) -> bool {
    request
        .headers
        .get_str("accept")
        .is_some_and(|accept| accept.to_ascii_lowercase().contains("text/html"))
}

/// Whether a `GET <route>/verify?token=…` should **spend** the single-use token rather than be
/// answered with the landing page.
///
/// Only when the caller says, in so many words, that JSON is what it came for: an `Accept` that
/// names `application/json` and does not also name `text/html`. Everything else — `*/*`, no
/// `Accept` header at all, `image/*`, a header this function has never heard of — gets the page
/// and spends nothing.
///
/// # The default branch has to be the safe one, and inverting this was the whole fix
///
/// The first attempt at retiring `GET`-redeems asked the opposite question: serve the page when
/// [`wants_html`] says so, redeem otherwise. That closes the case of a *browser* prefetching,
/// and none of the others. A mail gateway's link checker sends `Accept: */*` or no `Accept` at
/// all. A `<img src="…/verify?token=…">` planted in a mail body makes the reader's own browser
/// fetch the address with `Accept: image/avif,image/webp,…,*/*;q=0.8` — no `text/html` anywhere
/// in it. Every one of those still reached the redeem and still burned the token, which is
/// exactly the failure the change was written to prevent: the person clicks their link, once,
/// and is told it is invalid.
///
/// So the question is asked the other way round. Spending a credential is the exceptional act
/// and it now takes an explicit request; being handed a static page is what an unknown client
/// gets. The cost is precisely bounded — a JSON client that sends `Accept: */*` gets a page
/// instead of a redeem — and that is the trade worth making, because a client that will take
/// anything has told us nothing, and the safe answer to "I don't know what you are" cannot be
/// "then I will spend your single-use token".
///
/// The `text/html` exclusion matters: a browser's navigation `Accept` is
/// `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8`, which does not contain
/// `application/json` — but a future one that listed both would be a browser, and a browser
/// gets the page.
fn redeems_on_get(request: &Request) -> bool {
    request.headers.get_str("accept").is_some_and(|accept| {
        let accept = accept.to_ascii_lowercase();
        accept.contains("application/json") && !accept.contains("text/html")
    })
}

/// The origin of an absolute URL — scheme, host and port, with the path and everything after it
/// dropped: `https://reports.example.com/base` is `https://reports.example.com`.
///
/// This is the exact form an `Origin` header takes (never a path, never a trailing slash), so it
/// is the only form [`AccountsConfig::public_base_url`] and a request's own header can be
/// compared in. Anything that is not `scheme://authority…` is `None`, and
/// [`Service::cross_origin_post`] treats that as "this box does not know its own address"
/// rather than as a match.
///
/// It is also, word for word, the value a browser writes into a passkey ceremony's
/// `clientDataJSON` — so this is the one function that decides both the `Origin` wall's
/// expected value and [`crate::webauthn::Webauthn`]'s. Public so that `crates/cli` can assert
/// what a given `--public-base-url` will actually pin a ceremony to, rather than restating the
/// derivation somewhere it could drift.
pub fn origin_of(url: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    if scheme.is_empty() {
        return None;
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return None;
    }
    Some(format!("{scheme}://{authority}"))
}

/// A `302` to `location` — the OAuth authorization dance's only non-JSON answer. Still carries
/// the PUB-06 headers, same as every other answer this app sends.
fn redirect(location: &str) -> Response {
    let mut response = Response::redirect(Status::FOUND, location)
        .unwrap_or_else(|_| Response::empty(Status::INTERNAL_SERVER_ERROR));
    set_security_headers(&mut response);
    response
}

/// `303 See Other` — "the answer to what you just did is at this other address, and you fetch
/// it with `GET`".
///
/// Spelled out here rather than taken from [`Status`]'s own constants because
/// `selfhost_http` does not name this one, and a bare `Status(303)` at the two call sites would
/// be two numbers with no word attached to either.
const SEE_OTHER: Status = Status(303);

/// A `303` to `location`, carrying the PUB-06 headers every other answer here carries —
/// including `Cache-Control: no-store` from [`set_security_headers`], which matters more on
/// this one than on most: the success case carries a session cookie, and a cached redirect that
/// carries a session cookie is a session handed to the next person on the same machine.
fn see_other(location: &str) -> Response {
    let mut response = Response::redirect(SEE_OTHER, location)
        .unwrap_or_else(|_| Response::empty(Status::INTERNAL_SERVER_ERROR));
    set_security_headers(&mut response);
    response
}

/// The sign-in attempt did not survive the round trip — a `state` this box no longer holds, or
/// a provider that came back without `code`/`state` at all. Both mean the same thing to the
/// person: start again.
const SIGNIN_EXPIRED: &str = "expired";

/// The token or userinfo exchange failed, or the provider answered something this box could not
/// use. The provider's own words are never passed on; they are attacker-influenceable text and
/// they would be rendered on this box's page.
const SIGNIN_PROVIDER_UNREACHABLE: &str = "provider_unreachable";

/// This box cannot complete a provider sign-in right now — no HTTPS client, no session store,
/// an account file that would not write. Not the person's fault and not the provider's.
const SIGNIN_UNAVAILABLE: &str = "unavailable";

/// The address the provider vouched for already belongs to an account here that never proved
/// it — [`Service::oauth_account`]'s `409`, which is a refusal to merge, not a failure.
const SIGNIN_EMAIL_CONFLICT: &str = "email_conflict";

/// No such provider is configured on this box. Ordinarily a stale bookmark or a redirect URI
/// left behind by a provider that has since been removed.
const SIGNIN_UNKNOWN_PROVIDER: &str = "unknown_provider";

/// Which of the five sign-in error codes a browser is redirected with, derived from the status
/// of the refusal the JSON path would have answered.
///
/// # These five words are a contract
///
/// `assets/app.js` holds a written sentence for each one and renders it to the person; nothing
/// else on that page decides what a failed sign-in says. So the set is closed —
/// [`SIGNIN_EXPIRED`], [`SIGNIN_PROVIDER_UNREACHABLE`], [`SIGNIN_UNAVAILABLE`],
/// [`SIGNIN_EMAIL_CONFLICT`], [`SIGNIN_UNKNOWN_PROVIDER`] — and a sixth code added here without
/// a sentence added there falls through to the page's generic "that sign-in did not complete",
/// which is the least useful answer this door can give. Changing a spelling here changes it
/// there, in the same commit, or the change is not finished.
///
/// Deriving them from the status rather than from a second `match` beside the first is what
/// keeps the browser's answer and the API's answer talking about the same failure: there is one
/// place in [`Service::oauth_signin`] that decides what went wrong, and this reads that decision
/// back out. The mapping is total by construction — an unfamiliar status is this box being
/// unable to finish, which is exactly [`SIGNIN_UNAVAILABLE`].
fn signin_error_code(status: Status) -> &'static str {
    match status {
        // Both `400`s mean "that attempt is not redeemable, start another one": a `state` the
        // pool no longer holds, and a callback that arrived without `code`/`state` at all —
        // which is what a provider sends when the person pressed Cancel on the consent screen.
        Status::BAD_REQUEST => SIGNIN_EXPIRED,
        Status::NOT_FOUND => SIGNIN_UNKNOWN_PROVIDER,
        Status(409) => SIGNIN_EMAIL_CONFLICT,
        Status::BAD_GATEWAY => SIGNIN_PROVIDER_UNREACHABLE,
        _ => SIGNIN_UNAVAILABLE,
    }
}

/// Decodes a request body as JSON, or `None` for anything that is not valid UTF-8 JSON — every
/// account route's first check, so a caller always gets the same "the body is not JSON" refusal
/// [`crate::report::Report::parse`]'s own caller already gives.
fn parse_json_body(body: &[u8]) -> Option<Json> {
    std::str::from_utf8(body)
        .ok()
        .and_then(|text| selfhost_json::parse(text).ok())
}

/// A string field from a decoded body, trimmed, or `""` when absent — the same "missing means
/// empty" shape [`Report::parse`] reads optional fields with.
fn text_field<'a>(value: &'a Json, key: &str) -> &'a str {
    value
        .get(key)
        .and_then(Json::as_str)
        .unwrap_or_default()
        .trim()
}

/// The value of `name=…` in a query string, if present. No percent-decoding: every value this
/// module reads from a query (a verification token, an OAuth `code`/`state`) is itself
/// generated from a URL-safe alphabet with nothing to encode, so a caller that percent-encoded
/// one anyway would simply fail to match — the same trade [`service_in_query`] already makes by
/// staying a plain split rather than a full query-string parser this workspace's dependency
/// policy has no crate for.
fn query_param(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == name && !value.is_empty()).then(|| value.to_string())
    })
}

/// Maps an [`AccountError`] to the response its caller gives back.
fn account_error_response(error: &AccountError) -> Response {
    match error {
        AccountError::Full => refuse(Status::SERVICE_UNAVAILABLE, &error.to_string()),
        AccountError::NotFound => refuse(Status::NOT_FOUND, &error.to_string()),
        AccountError::Io(_) => {
            eprintln!("[{}] reports: {error}", selfhost_mail::stamp());
            refuse(
                Status::INTERNAL_SERVER_ERROR,
                "the account could not be updated",
            )
        }
        AccountError::EmailTaken | AccountError::WeakPassword | AccountError::BadEmail(_) => {
            refuse(Status::BAD_REQUEST, &error.to_string())
        }
    }
}

/// Compares two byte strings in time that does not depend on where they first differ.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0u8, |differences, (a, b)| differences | (a ^ b))
        == 0
}

/// Writes one response and closes the write half.
async fn write(stream: &mut TcpStream, response: &Response) -> std::io::Result<()> {
    let mut head = Vec::new();
    response
        .write_head(&mut head, false)
        .map_err(|error| std::io::Error::other(format!("{error}")))?;
    stream.write_all(&head).await?;
    if let selfhost_http::Body::Bytes(bytes) = &response.body {
        stream.write_all(bytes).await?;
    }
    stream.flush().await
}

/// A refusal every caller of [`Report::parse`] can produce, kept here so the module's error
/// type is nameable from the binary that runs the service.
pub type Rejected = Refusal;

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::UNIX_EPOCH;

    /// A scratch directory no other run of these tests can be using.
    ///
    /// The process id *and* a counter, not just the label: keying on the label alone made every
    /// fixture a fixed path under the system temp directory, and the `remove_dir_all` each of
    /// them does at setup then meant two concurrent `cargo test` runs of this crate wiped each
    /// other's fixtures mid-test — four different tests were watched failing that way. "The
    /// tests are green" has to be a claim about the code rather than about whether anybody else
    /// happened to be running them at the same moment.
    fn scratch_dir(label: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "selfhost-reports-service-{}-{nonce}-{label}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn service(label: &str) -> Service {
        let dir = scratch_dir(label);
        let store = Store::open(&dir).expect("store");
        store.add_project("dx").expect("project");
        Service::new(
            store,
            Config {
                token: Some("secret-token".to_string()),
                ..Config::default()
            },
        )
    }

    fn request(head: &str) -> Request {
        Request::parse(head.as_bytes())
            .expect("request parses")
            .request
    }

    fn post(body: &str) -> Request {
        request(&format!(
            "POST /report HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ))
    }

    fn text(response: &Response) -> String {
        match &response.body {
            selfhost_http::Body::Bytes(bytes) => String::from_utf8_lossy(bytes).to_string(),
            _ => String::new(),
        }
    }

    fn file(service: &Service, body: &str, client: &str) -> Response {
        service.answer(
            &post(body),
            body.as_bytes(),
            client,
            Instant::now(),
            UNIX_EPOCH,
        )
    }

    fn file_with_cookie(service: &Service, body: &str, client: &str, cookie: &str) -> Response {
        let posted = request(&format!(
            "POST /report HTTP/1.1\r\nHost: x\r\nCookie: {cookie}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        service.answer(&posted, body.as_bytes(), client, Instant::now(), UNIX_EPOCH)
    }

    /// A scratch service with the account subsystem turned on: password, passkey (relying
    /// party `RP`) and outbound verification mail spooled into a scratch data directory, all
    /// under one generous rate allowance so a test exercising several calls in a row is never
    /// the thing that trips the limiter it is not testing.
    fn service_with_accounts(label: &str) -> Service {
        service_shaped(label, "/report", Some(RP))
    }

    /// The same, but mounted at a route other than `/report` or with the passkey door turned
    /// off — the two pieces of a deployment's shape that `<route>/capabilities` reports and
    /// that the page's own relative references have to survive.
    fn service_shaped(label: &str, route: &str, rp_id: Option<&str>) -> Service {
        let dir = scratch_dir(&format!("accounts-{label}"));
        let store = Store::open(&dir.join("store")).expect("store");
        store.add_project("dx").expect("project");
        Service::new(
            store,
            Config {
                route: route.to_string(),
                accounts: Some(AccountsConfig {
                    data_dir: dir.join("accounts"),
                    site_name: "Test Reports".to_string(),
                    public_base_url: "https://reports.example.com".to_string(),
                    rp_id: rp_id.map(str::to_string),
                    oauth_providers: vec![oauth::Provider {
                        name: "example".to_string(),
                        authorize_url: "https://provider.example/authorize".to_string(),
                        token_url: "https://provider.example/token".to_string(),
                        userinfo_url: "https://provider.example/userinfo".to_string(),
                        client_id: "client-id".to_string(),
                        client_secret: "client-secret".to_string(),
                        scope: "email".to_string(),
                        subject_field: "sub".to_string(),
                        email_field: "email".to_string(),
                        email_verified_field: Some("email_verified".to_string()),
                    }],
                    verify_from: "reports@example.com".to_string(),
                    verify_helo: "example.com".to_string(),
                    mail_data_dir: Some(dir.join("mail")),
                    per_action: Rate::new(50, 3000.0),
                    global_action: Rate::new(500, 30_000.0),
                }),
                ..Config::default()
            },
        )
    }

    fn json_post(target: &str, body: &str) -> Request {
        request(&format!(
            "POST {target} HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ))
    }

    fn json_post_with_cookie(target: &str, body: &str, cookie: &str) -> Request {
        request(&format!(
            "POST {target} HTTP/1.1\r\nHost: x\r\nCookie: {cookie}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ))
    }

    fn get(target: &str) -> Request {
        request(&format!("GET {target} HTTP/1.1\r\nHost: x\r\n\r\n"))
    }

    fn get_with_cookie(target: &str, cookie: &str) -> Request {
        request(&format!(
            "GET {target} HTTP/1.1\r\nHost: x\r\nCookie: {cookie}\r\n\r\n"
        ))
    }

    /// A `GET` from a client that has said, in so many words, that JSON is what it came for —
    /// the one shape that still redeems a verification token on `GET`. See [`redeems_on_get`].
    fn get_json(target: &str) -> Request {
        get_with_header(target, "Accept", "application/json")
    }

    fn get_with_header(target: &str, name: &str, value: &str) -> Request {
        request(&format!(
            "GET {target} HTTP/1.1\r\nHost: x\r\n{name}: {value}\r\n\r\n"
        ))
    }

    /// A `POST` shaped the way a browser sends one: with the `Origin` of the page that made it.
    fn json_post_from(target: &str, body: &str, origin: &str) -> Request {
        request(&format!(
            "POST {target} HTTP/1.1\r\nHost: x\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ))
    }

    fn call(service: &Service, request: &Request, body: &str) -> Response {
        service.answer(
            request,
            body.as_bytes(),
            "203.0.113.9",
            Instant::now(),
            UNIX_EPOCH,
        )
    }

    /// The `Set-Cookie` value a response carries, as the bare `name=value` a follow-up request's
    /// own `Cookie` header wants — trimming everything after the first `;`.
    fn set_cookie(response: &Response) -> String {
        response
            .headers
            .get_str("set-cookie")
            .expect("a Set-Cookie header")
            .split(';')
            .next()
            .expect("at least the name=value")
            .to_string()
    }

    fn register(service: &Service, email: &str, password: &str) -> Response {
        let body = format!(r#"{{"email":"{email}","password":"{password}"}}"#);
        call(service, &json_post("/report/register", &body), &body)
    }

    fn login(service: &Service, email: &str, password: &str) -> Response {
        let body = format!(r#"{{"email":"{email}","password":"{password}"}}"#);
        call(service, &json_post("/report/login", &body), &body)
    }

    #[test]
    fn every_account_route_answers_404_when_accounts_are_not_configured() {
        let service = service("accounts-off");
        for (method_target, body) in [
            (
                "POST /report/register",
                r#"{"email":"a@example.com","password":"hunter2fish"}"#,
            ),
            (
                "POST /report/login",
                r#"{"email":"a@example.com","password":"hunter2fish"}"#,
            ),
            ("GET /report/me", ""),
            ("GET /report/mine", ""),
            ("POST /report/passkey/login/start", ""),
            ("GET /report/oauth/example/start", ""),
            ("GET /report/download", ""),
            ("GET /report/capabilities", ""),
            ("GET /report/", ""),
            ("GET /report/index.html", ""),
            ("GET /report/app.css", ""),
            ("GET /report/app.js", ""),
            ("GET /report/favicon.svg", ""),
        ] {
            let (method, target) = method_target.split_once(' ').unwrap();
            let head = if method == "GET" {
                get(target)
            } else {
                json_post(target, body)
            };
            let response = call(&service, &head, body);
            assert_eq!(
                response.status,
                Status::NOT_FOUND,
                "{method_target}: {}",
                text(&response)
            );
        }
    }

    #[test]
    fn registering_signs_in_and_a_second_registration_with_the_same_email_is_refused() {
        let service = service_with_accounts("register");
        let response = register(&service, "alex@example.com", "hunter2fish");
        assert_eq!(response.status, Status::OK, "{}", text(&response));
        let cookie = set_cookie(&response);
        assert!(cookie.starts_with("report_session="), "{cookie}");

        let again = register(&service, "Alex@Example.com", "differentpassword");
        assert_eq!(again.status, Status::BAD_REQUEST);
        assert!(text(&again).contains("already exists"), "{}", text(&again));
    }

    #[test]
    fn a_password_below_the_minimum_is_refused_before_an_account_is_created() {
        let service = service_with_accounts("weak-password");
        let response = register(&service, "alex@example.com", "short");
        assert_eq!(response.status, Status::BAD_REQUEST);
        assert_eq!(
            login(&service, "alex@example.com", "short").status,
            Status::UNAUTHORIZED
        );
    }

    #[test]
    fn logging_in_verifies_the_password_and_a_wrong_one_is_refused_uniformly() {
        let service = service_with_accounts("login");
        register(&service, "alex@example.com", "hunter2fish");

        let wrong_password = login(&service, "alex@example.com", "wrongpassword");
        assert_eq!(wrong_password.status, Status::UNAUTHORIZED);
        let no_such_account = login(&service, "nobody@example.com", "hunter2fish");
        assert_eq!(no_such_account.status, Status::UNAUTHORIZED);
        assert_eq!(
            text(&wrong_password),
            text(&no_such_account),
            "a wrong password and no such account must not be distinguishable"
        );

        let right = login(&service, "alex@example.com", "hunter2fish");
        assert_eq!(right.status, Status::OK);
        assert!(set_cookie(&right).starts_with("report_session="));
    }

    #[test]
    fn logging_out_ends_the_session_the_cookie_named() {
        let service = service_with_accounts("logout");
        let cookie = set_cookie(&register(&service, "alex@example.com", "hunter2fish"));

        let logged_out = call(
            &service,
            &json_post_with_cookie("/report/logout", "", &cookie),
            "",
        );
        assert_eq!(logged_out.status, Status::OK);
        let full_header = logged_out
            .headers
            .get_str("set-cookie")
            .expect("a Set-Cookie header");
        assert!(full_header.contains("Max-Age=0"), "{full_header}");

        let whoami = call(&service, &get_with_cookie("/report/me", &cookie), "");
        assert_eq!(
            whoami.status,
            Status::UNAUTHORIZED,
            "the ended session no longer authenticates"
        );
    }

    #[test]
    fn whoami_answers_the_signed_in_account_and_refuses_anyone_else() {
        let service = service_with_accounts("whoami");
        let cookie = set_cookie(&register(&service, "alex@example.com", "hunter2fish"));

        let anonymous = call(&service, &get("/report/me"), "");
        assert_eq!(anonymous.status, Status::UNAUTHORIZED);

        let mine = call(&service, &get_with_cookie("/report/me", &cookie), "");
        assert_eq!(mine.status, Status::OK);
        assert!(
            text(&mine).contains("\"email\":\"alex@example.com\""),
            "{}",
            text(&mine)
        );
        assert!(
            text(&mine).contains("\"emailVerified\":false"),
            "{}",
            text(&mine)
        );
    }

    #[test]
    fn the_download_route_needs_a_session() {
        let service = service_with_accounts("download-anon");
        let response = call(&service, &get("/report/download"), "");
        assert_eq!(response.status, Status::UNAUTHORIZED);
    }

    #[test]
    fn the_download_route_answers_the_archive_for_any_signed_in_account() {
        let service = service_with_accounts("download-any");
        let cookie = set_cookie(&register(&service, "alex@example.com", "hunter2fish"));

        let response = call(&service, &get_with_cookie("/report/download", &cookie), "");
        assert_eq!(response.status, Status::OK, "{}", text(&response));
        let body = text(&response);
        assert!(
            body.contains(
                "\"downloadUrl\":\"https://github.com/RockyWearsAHat/selfhost/archive/refs/heads/main.zip\""
            ),
            "{body}"
        );
        assert!(
            body.contains("\"repository\":\"https://github.com/RockyWearsAHat/selfhost\""),
            "{body}"
        );
        assert!(body.contains("\"branch\":\"main\""), "{body}");
        assert!(body.contains("cargo build --release"), "{body}");
    }

    #[test]
    fn the_landing_page_is_open_html_and_names_registering() {
        let service = service_with_accounts("landing-page");
        for target in ["/report/", "/report/index.html"] {
            let response = call(&service, &get(target), "");
            assert_eq!(response.status, Status::OK, "{target}: {}", text(&response));
            assert_eq!(
                response.headers.get_str("content-type"),
                Some("text/html; charset=utf-8"),
                "{target}"
            );
            assert!(
                text(&response).to_ascii_lowercase().contains("register"),
                "{target}: {}",
                text(&response)
            );
        }
    }

    /// The policy is asserted whole rather than by absence alone: `'unsafe-inline'` is the one
    /// this crate spent two dispatch arms to be rid of, so it gets its own assertion, but a
    /// policy that silently lost `base-uri 'none'` would be a regression nobody would notice
    /// from a test that only looked for what must not be there.
    #[test]
    fn the_pages_policy_names_this_origin_and_allows_no_inline_script_or_style() {
        let service = service_with_accounts("page-policy");
        for target in [
            "/report/",
            "/report/index.html",
            "/report/app.css",
            "/report/app.js",
            "/report/favicon.svg",
        ] {
            let response = call(&service, &get(target), "");
            assert_eq!(response.status, Status::OK, "{target}: {}", text(&response));
            let policy = response
                .headers
                .get_str("content-security-policy")
                .unwrap_or_default();
            assert!(
                !policy.contains("unsafe-inline"),
                "{target} may not allow an inline script or style: {policy}"
            );
            assert!(!policy.contains("unsafe-eval"), "{target}: {policy}");
            assert_eq!(
                policy,
                "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; \
                 img-src 'self' data:; form-action 'self'; frame-src 'none'; object-src 'none'; \
                 frame-ancestors 'none'; base-uri 'none'",
                "{target}"
            );
            assert_eq!(
                response.headers.get_str("x-content-type-options"),
                Some("nosniff"),
                "{target}"
            );
            assert_eq!(
                response.headers.get_str("x-frame-options"),
                Some("DENY"),
                "{target}"
            );
            assert_eq!(
                response.headers.get_str("referrer-policy"),
                Some("no-referrer"),
                "{target}"
            );
        }
    }

    #[test]
    fn the_page_is_three_files_of_its_own_under_whatever_route_is_configured() {
        let service = service_shaped("assets-elsewhere", "/bugs", Some(RP));
        for (target, content_type) in [
            ("/bugs/", "text/html; charset=utf-8"),
            ("/bugs/index.html", "text/html; charset=utf-8"),
            ("/bugs/app.css", "text/css; charset=utf-8"),
            ("/bugs/app.js", "text/javascript; charset=utf-8"),
            ("/bugs/favicon.svg", "image/svg+xml"),
        ] {
            let response = call(&service, &get(target), "");
            assert_eq!(response.status, Status::OK, "{target}: {}", text(&response));
            assert_eq!(
                response.headers.get_str("content-type"),
                Some(content_type),
                "{target}"
            );
            assert!(!text(&response).is_empty(), "{target} served nothing");
        }
        // The other half of the contract: the shell names its two files relatively, so that
        // serving them at `<route>/app.css` and `<route>/app.js` is what the browser asks for
        // wherever this crate is mounted. A rename on either side breaks here rather than in a
        // browser.
        let shell = text(&call(&service, &get("/bugs/"), ""));
        assert!(shell.contains("\"app.css\""), "the shell must link app.css");
        assert!(shell.contains("\"app.js\""), "the shell must load app.js");
        assert!(
            !shell.contains("/bugs/app.js"),
            "an absolute reference would bake the route into the page"
        );
        assert!(
            text(&call(&service, &get("/bugs/favicon.svg"), "")).contains("<svg"),
            "the icon must actually be SVG, since its content type says so"
        );
    }

    #[test]
    fn an_asset_the_browser_already_has_is_answered_without_sending_it_again() {
        let service = service_with_accounts("asset-revalidation");
        let first = call(&service, &get("/report/app.js"), "");
        assert_eq!(first.status, Status::OK);
        assert_eq!(
            first.headers.get_str("cache-control"),
            Some("no-cache, must-revalidate"),
            "a stale asset must be impossible, a cheap reload merely likely"
        );
        let tag = first.headers.get_str("etag").expect("an ETag").to_string();
        assert!(!text(&first).is_empty());

        let again = call(
            &service,
            &get_with_header("/report/app.js", "If-None-Match", &tag),
            "",
        );
        assert_eq!(again.status, Status::NOT_MODIFIED);
        assert!(text(&again).is_empty(), "a 304 carries no body");
        assert_eq!(again.headers.get_str("etag"), Some(tag.as_str()));

        let stale = call(
            &service,
            &get_with_header("/report/app.js", "If-None-Match", "\"0000000000000000\""),
            "",
        );
        assert_eq!(
            stale.status,
            Status::OK,
            "a tag that is not this file's gets the file"
        );
        // Two different files must never share a tag, or one would be served for the other out
        // of a browser's cache.
        let stylesheet = call(&service, &get("/report/app.css"), "");
        assert_ne!(stylesheet.headers.get_str("etag"), Some(tag.as_str()));
    }

    #[test]
    fn capabilities_states_what_this_box_offers_and_the_bounds_it_will_enforce() {
        let service = service_with_accounts("capabilities");
        let response = call(&service, &get("/report/capabilities"), "");
        assert_eq!(response.status, Status::OK, "{}", text(&response));
        let body = text(&response);
        let value = selfhost_json::parse(&body).expect("JSON");
        assert_eq!(value.get("accounts").and_then(Json::as_bool), Some(true));
        assert_eq!(
            value.get("passkeys").and_then(Json::as_bool),
            Some(true),
            "this box was configured with an rp_id"
        );
        assert_eq!(
            value.get("mailConfigured").and_then(Json::as_bool),
            Some(true)
        );
        assert_eq!(value.get("route").and_then(Json::as_str), Some("/report"));
        assert!(
            body.contains("\"oauthProviders\":[\"example\"]"),
            "the one configured provider, by name: {body}"
        );

        // Every bound is the constant that actually enforces it, so a page cannot promise one
        // number while the door refuses at another.
        let limits = value.get("limits").expect("limits");
        for (key, expected) in [
            ("passwordMin", accounts::MIN_PASSWORD),
            ("passwordMax", accounts::MAX_PASSWORD),
            ("titleMax", report::MAX_TITLE),
            ("detailMax", report::MAX_DETAIL),
            ("reproMax", report::MAX_REPRO),
            ("passkeysPerAccount", webauthn::MAX_PASSKEYS_PER_ACCOUNT),
            ("maxAccounts", accounts::MAX_ACCOUNTS),
            ("maxProjects", store::MAX_PROJECTS),
        ] {
            assert_eq!(
                limits.get(key).and_then(Json::as_u64),
                Some(expected as u64),
                "{key}"
            );
        }
        // It says nothing about who is registered — the whole reason it can be open.
        register(&service, "alex@example.com", "hunter2fish");
        let after = text(&call(&service, &get("/report/capabilities"), ""));
        assert_eq!(
            after, body,
            "a registration changes nothing this route says"
        );
    }

    #[test]
    fn capabilities_reports_a_door_that_is_not_configured_as_absent_rather_than_broken() {
        let service = service_shaped("capabilities-no-rp", "/report", None);
        let value = selfhost_json::parse(&text(&call(&service, &get("/report/capabilities"), "")))
            .expect("JSON");
        assert_eq!(
            value.get("passkeys").and_then(Json::as_bool),
            Some(false),
            "with no rp_id the passkey routes 404, so the page must not draw the button"
        );
        assert_eq!(
            call(&service, &json_post("/report/passkey/login/start", ""), "").status,
            Status::NOT_FOUND,
            "which is exactly what pressing it would have got"
        );
    }

    /// It used to spend the *reading* allowance, which was right about which bucket it must not
    /// be on (the account door's) and wrong about which one it belongs to: ten tokens is five
    /// page loads, and the sixth served every file and refused this, which the page draws as a
    /// box with no passkeys and no providers. It is on the page visit's budget now.
    #[test]
    fn capabilities_spends_the_page_visit_allowance_and_not_the_account_doors() {
        let service = service_with_accounts("capabilities-allowance");
        // `service_with_accounts` gives the account door a generous allowance; the page one is
        // `Config::default`'s hundred and twenty. Spending the page bucket dry must leave
        // signing in possible, which is the whole reason this route is not counted with the
        // credential doors.
        let mut refused = false;
        for _ in 0..300 {
            let response = call(&service, &get("/report/capabilities"), "");
            if response.status == Status::TOO_MANY_REQUESTS {
                refused = true;
                break;
            }
        }
        assert!(
            refused,
            "an unlimited open route is not a route, it is a hole"
        );
        assert_eq!(
            register(&service, "alex@example.com", "hunter2fish").status,
            Status::OK,
            "a page that reloaded too often must not lock its own user out of the door"
        );
        // Nor did it spend the owner's reading allowance on the way — that bucket is ten deep
        // and exists to make the token expensive to guess, not to carry a login page.
        let feed = call(
            &service,
            &get_with_header("/report/feed?dx", "Authorization", "Bearer secret-token"),
            "",
        );
        assert_ne!(
            feed.status,
            Status::TOO_MANY_REQUESTS,
            "a stranger reloading the page must not close the owner's feed"
        );
    }

    #[test]
    fn a_browser_asking_for_the_bare_route_is_sent_to_the_page_and_no_other_client_is() {
        let service = service_with_accounts("bare-route");
        let browser = call(
            &service,
            &get_with_header(
                "/report",
                "Accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
            "",
        );
        assert_eq!(browser.status, Status::PERMANENT_REDIRECT);
        assert_eq!(browser.headers.get_str("location"), Some("/report/"));

        for accept in ["*/*", "application/json"] {
            let client = call(&service, &get_with_header("/report", "Accept", accept), "");
            assert_eq!(client.status, Status::METHOD_NOT_ALLOWED, "{accept}");
            assert!(
                text(&client).contains("file a report with POST"),
                "{accept}: {}",
                text(&client)
            );
        }
        let no_accept = call(&service, &get("/report"), "");
        assert_eq!(no_accept.status, Status::METHOD_NOT_ALLOWED);
        assert!(text(&no_accept).contains("file a report with POST"));

        // Only `GET`: a filing is still a filing whatever the client will render.
        let filed = call(
            &service,
            &request(&format!(
                "POST /report HTTP/1.1\r\nHost: x\r\nAccept: text/html\r\nContent-Length: {}\r\n\r\n",
                r#"{"kind":"bug","title":"typed it in","detail":"the words"}"#.len()
            )),
            r#"{"kind":"bug","title":"typed it in","detail":"the words"}"#,
        );
        assert_eq!(filed.status, Status::OK, "{}", text(&filed));
    }

    /// The other half of the redirect above: with accounts off there is no page at `<route>/`
    /// — it is a `404` like every other account route — and sending a person from an answer
    /// that says what to do to one that says nothing is worse than the refusal it replaced.
    #[test]
    fn a_box_with_no_page_to_land_on_redirects_nobody() {
        let intake = service("bare-route-no-accounts");
        let response = call(
            &intake,
            &get_with_header("/report", "Accept", "text/html"),
            "",
        );
        assert_eq!(response.status, Status::METHOD_NOT_ALLOWED);
        assert!(text(&response).contains("file a report with POST"));
        assert_eq!(
            call(&intake, &get("/report/"), "").status,
            Status::NOT_FOUND,
            "which is where the redirect would have sent them"
        );
    }

    #[test]
    fn a_post_from_another_site_is_refused_and_one_carrying_no_origin_is_not() {
        let service = service_with_accounts("cross-origin");
        let body = r#"{"email":"alex@example.com","password":"hunter2fish"}"#;

        let foreign = call(
            &service,
            &json_post_from("/report/register", body, "https://evil.example"),
            body,
        );
        assert_eq!(foreign.status, Status::FORBIDDEN, "{}", text(&foreign));
        assert!(
            text(&foreign).contains("another site"),
            "{}",
            text(&foreign)
        );
        assert_eq!(
            login(&service, "alex@example.com", "hunter2fish").status,
            Status::UNAUTHORIZED,
            "the refusal happened before anything was created"
        );

        // This box's own page, in the spelling a browser sends and in a louder one.
        for origin in ["https://reports.example.com", "HTTPS://Reports.Example.COM"] {
            let mine = call(&service, &json_post_from("/report/logout", "", origin), "");
            assert_eq!(mine.status, Status::OK, "{origin}: {}", text(&mine));
        }

        // No `Origin` at all is curl, the CLI, and every agent this endpoint was built for.
        assert_eq!(
            register(&service, "alex@example.com", "hunter2fish").status,
            Status::OK
        );

        // A `GET` is not a submission: a cross-site read of an open route was always allowed
        // and refusing it here would only break the page's own navigation.
        let read = call(
            &service,
            &get_with_header("/report/capabilities", "Origin", "https://evil.example"),
            "",
        );
        assert_eq!(read.status, Status::OK, "{}", text(&read));
    }

    #[test]
    fn an_origin_is_a_scheme_and_an_authority_and_never_a_path() {
        assert_eq!(
            origin_of("https://reports.example.com").as_deref(),
            Some("https://reports.example.com")
        );
        assert_eq!(
            origin_of("https://reports.example.com/base/path?x=1").as_deref(),
            Some("https://reports.example.com"),
            "a configured base URL may carry a path; an Origin header never does"
        );
        assert_eq!(
            origin_of("http://127.0.0.1:8734").as_deref(),
            Some("http://127.0.0.1:8734"),
            "the port is part of the origin"
        );
        assert_eq!(origin_of("reports.example.com"), None);
        assert_eq!(origin_of("https://"), None);
    }

    /// The three dispatch lists — the rate-limit `matches!`, the handler arms, and the two
    /// method-refusal groups — have to move together. A suffix left out of the last one exists
    /// for `GET` and answers `404 "no such endpoint"` for everything else, which is this
    /// crate's sentence for *accounts are turned off*: a client would read a wrong method as a
    /// box with no account door at all.
    #[test]
    fn every_new_page_route_answers_a_method_refusal_rather_than_a_misleading_404() {
        let service = service_with_accounts("method-walk");
        for suffix in [
            "capabilities",
            "",
            "index.html",
            "app.css",
            "app.js",
            "favicon.svg",
        ] {
            for method in ["GET", "POST", "PUT", "DELETE"] {
                let head = request(&format!(
                    "{method} /report/{suffix} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"
                ));
                let response = call(&service, &head, "");
                if method == "GET" {
                    assert_eq!(
                        response.status,
                        Status::OK,
                        "GET /report/{suffix}: {}",
                        text(&response)
                    );
                    continue;
                }
                assert_eq!(
                    response.status,
                    Status::METHOD_NOT_ALLOWED,
                    "{method} /report/{suffix}: {}",
                    text(&response)
                );
                assert!(
                    text(&response).contains("takes GET"),
                    "{method} /report/{suffix}: {}",
                    text(&response)
                );
                assert!(
                    !text(&response).contains("no such endpoint"),
                    "{method} /report/{suffix} must not read as accounts being off"
                );
            }
        }
    }

    #[test]
    fn changing_the_password_signs_out_every_other_session() {
        let service = service_with_accounts("rotate");
        let first = set_cookie(&register(&service, "alex@example.com", "hunter2fish"));
        let second = set_cookie(&login(&service, "alex@example.com", "hunter2fish"));
        assert_ne!(first, second, "two logins mint two distinct sessions");

        let changed = call(
            &service,
            &json_post_with_cookie(
                "/report/me/password",
                r#"{"password":"brandnewpassword"}"#,
                &first,
            ),
            r#"{"password":"brandnewpassword"}"#,
        );
        assert_eq!(changed.status, Status::OK, "{}", text(&changed));

        assert_eq!(
            call(&service, &get_with_cookie("/report/me", &second), "").status,
            Status::UNAUTHORIZED,
            "the other session was ended by the rotation"
        );
        assert_eq!(
            login(&service, "alex@example.com", "hunter2fish").status,
            Status::UNAUTHORIZED
        );
        assert_eq!(
            login(&service, "alex@example.com", "brandnewpassword").status,
            Status::OK
        );
    }

    #[test]
    fn filing_with_a_session_attributes_the_report_and_lists_it_under_mine() {
        let service = service_with_accounts("attribution");
        let cookie = set_cookie(&register(&service, "alex@example.com", "hunter2fish"));

        let filed = file_with_cookie(
            &service,
            r#"{"kind":"bug","title":"attributed","detail":"d"}"#,
            "203.0.113.9",
            &cookie,
        );
        assert_eq!(filed.status, Status::OK, "{}", text(&filed));

        let mine = call(&service, &get_with_cookie("/report/mine", &cookie), "");
        assert_eq!(mine.status, Status::OK);
        assert!(text(&mine).contains("attributed"), "{}", text(&mine));

        // Filed with no session at all: unaffected, as it always was.
        let anonymous = file(
            &service,
            r#"{"kind":"bug","title":"anonymous","detail":"d"}"#,
            "203.0.113.9",
        );
        assert_eq!(anonymous.status, Status::OK);
        let entries = service.store().list("dx").expect("list");
        let anon_entry = entries
            .iter()
            .find(|entry| entry.title == "anonymous")
            .expect("found");
        assert!(anon_entry.account_id.is_none());
    }

    #[test]
    fn an_account_can_withdraw_its_own_report_but_not_anyone_elses() {
        let service = service_with_accounts("withdraw");
        let owner_cookie = set_cookie(&register(&service, "owner@example.com", "hunter2fish"));
        let stranger_cookie =
            set_cookie(&register(&service, "stranger@example.com", "hunter2fish"));

        file_with_cookie(
            &service,
            r#"{"kind":"bug","title":"mine to withdraw","detail":"d"}"#,
            "203.0.113.9",
            &owner_cookie,
        );
        let id = service.store().list("dx").expect("list")[0].id.clone();
        let withdraw_body = format!(r#"{{"project":"dx","id":"{id}"}}"#);

        let by_stranger = call(
            &service,
            &json_post_with_cookie("/report/mine/withdraw", &withdraw_body, &stranger_cookie),
            &withdraw_body,
        );
        assert_eq!(
            by_stranger.status,
            Status::NOT_FOUND,
            "not this account's report"
        );
        assert_eq!(
            service.store().list("dx").expect("list").len(),
            1,
            "still there"
        );

        let by_owner = call(
            &service,
            &json_post_with_cookie("/report/mine/withdraw", &withdraw_body, &owner_cookie),
            &withdraw_body,
        );
        assert_eq!(by_owner.status, Status::OK, "{}", text(&by_owner));
        assert!(service.store().list("dx").expect("list").is_empty());
    }

    /// The JSON contract on `GET <route>/verify`, which is now reached only by a client that
    /// asked for JSON — see [`redeems_on_get`], and the test below it for everything that
    /// no longer reaches it.
    #[test]
    fn a_verification_link_confirms_the_email_exactly_once() {
        let service = service_with_accounts("verify");
        register(&service, "alex@example.com", "hunter2fish");

        let token = spooled_verification_token(&service);
        let verified = call(
            &service,
            &get_json(&format!("/report/verify?token={token}")),
            "",
        );
        assert_eq!(verified.status, Status::OK, "{}", text(&verified));

        let replayed = call(
            &service,
            &get_json(&format!("/report/verify?token={token}")),
            "",
        );
        assert_eq!(
            replayed.status,
            Status::BAD_REQUEST,
            "a verification link is single-use"
        );

        let cookie = set_cookie(&login(&service, "alex@example.com", "hunter2fish"));
        let whoami = call(&service, &get_with_cookie("/report/me", &cookie), "");
        assert!(
            text(&whoami).contains("\"emailVerified\":true"),
            "{}",
            text(&whoami)
        );
    }

    /// A mail gateway's prefetch and the person's own click are the same `GET`, so that `GET`
    /// must not spend anything. It is answered with the page — the exact shell `<route>/`
    /// serves, with nothing built per request and in particular nothing from the query in it —
    /// and the token is still there afterwards for whoever the mail was actually addressed to.
    ///
    /// The JSON half of the same route is unchanged in the same test, deliberately: this is the
    /// one behaviour where "a browser gets something else" could quietly have become "everybody
    /// gets something else".
    #[test]
    fn a_browser_opening_the_verification_link_is_shown_the_page_and_spends_no_token() {
        let service = service_with_accounts("verify-page");
        register(&service, "alex@example.com", "hunter2fish");
        let token = spooled_verification_token(&service);
        let target = format!("/report/verify?token={token}");

        let page = call(
            &service,
            &get_with_header(
                &target,
                "Accept",
                "text/html,application/xhtml+xml,*/*;q=0.8",
            ),
            "",
        );
        assert_eq!(page.status, Status::OK, "{}", text(&page));
        assert_eq!(
            page.headers.get_str("content-type").unwrap_or_default(),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            text(&page),
            LANDING_PAGE,
            "the same shell, byte for byte — this route builds no markup of its own"
        );
        assert!(
            !text(&page).contains(&token),
            "the token is read by the page from its own address, never written into the markup"
        );

        // Three more prefetches, exactly as a link checker in front of an inbox makes them.
        for _ in 0..3 {
            let prefetched = call(
                &service,
                &get_with_header(&target, "Accept", "text/html"),
                "",
            );
            assert_eq!(prefetched.status, Status::OK);
        }

        // And every other client still redeems on the same address, byte for byte.
        let redeemed = call(
            &service,
            &get_with_header(&target, "Accept", "application/json"),
            "",
        );
        assert_eq!(redeemed.status, Status::OK, "{}", text(&redeemed));
        assert_eq!(text(&redeemed), r#"{"verified":true}"#);
    }

    /// The four callers the first attempt at this fix missed, and the one it got right.
    ///
    /// Serving the page only to `Accept: text/html` left every *other* non-browser fetcher
    /// still redeeming — and the ones that matter are precisely the ones that do not ask for
    /// HTML: a mail gateway's link checker sends `*/*` or no `Accept` at all, and a
    /// `<img src="…/verify?token=…">` planted in a mail body makes the recipient's own browser
    /// fetch the address with an image `Accept` that names no HTML anywhere. Each of those
    /// burned the single-use token before the person clicked their link. So the rule is
    /// inverted: the safe answer is the default one, and only an explicit `application/json`
    /// redeems. That last case is asserted *last*, on the same token, which is the proof the
    /// others really did spend nothing.
    #[test]
    fn only_a_caller_that_asks_for_json_spends_the_token_on_a_get() {
        let service = service_with_accounts("verify-accept");
        register(&service, "alex@example.com", "hunter2fish");
        let token = spooled_verification_token(&service);
        let target = format!("/report/verify?token={token}");

        // No `Accept` header at all — curl's `-H 'Accept:'`, most link checkers, and any
        // client that never thought about it.
        let bare = call(&service, &get(&target), "");
        assert_eq!(bare.status, Status::OK, "{}", text(&bare));
        assert_eq!(
            text(&bare),
            LANDING_PAGE,
            "a request with no `Accept` gets the page"
        );

        for (label, accept) in [
            // The gateway that will take anything.
            ("*/*", "*/*"),
            // Chrome's exact `Accept` for an `<img src>` subresource — no `text/html` in it.
            (
                "a planted <img src>",
                "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
            ),
            // A browser navigating, the one case the first attempt did cover.
            (
                "a browser navigating",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
            // Both named: this is a browser, and a browser gets the page.
            ("both named", "text/html,application/json"),
        ] {
            let answered = call(&service, &get_with_header(&target, "Accept", accept), "");
            assert_eq!(answered.status, Status::OK, "{label}");
            assert_eq!(text(&answered), LANDING_PAGE, "{label} must get the page");
        }

        // Nothing above spent anything, which this proves: the token is still redeemable, and
        // the JSON answer is byte for byte the one the contract has always had.
        let redeemed = call(&service, &get_json(&target), "");
        assert_eq!(redeemed.status, Status::OK, "{}", text(&redeemed));
        assert_eq!(text(&redeemed), r#"{"verified":true}"#);

        // And having been spent once, it is spent.
        let replayed = call(&service, &get_json(&target), "");
        assert_eq!(replayed.status, Status::BAD_REQUEST);
    }

    /// The page's own half: `POST <route>/verify/confirm`, which a prefetcher does not make.
    /// Single-use is still single-use, and the two refusals are the ones the `GET` already gave.
    #[test]
    fn the_page_spends_the_verification_token_with_a_post_and_only_once() {
        let service = service_with_accounts("verify-confirm");
        register(&service, "alex@example.com", "hunter2fish");
        let token = spooled_verification_token(&service);
        let body = format!(r#"{{"token":"{token}"}}"#);

        let confirmed = call(&service, &json_post("/report/verify/confirm", &body), &body);
        assert_eq!(confirmed.status, Status::OK, "{}", text(&confirmed));
        assert_eq!(text(&confirmed), r#"{"verified":true}"#);

        let replayed = call(&service, &json_post("/report/verify/confirm", &body), &body);
        assert_eq!(
            replayed.status,
            Status::BAD_REQUEST,
            "a verification token is single-use whichever door spends it"
        );
        assert!(
            text(&replayed).contains("this verification link is invalid or has expired"),
            "{}",
            text(&replayed)
        );

        let empty = call(&service, &json_post("/report/verify/confirm", "{}"), "{}");
        assert_eq!(empty.status, Status::BAD_REQUEST);
        assert!(
            text(&empty).contains("`token` is required"),
            "the same sentence the `GET` gives a link with no token: {}",
            text(&empty)
        );

        let cookie = set_cookie(&login(&service, "alex@example.com", "hunter2fish"));
        let whoami = call(&service, &get_with_cookie("/report/me", &cookie), "");
        assert!(
            text(&whoami).contains("\"emailVerified\":true"),
            "{}",
            text(&whoami)
        );
    }

    /// The verifying half of a ceremony used to be the free half: a `start` hands out a
    /// challenge and a `finish` checks a signature, and only the first cost anything. A
    /// verification token is a credential too, and guessing at one is guessing.
    #[test]
    fn the_verifying_half_of_a_ceremony_costs_the_account_doors_allowance_too() {
        let dir = scratch_dir("accounts-finish-rate");
        let store = Store::open(&dir.join("store")).expect("store");
        store.add_project("dx").expect("project");
        let service = Service::new(
            store,
            Config {
                accounts: Some(AccountsConfig {
                    data_dir: dir.join("accounts"),
                    site_name: "Test Reports".to_string(),
                    public_base_url: "https://reports.example.com".to_string(),
                    rp_id: Some(RP.to_string()),
                    oauth_providers: Vec::new(),
                    verify_from: "reports@example.com".to_string(),
                    verify_helo: "example.com".to_string(),
                    mail_data_dir: None,
                    per_action: Rate::new(2, 3.0),
                    global_action: Rate::new(200, 300.0),
                }),
                ..Config::default()
            },
        );
        let now = Instant::now();
        for (index, (label, target, body)) in [
            (
                "a passkey registration's verifying half",
                "/report/passkey/register/finish",
                "{}",
            ),
            (
                "a passkey sign-in's verifying half",
                "/report/passkey/login/finish",
                "{}",
            ),
            (
                "a verification token spent by the page",
                "/report/verify/confirm",
                r#"{"token":"not-a-real-token"}"#,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            // A fresh address each time: this proves the per-source wall, not a shared one.
            let client = format!("198.51.100.{}", index + 1);
            let mut last = Status::OK;
            for _ in 0..3 {
                last = service
                    .answer(
                        &json_post(target, body),
                        body.as_bytes(),
                        &client,
                        now,
                        UNIX_EPOCH,
                    )
                    .status;
            }
            assert_eq!(last, Status::TOO_MANY_REQUESTS, "{label} is unmetered");
        }

        // The link's own address counts too when it is actually redeeming, and it is a `GET`.
        let mut last = Status::OK;
        for _ in 0..3 {
            last = service
                .answer(
                    &get_json("/report/verify?token=not-a-real-token"),
                    b"",
                    "198.51.100.9",
                    now,
                    UNIX_EPOCH,
                )
                .status;
        }
        assert_eq!(last, Status::TOO_MANY_REQUESTS, "the redeem is unmetered");

        // And the *page* half of the same address does not, from a fresh address that has
        // spent nothing: it is a static file, and metering it on the account door meant a
        // corporate gateway prefetching the link could hand the human behind the same egress
        // address a `429` on their first and only click. `per_action` here is two.
        for attempt in 0..6 {
            let served = service.answer(
                &get("/report/verify?token=not-a-real-token"),
                b"",
                "198.51.100.10",
                now,
                UNIX_EPOCH,
            );
            assert_eq!(
                served.status,
                Status::OK,
                "attempt {attempt}: the landing page is metered on the account door"
            );
        }
    }

    /// Reads the verification token out of the one message the intake just spooled — the
    /// email a real inbox would receive, without a real mail server in this test.
    ///
    /// The queue is found by asking the service where it spools, rather than by rebuilding the
    /// fixture's path from its label a second time. Now that [`scratch_dir`] makes each
    /// fixture's directory unique, rebuilding it is not merely duplication — it is wrong.
    fn spooled_verification_token(service: &Service) -> String {
        let queue_dir = service
            .config()
            .accounts
            .as_ref()
            .expect("accounts are configured")
            .mail_data_dir
            .as_ref()
            .expect("a spool directory")
            .join("mail")
            .join("queue");
        let entry = std::fs::read_dir(&queue_dir)
            .unwrap_or_else(|error| panic!("{}: {error}", queue_dir.display()))
            .filter_map(Result::ok)
            .next()
            .expect("one spooled message");
        let raw = std::fs::read_to_string(entry.path()).expect("read");
        raw.split("token=")
            .nth(1)
            .expect("a token in the message")
            .split_whitespace()
            .next()
            .expect("the token's own characters")
            .trim()
            .to_string()
    }

    #[test]
    fn passkey_registration_and_login_round_trip_through_the_http_routes() {
        let service = service_with_accounts("passkey");
        let device = Authenticator::new("credential-1");

        let started = call(
            &service,
            &json_post(
                "/report/passkey/register/start",
                r#"{"email":"alex@example.com"}"#,
            ),
            r#"{"email":"alex@example.com"}"#,
        );
        assert_eq!(started.status, Status::OK, "{}", text(&started));
        let challenge = challenge_value(&started);

        let finish_body = device.register_body_json(&challenge, "phone");
        let finished = call(
            &service,
            &json_post("/report/passkey/register/finish", &finish_body),
            &finish_body,
        );
        assert_eq!(finished.status, Status::OK, "{}", text(&finished));
        let registered_cookie = set_cookie(&finished);

        let login_started = call(&service, &json_post("/report/passkey/login/start", ""), "");
        assert_eq!(login_started.status, Status::OK);
        let login_challenge = challenge_value(&login_started);
        let login_body = device.login_body_json(&login_challenge);
        let login_finished = call(
            &service,
            &json_post("/report/passkey/login/finish", &login_body),
            &login_body,
        );
        assert_eq!(
            login_finished.status,
            Status::OK,
            "{}",
            text(&login_finished)
        );

        // Both sessions authenticate the same account.
        let via_registration = call(
            &service,
            &get_with_cookie("/report/me", &registered_cookie),
            "",
        );
        let via_login_cookie = set_cookie(&login_finished);
        let via_login = call(
            &service,
            &get_with_cookie("/report/me", &via_login_cookie),
            "",
        );
        assert_eq!(
            json_field(&text(&via_registration), "id"),
            json_field(&text(&via_login), "id"),
            "one passkey, one account, however it signed in"
        );
    }

    #[test]
    fn oauth_start_redirects_with_pkce_and_an_unknown_provider_is_404() {
        let service = service_with_accounts("oauth-start");
        let started = call(&service, &get("/report/oauth/example/start"), "");
        assert_eq!(started.status, Status::FOUND, "{}", text(&started));
        let location = started
            .headers
            .get_str("location")
            .expect("a Location header");
        assert!(
            location.starts_with("https://provider.example/authorize?"),
            "{location}"
        );
        assert!(
            location.contains("code_challenge_method=S256"),
            "{location}"
        );
        assert!(location.contains("redirect_uri=https%3A%2F%2Freports.example.com%2Freport%2Foauth%2Fexample%2Fcallback"), "{location}");

        let unknown = call(&service, &get("/report/oauth/nope/start"), "");
        assert_eq!(unknown.status, Status::NOT_FOUND);
    }

    /// The `state` in the redirect and the cookie beside it are two halves of one binding: the
    /// start route must hand out both, or the callback it leads to can never succeed.
    #[test]
    fn oauth_start_binds_the_attempt_to_the_browser_it_redirected() {
        let service = service_with_accounts("oauth-nonce-cookie");
        let started = call(&service, &get("/report/oauth/example/start"), "");
        let cookie = started
            .headers
            .get_str("set-cookie")
            .expect("a Set-Cookie header");
        assert!(
            cookie.starts_with(&format!("{}=", oauth::NONCE_COOKIE_NAME)),
            "{cookie}"
        );
        assert!(cookie.contains("HttpOnly"), "{cookie}");
        assert!(cookie.contains("SameSite=Lax"), "{cookie}");
        assert!(cookie.contains("Path=/report"), "{cookie}");
        assert!(
            cookie.contains("Secure"),
            "this test's public base URL is https, so the cookie says so: {cookie}"
        );
    }

    /// Login CSRF: a `state` that is genuinely live but was not started by *this* browser is
    /// worth nothing, and says nothing — the refusal is the same sentence an unknown or expired
    /// `state` gets.
    ///
    /// Only the refusals are proven end to end here. The matching success — the same `state`
    /// with the cookie the redirect actually set — cannot finish at this layer without reaching
    /// the provider over the network; that the right cookie redeems the attempt is proven in
    /// `crate::oauth`'s own tests, against the pool that decides it.
    #[tokio::test]
    async fn an_oauth_callback_from_a_browser_that_did_not_start_the_attempt_is_refused() {
        let service = service_with_accounts("oauth-nonce-callback");
        let started = call(&service, &get("/report/oauth/example/start"), "");
        let location = started
            .headers
            .get_str("location")
            .expect("a Location header");
        let state = location
            .split("&state=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .expect("the redirect carries a state");
        let expired = "this sign-in attempt has expired — start again";

        let target =
            format!("/report/oauth/example/callback?code=an-authorization-code&state={state}");
        for (label, request) in [
            ("no cookie at all", get(&target)),
            (
                "somebody else's cookie",
                get_with_cookie(
                    &target,
                    &format!("{}=not-the-one", oauth::NONCE_COOKIE_NAME),
                ),
            ),
            (
                "only a session cookie",
                get_with_cookie(&target, "report_session=whatever"),
            ),
        ] {
            let refused = service
                .answer_async(&request, b"", "203.0.113.9", Instant::now(), UNIX_EPOCH)
                .await;
            assert_eq!(refused.status, Status::BAD_REQUEST, "{label}");
            assert!(
                text(&refused).contains(expired),
                "{label}: {}",
                text(&refused)
            );
        }
    }

    /// A `Set-Cookie` with its one variable part — the opaque session id — replaced, so two
    /// separate mints of the same cookie can be compared byte for byte. Everything a cookie's
    /// safety is actually made of (`HttpOnly`, `Secure`, `SameSite`, `Path`, `Max-Age`) is in
    /// the part this keeps.
    fn cookie_shape(response: &Response) -> String {
        let header = response
            .headers
            .get_str("set-cookie")
            .expect("a Set-Cookie header");
        let (name, rest) = header.split_once('=').expect("name=value");
        let attributes = rest.find(';').map(|at| &rest[at..]).unwrap_or_default();
        format!("{name}=<id>{attributes}")
    }

    /// A browser that finished a provider sign-in is sent to the page rather than shown the
    /// JSON, and the session it lands with is the *same* session an API client would have got:
    /// both answers are built from one `session_cookie`, so a cookie cannot end up `Secure` on
    /// one path and not the other.
    #[test]
    fn a_browser_that_finished_a_sign_in_is_sent_to_the_page_carrying_the_same_cookie() {
        let service = service_with_accounts("oauth-landing");
        let runtime = service.accounts.as_ref().expect("accounts are on");
        register(&service, "alex@example.com", "hunter2fish");
        let account = runtime
            .accounts
            .find_by_email(&selfhost_mail::Address::parse("alex@example.com").unwrap())
            .expect("registered");

        let api = service.session_response(runtime, &account.id);
        let browser = service.session_redirect(runtime, &account.id);

        assert_eq!(api.status, Status::OK, "{}", text(&api));
        assert_eq!(
            text(&api),
            r#"{"signedIn":true}"#,
            "the JSON contract is untouched"
        );
        assert_eq!(browser.status, SEE_OTHER);
        assert_eq!(
            browser.headers.get_str("location").unwrap_or_default(),
            "/report/?signedin=1",
            "built from the configured route and from nothing a caller sent"
        );
        assert_eq!(
            cookie_shape(&browser),
            cookie_shape(&api),
            "one cookie, two bodies"
        );
        assert!(
            browser
                .headers
                .get_str("cache-control")
                .is_some_and(|value| value.contains("no-store")),
            "a redirect carrying a session cookie must not be cached"
        );

        // And it is a live session, not a well-shaped string.
        let cookie = set_cookie(&browser);
        let whoami = call(&service, &get_with_cookie("/report/me", &cookie), "");
        assert_eq!(whoami.status, Status::OK, "{}", text(&whoami));
    }

    /// Every way the callback can fail sends a browser to the page with one of the five codes
    /// `assets/app.js` has a written sentence for — and sends every other client the exact
    /// status and sentence it has always had.
    #[tokio::test]
    async fn a_failed_sign_in_lands_a_browser_on_the_page_and_leaves_every_other_client_alone() {
        let service = service_with_accounts("oauth-landing-error");
        let answered = |request: Request| {
            let service = &service;
            async move {
                service
                    .answer_async(&request, b"", "203.0.113.9", Instant::now(), UNIX_EPOCH)
                    .await
            }
        };

        for (label, target, code, status, sentence) in [
            (
                "a provider this box does not have",
                "/report/oauth/nope/callback?code=c&state=s",
                SIGNIN_UNKNOWN_PROVIDER,
                Status::NOT_FOUND,
                "no such sign-in provider is configured",
            ),
            (
                "a callback that came back without a code",
                "/report/oauth/example/callback?state=s",
                SIGNIN_EXPIRED,
                Status::BAD_REQUEST,
                "the provider did not return `code` and `state`",
            ),
            (
                "a state this box no longer holds",
                "/report/oauth/example/callback?code=c&state=long-gone",
                SIGNIN_EXPIRED,
                Status::BAD_REQUEST,
                "this sign-in attempt has expired — start again",
            ),
        ] {
            let browser = answered(get_with_header(target, "Accept", "text/html")).await;
            assert_eq!(browser.status, SEE_OTHER, "{label}");
            assert_eq!(
                browser.headers.get_str("location").unwrap_or_default(),
                format!("/report/?signin_error={code}"),
                "{label}"
            );
            assert!(
                browser.headers.get_str("set-cookie").is_none(),
                "{label}: a sign-in that failed mints nothing"
            );

            let api = answered(get(target)).await;
            assert_eq!(api.status, status, "{label}: {}", text(&api));
            assert!(text(&api).contains(sentence), "{label}: {}", text(&api));
        }
    }

    /// The five codes are a contract with `assets/app.js`, which holds one written sentence for
    /// each and nothing else to say about a failed sign-in. This walks every status the callback
    /// can refuse with, plus statuses it cannot, and proves the mapping is total and closed —
    /// a sixth code invented here would reach the page as its generic fallback.
    #[test]
    fn every_sign_in_failure_maps_to_one_of_the_five_codes_the_page_has_a_sentence_for() {
        let written = [
            SIGNIN_EXPIRED,
            SIGNIN_PROVIDER_UNREACHABLE,
            SIGNIN_UNAVAILABLE,
            SIGNIN_EMAIL_CONFLICT,
            SIGNIN_UNKNOWN_PROVIDER,
        ];
        for (status, expected) in [
            (Status::BAD_REQUEST, SIGNIN_EXPIRED),
            (Status::NOT_FOUND, SIGNIN_UNKNOWN_PROVIDER),
            (Status(409), SIGNIN_EMAIL_CONFLICT),
            (Status::BAD_GATEWAY, SIGNIN_PROVIDER_UNREACHABLE),
            (Status::SERVICE_UNAVAILABLE, SIGNIN_UNAVAILABLE),
            (Status::INTERNAL_SERVER_ERROR, SIGNIN_UNAVAILABLE),
            (Status::OK, SIGNIN_UNAVAILABLE),
        ] {
            let code = signin_error_code(status);
            assert_eq!(code, expected, "status {}", status.code());
            assert!(written.contains(&code), "an unwritten code: {code}");
            assert!(
                code.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "a code goes straight into a query string this box builds: {code}"
            );
        }
    }

    /// The takeover this box shipped with, reproduced end to end: squat an address at the
    /// unauthenticated passkey door, then have the address's real owner sign in with a provider
    /// that truthfully vouches for it. The provider sign-in must not land on the squatted
    /// account — see `Service::oauth_account`'s documentation for why the two rules that made
    /// this possible were each individually reasonable.
    #[test]
    fn a_squatted_address_does_not_become_a_session_when_its_real_owner_signs_in() {
        let service = service_with_accounts("oauth-squat");
        let runtime = service.accounts.as_ref().expect("accounts are on");
        let attacker = Authenticator::new("attackers-authenticator");

        // 1. The attacker names an address that is not theirs and finishes the ceremony with
        //    their own device. This is allowed, and stays allowed: it is how anyone registers.
        let squat = r#"{"email":"victim@example.com"}"#;
        let started = call(
            &service,
            &json_post("/report/passkey/register/start", squat),
            squat,
        );
        assert_eq!(started.status, Status::OK, "{}", text(&started));
        let finish_body = attacker.register_body_json(&challenge_value(&started), "attacker");
        let finished = call(
            &service,
            &json_post("/report/passkey/register/finish", &finish_body),
            &finish_body,
        );
        assert_eq!(finished.status, Status::OK, "{}", text(&finished));
        let squatted = runtime
            .accounts
            .find_by_email(&selfhost_mail::Address::parse("victim@example.com").unwrap())
            .expect("the squat created an account");
        assert!(!squatted.email_proven(), "nobody proved the address");

        // 2. The real owner signs in with a provider that genuinely checked the address.
        let identity = oauth::Identity {
            subject: "the-victims-subject".to_string(),
            email: "victim@example.com".to_string(),
            email_verified: true,
        };
        let refused = service
            .oauth_account(runtime, "example", &identity)
            .expect_err("no account is handed back");
        assert_eq!(refused.status, Status(409));
        assert!(
            text(&refused).contains(&OAuthError::UnverifiedEmailConflict.to_string()),
            "{}",
            text(&refused)
        );

        // 3. Nothing was linked, so no later sign-in walks into it either.
        let after = runtime
            .accounts
            .find_by_id(&squatted.id)
            .expect("still there");
        assert!(
            after.oauth_links.is_empty(),
            "the provider was linked into the squatted account: {after:?}"
        );
        assert!(
            runtime
                .accounts
                .find_by_oauth("example", "the-victims-subject")
                .is_none()
        );
    }

    /// The other half of the same seam: an account that *did* prove its address still merges, so
    /// the fix above did not simply turn "sign in with…" off for everybody.
    #[test]
    fn a_provider_still_merges_into_an_account_that_proved_its_own_address() {
        let service = service_with_accounts("oauth-merge");
        let runtime = service.accounts.as_ref().expect("accounts are on");
        let registered = register(&service, "alex@example.com", "hunter2fish");
        assert_eq!(registered.status, Status::OK, "{}", text(&registered));
        let account = runtime
            .accounts
            .find_by_email(&selfhost_mail::Address::parse("alex@example.com").unwrap())
            .expect("registered");

        let identity = oauth::Identity {
            subject: "sub-1".to_string(),
            email: "alex@example.com".to_string(),
            email_verified: true,
        };
        // Before the verification link is clicked, even a vouching provider is refused.
        assert!(
            service
                .oauth_account(runtime, "example", &identity)
                .is_err()
        );

        runtime
            .accounts
            .mark_verified(&account.id)
            .expect("verified");
        let merged = service
            .oauth_account(runtime, "example", &identity)
            .expect("merges");
        assert_eq!(merged.id, account.id);
        assert_eq!(
            runtime
                .accounts
                .find_by_oauth("example", "sub-1")
                .map(|found| found.id),
            Some(account.id),
            "and a returning sign-in finds it by the link, not by the address"
        );
    }

    /// An unauthenticated door must not double as a membership oracle. `login_password` is the
    /// house pattern — one sentence for every failure — and this route now matches it: a taken
    /// address and a free one are the same status, the same field set, the same shape.
    #[test]
    fn the_unauthenticated_passkey_door_answers_the_same_for_a_taken_address() {
        let service = service_with_accounts("passkey-oracle");
        register(&service, "taken@example.com", "hunter2fish");

        let taken = r#"{"email":"taken@example.com"}"#;
        let free = r#"{"email":"free@example.com"}"#;
        let for_taken = call(
            &service,
            &json_post("/report/passkey/register/start", taken),
            taken,
        );
        let for_free = call(
            &service,
            &json_post("/report/passkey/register/start", free),
            free,
        );
        assert_eq!(for_taken.status, Status::OK, "{}", text(&for_taken));
        assert_eq!(for_free.status, for_taken.status);
        assert_eq!(
            json_field(&text(&for_taken), "rpId"),
            json_field(&text(&for_free), "rpId")
        );
        assert_eq!(
            challenge_value(&for_taken).len(),
            challenge_value(&for_free).len(),
            "a challenge is a challenge; its length must not sort addresses"
        );
        assert!(
            !text(&for_taken).contains("already exists"),
            "{}",
            text(&for_taken)
        );

        // And the decoy leads nowhere: the ceremony fails at the finish with the same sentence
        // every unverifiable ceremony gets, having created no account and no credential.
        let device = Authenticator::new("a-prober");
        let body = device.register_body_json(&challenge_value(&for_taken), "prober");
        let finished = call(
            &service,
            &json_post("/report/passkey/register/finish", &body),
            &body,
        );
        assert_eq!(finished.status, Status::UNAUTHORIZED);
        assert!(
            text(&finished).contains("the passkey ceremony could not be verified"),
            "{}",
            text(&finished)
        );
        let runtime = service.accounts.as_ref().expect("accounts are on");
        assert!(
            runtime
                .webauthn
                .as_ref()
                .expect("passkeys are on")
                .is_empty(),
            "the decoy must not have registered a credential anywhere"
        );
    }

    /// The global account-door bucket is everybody's, not one visitor's. Sized like a single
    /// source's, two people signing in at once would spend it and the third would be refused by
    /// a box doing nothing at all.
    #[test]
    fn one_source_spending_its_account_allowance_does_not_starve_another() {
        let service = service_with_accounts("action-global");
        let now = Instant::now();
        let attempt = |client: &str| {
            let body = r#"{"email":"nobody@example.com","password":"whatever1"}"#;
            service.answer(
                &json_post("/report/login", body),
                body.as_bytes(),
                client,
                now,
                UNIX_EPOCH,
            )
        };
        // This test's per-source allowance is fifty; spend it from one address until it refuses.
        let mut refusals = 0;
        for _ in 0..60 {
            if attempt("198.51.100.1").status == Status::TOO_MANY_REQUESTS {
                refusals += 1;
            }
        }
        assert!(refusals > 0, "the per-source wall still stands");

        let other = attempt("203.0.113.7");
        assert_eq!(
            other.status,
            Status::UNAUTHORIZED,
            "a second visitor gets their own allowance, not the first one's leftovers: {}",
            text(&other)
        );
    }

    #[test]
    fn a_flood_at_the_login_door_does_not_touch_the_filing_or_reading_allowance() {
        let dir = scratch_dir("accounts-flood");
        let store = Store::open(&dir.join("store")).expect("store");
        store.add_project("dx").expect("project");
        let service = Service::new(
            store,
            Config {
                token: Some("secret-token".to_string()),
                accounts: Some(AccountsConfig {
                    data_dir: dir.join("accounts"),
                    site_name: "Test Reports".to_string(),
                    public_base_url: "https://reports.example.com".to_string(),
                    rp_id: None,
                    oauth_providers: Vec::new(),
                    verify_from: "reports@example.com".to_string(),
                    verify_helo: "example.com".to_string(),
                    mail_data_dir: None,
                    per_action: Rate::new(2, 3.0),
                    global_action: Rate::new(20, 30.0),
                }),
                ..Config::default()
            },
        );
        let now = Instant::now();
        for _ in 0..2 {
            login(&service, "nobody@example.com", "whatever1");
        }
        let flooded = login(&service, "nobody@example.com", "whatever1");
        assert_eq!(flooded.status, Status::TOO_MANY_REQUESTS);

        // Filing is a wholly separate allowance.
        let body = r#"{"kind":"bug","title":"still able to file","detail":"d"}"#;
        assert_eq!(
            service
                .answer(&post(body), body.as_bytes(), "203.0.113.9", now, UNIX_EPOCH)
                .status,
            Status::OK
        );
    }

    /// A service with production-shaped reading and page allowances and an owner token, for the
    /// two tests below about who can spend whose budget. `service_with_accounts` deliberately
    /// widens the *account door* so unrelated tests never trip it; these two need the defaults.
    fn service_with_default_budgets(label: &str) -> Service {
        let dir = scratch_dir(label);
        let store = Store::open(&dir.join("store")).expect("store");
        store.add_project("dx").expect("project");
        Service::new(
            store,
            Config {
                token: Some("secret-token".to_string()),
                accounts: Some(AccountsConfig {
                    data_dir: dir.join("accounts"),
                    site_name: "Test Reports".to_string(),
                    public_base_url: "https://reports.example.com".to_string(),
                    rp_id: None,
                    oauth_providers: Vec::new(),
                    verify_from: "reports@example.com".to_string(),
                    verify_helo: "example.com".to_string(),
                    mail_data_dir: None,
                    per_action: Rate::new(50, 3000.0),
                    global_action: Rate::new(500, 30_000.0),
                }),
                ..Config::default()
            },
        )
    }

    /// The reading limiter's *global* bucket used to be `Config::global` — the filing bucket,
    /// twenty tokens refilling at one a second, sized for a box that takes a few reports a
    /// minute. Then the page arrived, and `<route>/capabilities` and `<route>/projects` are
    /// two calls it makes on every load, by every visitor. Twelve strangers opening the login
    /// page once each therefore emptied that bucket and the owner's own token-gated feed
    /// answered `429`: a public page turned into a denial of service against the one person
    /// who is supposed to be able to read.
    ///
    /// Each stranger here uses their own address, so nothing below is refused by a *per-source*
    /// wall — the shared bucket is the whole subject.
    #[test]
    fn strangers_loading_the_page_cannot_close_the_owners_feed() {
        let service = service_with_default_budgets("reading-global");
        let now = Instant::now();

        for visitor in 0..40 {
            let client = format!("198.51.100.{}", visitor + 1);
            for target in ["/report/capabilities", "/report/projects"] {
                let answered = service.answer(&get(target), b"", &client, now, UNIX_EPOCH);
                assert_eq!(
                    answered.status,
                    Status::OK,
                    "visitor {visitor} was refused {target}: {}",
                    text(&answered)
                );
            }
        }

        let feed = service.answer(
            &get_with_header("/report/feed?dx", "Authorization", "Bearer secret-token"),
            b"",
            "203.0.113.9",
            now,
            UNIX_EPOCH,
        );
        assert_eq!(
            feed.status,
            Status::OK,
            "eighty stranger page-load reads closed the owner's feed: {}",
            text(&feed)
        );
    }

    /// The page routes shipped with no allowance at all, carrying about 87 KB between them on
    /// a box with a real public IP — and the `308` from the bare `<route>` steers browsers at
    /// them. They have a budget now, and it is their own: a visitor pulling the page in a loop
    /// is eventually refused, and doing so touches neither the owner's reading allowance nor
    /// the account door a person needs to sign in with.
    #[test]
    fn the_page_files_are_bounded_and_spend_only_their_own_budget() {
        let service = service_with_default_budgets("page-budget");
        let now = Instant::now();
        let looper = "198.51.100.44";
        let files = [
            "/report/",
            "/report/index.html",
            "/report/app.css",
            "/report/app.js",
            "/report/favicon.svg",
        ];

        // `per_page_visitor` is a hundred and twenty: fifteen page loads' worth. A loop gets
        // there.
        let mut refused = false;
        for _ in 0..40 {
            for target in files {
                if service
                    .answer(&get(target), b"", looper, now, UNIX_EPOCH)
                    .status
                    == Status::TOO_MANY_REQUESTS
                {
                    refused = true;
                }
            }
        }
        assert!(refused, "the page files are unbounded");

        // A page load is generous, though: the same address's *first* ten loads are all served,
        // which is what stops this wall from being a bug of its own. Proven by a fresh address.
        for visit in 0..10 {
            for target in files {
                let served = service.answer(&get(target), b"", "198.51.100.45", now, UNIX_EPOCH);
                assert_eq!(
                    served.status,
                    Status::OK,
                    "visit {visit} of {target} was refused"
                );
            }
        }

        // And the looper spent nothing that belongs to anyone else: the same address can still
        // sign in and still read.
        let door = login(&service, "nobody@example.com", "whatever1");
        assert_eq!(
            door.status,
            Status::UNAUTHORIZED,
            "pulling the page closed the account door: {}",
            text(&door)
        );
        let feed = service.answer(
            &get_with_header("/report/feed?dx", "Authorization", "Bearer secret-token"),
            b"",
            looper,
            now,
            UNIX_EPOCH,
        );
        assert_eq!(
            feed.status,
            Status::OK,
            "pulling the page closed the feed: {}",
            text(&feed)
        );
    }

    /// The same shape as [`service_with_default_budgets`], but with the account door set to the
    /// numbers `crates/cli` actually ships — five attempts, then one every twelve seconds.
    /// A test that a real person is never refused is only worth anything against the real
    /// bucket: with the generous test rate every arrangement of these routes passes.
    fn service_with_production_budgets(label: &str) -> Service {
        let dir = scratch_dir(label);
        let store = Store::open(&dir.join("store")).expect("store");
        store.add_project("dx").expect("project");
        Service::new(
            store,
            Config {
                token: Some("secret-token".to_string()),
                accounts: Some(AccountsConfig {
                    data_dir: dir.join("accounts"),
                    site_name: "Test Reports".to_string(),
                    public_base_url: "https://reports.example.com".to_string(),
                    rp_id: None,
                    oauth_providers: Vec::new(),
                    verify_from: "reports@example.com".to_string(),
                    verify_helo: "example.com".to_string(),
                    mail_data_dir: None,
                    per_action: Rate::new(5, 5.0),
                    global_action: Rate::new(200, 120.0),
                }),
                ..Config::default()
            },
        )
    }

    /// The eight requests a browser actually makes drawing this page once, in order: the `308`
    /// off the bare route, the shell, its three files, then the three JSON calls
    /// `assets/app.js` makes — `capabilities` and `me` on boot, `projects` when the filing form
    /// draws. Written once here so the two tests below cannot come to disagree about what a
    /// page load *is*, which is the thing the budget is sized against.
    fn page_load(
        service: &Service,
        client: &str,
        now: Instant,
        cookie: Option<&str>,
    ) -> Vec<(String, Response)> {
        let browser_accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        let mut answers = vec![(
            "GET /report".to_string(),
            service.answer(
                &get_with_header("/report", "Accept", browser_accept),
                b"",
                client,
                now,
                UNIX_EPOCH,
            ),
        )];
        for target in [
            "/report/",
            "/report/app.css",
            "/report/app.js",
            "/report/favicon.svg",
            "/report/capabilities",
            "/report/me",
            "/report/projects",
        ] {
            let head = match cookie {
                Some(cookie) => get_with_cookie(target, cookie),
                None => get(target),
            };
            answers.push((
                format!("GET {target}"),
                service.answer(&head, b"", client, now, UNIX_EPOCH),
            ));
        }
        answers
    }

    /// Finding 2: a page load has to cost one coherent budget.
    ///
    /// The four files were budgeted and the JSON calls beside them were not, so the sixth
    /// consecutive load from one address served every file and answered `429` to `capabilities`
    /// and `projects` — and `assets/app.js` draws exactly that as a working page with no
    /// passkeys, no providers and no projects. A visitor cannot tell that from a box that has
    /// none, which is why a half-spent budget is worse than a clean refusal. Ten real loads
    /// from one address, every one of the eighty requests served.
    #[test]
    fn ten_consecutive_page_loads_from_one_address_are_all_served_whole() {
        let service = service_with_default_budgets("page-load-whole");
        let now = Instant::now();
        for visit in 0..10 {
            for (what, answer) in page_load(&service, "198.51.100.60", now, None) {
                assert_ne!(
                    answer.status,
                    Status::TOO_MANY_REQUESTS,
                    "visit {visit}: {what} was refused, so the page drew its degraded fallback"
                );
            }
        }
    }

    /// Finding 1: six routes under `<route>/` spent no allowance at all.
    ///
    /// `me`, `mine`, `download`, `logout`, `me/password` and `mine/withdraw` appeared in
    /// neither budget list, so five hundred requests from one address got five hundred answers
    /// — and `me`, the call the page makes on every load, does that while answering `401` to a
    /// caller holding no credential whatsoever. Each gets its own client address here, because
    /// they share buckets by design and a shared address would prove only that *something* was
    /// bounded.
    #[test]
    fn a_looping_stranger_is_eventually_refused_on_every_route_but_health() {
        let service = service_with_default_budgets("looping-stranger");
        let now = Instant::now();
        let empty = "";
        for (nth, (method, target)) in [
            ("GET", "/report/me"),
            ("GET", "/report/mine"),
            ("GET", "/report/download"),
            ("POST", "/report/logout"),
            ("POST", "/report/me/password"),
            ("POST", "/report/mine/withdraw"),
            ("GET", "/report/capabilities"),
            ("GET", "/report/projects"),
        ]
        .into_iter()
        .enumerate()
        {
            let client = format!("198.51.100.{}", 100 + nth);
            let head = if method == "GET" {
                get(target)
            } else {
                json_post(target, empty)
            };
            let mut refused = false;
            for _ in 0..600 {
                if service
                    .answer(&head, empty.as_bytes(), &client, now, UNIX_EPOCH)
                    .status
                    == Status::TOO_MANY_REQUESTS
                {
                    refused = true;
                    break;
                }
            }
            assert!(
                refused,
                "{method} {target} answered a loop without ever spending an allowance"
            );
        }

        // And the exception stays an exception: the proxy's own health check is never refused,
        // however rude anybody else on the same address has been.
        for _ in 0..600 {
            assert_eq!(
                service
                    .answer(&get("/report/health"), b"", "198.51.100.100", now, UNIX_EPOCH)
                    .status,
                Status::OK,
                "a health check that can be rate-limited drops the site out of rotation"
            );
        }
    }

    /// The other half of the bound: an ordinary signed-in person, doing ordinary things against
    /// the account door `crates/cli` actually ships, is never refused.
    ///
    /// This is the test that says *which* budget each of the six belongs on. Splitting them —
    /// reads on the page visit, the two state-changing `POST`s on the account door — is only
    /// right if a page load plus a few actions still fits inside the five-attempt credential
    /// bucket, and it does precisely because the reads are not counted against it.
    #[test]
    fn a_signed_in_person_doing_ordinary_things_is_never_refused() {
        let service = service_with_production_budgets("ordinary-use");
        let now = Instant::now();
        let client = "198.51.100.70";

        let registered = service.answer(
            &json_post(
                "/report/register",
                r#"{"email":"alex@example.com","password":"hunter2fish"}"#,
            ),
            br#"{"email":"alex@example.com","password":"hunter2fish"}"#,
            client,
            now,
            UNIX_EPOCH,
        );
        assert_eq!(registered.status, Status::OK, "{}", text(&registered));
        let cookie = set_cookie(&registered);

        // A page load, signed in — the same eight requests, now carrying the session.
        for (what, answer) in page_load(&service, client, now, Some(&cookie)) {
            assert_ne!(
                answer.status,
                Status::TOO_MANY_REQUESTS,
                "{what} was refused on an ordinary page load"
            );
        }

        // Then a few ordinary actions: file a report, look at the list, ask for the download,
        // withdraw the report, rotate the password, sign out. Nothing here is an attack and
        // nothing here may answer `429`.
        let filed_body = r#"{"kind":"bug","title":"a real report","detail":"the words"}"#;
        let filed = service.answer(
            &json_post_with_cookie("/report", filed_body, &cookie),
            filed_body.as_bytes(),
            client,
            now,
            UNIX_EPOCH,
        );
        assert_eq!(filed.status, Status::OK, "{}", text(&filed));
        let id = service.store().list("dx").expect("list")[0].id.clone();
        let withdraw_body = format!(r#"{{"project":"dx","id":"{id}"}}"#);
        let ordinary: [(&str, Request, &[u8]); 5] = [
            ("GET /report/mine", get_with_cookie("/report/mine", &cookie), b""),
            (
                "GET /report/download",
                get_with_cookie("/report/download", &cookie),
                b"",
            ),
            (
                "POST /report/mine/withdraw",
                json_post_with_cookie("/report/mine/withdraw", &withdraw_body, &cookie),
                withdraw_body.as_bytes(),
            ),
            (
                "POST /report/me/password",
                json_post_with_cookie(
                    "/report/me/password",
                    r#"{"password":"brandnewpassword"}"#,
                    &cookie,
                ),
                br#"{"password":"brandnewpassword"}"#,
            ),
            (
                "POST /report/logout",
                json_post_with_cookie("/report/logout", "{}", &cookie),
                b"{}",
            ),
        ];
        for (what, head, body) in ordinary {
            let answer = service.answer(&head, body, client, now, UNIX_EPOCH);
            assert_ne!(
                answer.status,
                Status::TOO_MANY_REQUESTS,
                "{what} was refused: {}",
                text(&answer)
            );
        }

        // And the door is still open afterwards — the whole point of keeping page-frequency
        // reads off the credential bucket is that using the page never costs a sign-in.
        let back = service.answer(
            &json_post(
                "/report/login",
                r#"{"email":"alex@example.com","password":"brandnewpassword"}"#,
            ),
            br#"{"email":"alex@example.com","password":"brandnewpassword"}"#,
            client,
            now,
            UNIX_EPOCH,
        );
        assert_eq!(
            back.status,
            Status::OK,
            "ordinary use spent the allowance that protects sign-in: {}",
            text(&back)
        );
    }

    /// The module documentation claimed a `POST` under `<route>/` carrying a foreign `Origin`
    /// was refused `403`, and the check only ever ran inside `accounts_answer` — so the filing
    /// route itself, `POST <route>`, which is the one the page posts reports to and the one
    /// that attributes a report to a live session, was outside a wall the documentation said
    /// was around it. It is inside now.
    #[test]
    fn a_cross_site_post_is_refused_on_the_filing_route_too() {
        let service = service_with_accounts("origin-filing");
        let body = r#"{"kind":"bug","title":"filed by another site","detail":"d"}"#;

        let forged = call(
            &service,
            &json_post_from("/report", body, "https://evil.example"),
            body,
        );
        assert_eq!(forged.status, Status::FORBIDDEN, "{}", text(&forged));
        assert!(
            text(&forged).contains("this request came from another site"),
            "{}",
            text(&forged)
        );
        assert!(
            service.store().list("dx").expect("list").is_empty(),
            "a refused cross-site POST must not have stored anything"
        );

        // The page's own POST, from this box's own address, is untouched.
        let ours = call(
            &service,
            &json_post_from("/report", body, "https://reports.example.com"),
            body,
        );
        assert_eq!(ours.status, Status::OK, "{}", text(&ours));

        // And so is every client that sends no `Origin` at all — curl, the CLI, every agent.
        let agent = call(&service, &post(body), body);
        assert_eq!(agent.status, Status::OK, "{}", text(&agent));
    }

    /// The `challenge` field out of a JSON challenge answer.
    fn challenge_value(response: &Response) -> String {
        let value = selfhost_json::parse(&text(response)).expect("json");
        value
            .get("challenge")
            .and_then(Json::as_str)
            .expect("a challenge")
            .to_string()
    }

    /// A named field out of a flat JSON object's text, for assertions that only need one value.
    fn json_field(text: &str, field: &str) -> String {
        selfhost_json::parse(text)
            .ok()
            .and_then(|value| value.get(field).and_then(Json::as_str).map(str::to_string))
            .unwrap_or_default()
    }

    /// The relying party these tests' passkey ceremonies speak for.
    const RP: &str = "reports.example.com";

    /// A minimal WebAuthn test authenticator — the same shape `webauthn::tests::Authenticator`
    /// uses, duplicated here rather than exported from that module's `#[cfg(test)]` block, so
    /// this file can drive the actual HTTP routes end to end without a browser.
    struct Authenticator {
        keys: ring::signature::EcdsaKeyPair,
        id: String,
    }

    impl Authenticator {
        fn new(id: &str) -> Self {
            use ring::rand::SystemRandom;
            use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair};
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                .expect("keypair");
            let keys =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
                    .expect("keypair parses back");
            Self {
                keys,
                id: oauth::b64url_encode(id.as_bytes()),
            }
        }

        fn spki(&self) -> Vec<u8> {
            use ring::signature::KeyPair;
            // The exact prefix `crates/reports/src/webauthn.rs::P256_SPKI_PREFIX` cuts back out.
            const P256_SPKI_PREFIX: [u8; 26] = [
                0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
                0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
            ];
            let mut out = P256_SPKI_PREFIX.to_vec();
            out.extend_from_slice(self.keys.public_key().as_ref());
            out
        }

        fn auth_data(flags: u8) -> Vec<u8> {
            let mut out = ring::digest::digest(&ring::digest::SHA256, RP.as_bytes())
                .as_ref()
                .to_vec();
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

        fn register_body_json(&self, challenge: &str, label: &str) -> String {
            let client = Self::client_data("webauthn.create", challenge);
            let flags = 0x01 | 0x04 | 0x40; // present, verified, attested credential
            Json::object([
                ("id", Json::string(&self.id)),
                ("algorithm", Json::Number(-7.0)),
                (
                    "publicKey",
                    Json::string(oauth::b64url_encode(&self.spki())),
                ),
                (
                    "clientDataJSON",
                    Json::string(oauth::b64url_encode(&client)),
                ),
                (
                    "authenticatorData",
                    Json::string(oauth::b64url_encode(&Self::auth_data(flags))),
                ),
                ("label", Json::string(label)),
            ])
            .to_text()
        }

        fn login_body_json(&self, challenge: &str) -> String {
            use ring::rand::SystemRandom;
            let client = Self::client_data("webauthn.get", challenge);
            let auth = Self::auth_data(0x01 | 0x04);
            let mut message = auth.clone();
            message
                .extend_from_slice(ring::digest::digest(&ring::digest::SHA256, &client).as_ref());
            let signature = self
                .keys
                .sign(&SystemRandom::new(), &message)
                .expect("signs");
            Json::object([
                ("id", Json::string(&self.id)),
                (
                    "clientDataJSON",
                    Json::string(oauth::b64url_encode(&client)),
                ),
                (
                    "authenticatorData",
                    Json::string(oauth::b64url_encode(&auth)),
                ),
                (
                    "signature",
                    Json::string(oauth::b64url_encode(signature.as_ref())),
                ),
            ])
            .to_text()
        }
    }

    #[test]
    fn a_report_from_anywhere_is_stored_and_answered_with_its_id() {
        let service = service("filed");
        let response = file(
            &service,
            r#"{"kind":"bug","title":"search misses","detail":"it answered the heading"}"#,
            "203.0.113.9",
        );
        assert_eq!(response.status, Status::OK);
        let answered = text(&response);
        assert!(answered.contains("\"filed\":\"report-"), "{answered}");
        assert!(answered.contains("\"project\":\"dx\""), "{answered}");
        assert_eq!(service.store().list("dx").expect("list").len(), 1);
    }

    #[test]
    fn the_same_defect_twice_is_one_record_and_the_answer_says_so() {
        let service = service("twice");
        let body = r#"{"kind":"bug","title":"same","detail":"one"}"#;
        file(&service, body, "203.0.113.9");
        let second = file(&service, body, "198.51.100.4");
        assert!(
            text(&second).contains("\"known\":true"),
            "{}",
            text(&second)
        );
        assert!(
            text(&second).contains("\"sightings\":2"),
            "{}",
            text(&second)
        );
    }

    #[test]
    fn a_flood_from_one_source_is_refused_with_a_wait() {
        let service = service("flood");
        let now = Instant::now();
        for nth in 0..3 {
            let body = format!(r#"{{"kind":"bug","title":"defect {nth}","detail":"d"}}"#);
            let response = service.answer(
                &post(&body),
                body.as_bytes(),
                "203.0.113.9",
                now,
                UNIX_EPOCH,
            );
            assert_eq!(response.status, Status::OK);
        }
        let body = r#"{"kind":"bug","title":"one too many","detail":"d"}"#;
        let refused = service.answer(&post(body), body.as_bytes(), "203.0.113.9", now, UNIX_EPOCH);
        assert_eq!(refused.status, Status::TOO_MANY_REQUESTS);
        assert!(refused.headers.get_str("retry-after").is_some());
        // And it did not cost the reporter's neighbour anything.
        let other = service.answer(
            &post(body),
            body.as_bytes(),
            "198.51.100.4",
            now,
            UNIX_EPOCH,
        );
        assert_eq!(other.status, Status::OK);
    }

    #[test]
    fn the_client_is_the_last_forwarded_value_not_the_one_the_client_chose() {
        let request = request(
            "POST /report HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 1.2.3.4\r\n\
             X-Forwarded-For: 203.0.113.9\r\nContent-Length: 0\r\n\r\n",
        );
        let peer: SocketAddr = "127.0.0.1:5000".parse().expect("peer");
        assert_eq!(client_address(&request, peer), "203.0.113.9");

        let direct =
            Request::parse(b"POST /report HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
                .expect("request parses")
                .request;
        assert_eq!(client_address(&direct, peer), "127.0.0.1");
    }

    #[test]
    fn a_spoofed_forwarded_header_cannot_buy_a_fresh_allowance() {
        let service = service("spoof");
        let now = Instant::now();
        let body = r#"{"kind":"bug","title":"t","detail":"d"}"#;
        for _ in 0..3 {
            service.answer(&post(body), body.as_bytes(), "203.0.113.9", now, UNIX_EPOCH);
        }
        // The header a client sends is not what the limiter sees; the proxy's value is.
        let refused = service.answer(&post(body), body.as_bytes(), "203.0.113.9", now, UNIX_EPOCH);
        assert_eq!(refused.status, Status::TOO_MANY_REQUESTS);
    }

    /// The whole of registering a service: file one report to it.
    #[test]
    fn filing_to_a_service_nobody_declared_brings_it_into_existence() {
        let service = service("new-service");
        let body = r#"{"project":"billing","kind":"bug","title":"t","detail":"d"}"#;
        let posted = request(&format!(
            "POST /report?billing HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        let response = service.answer(
            &posted,
            body.as_bytes(),
            "203.0.113.9",
            Instant::now(),
            UNIX_EPOCH,
        );
        assert_eq!(response.status, Status::OK, "{}", text(&response));
        assert!(
            text(&response).contains("\"filed\":\"report-"),
            "{}",
            text(&response)
        );
        assert_eq!(service.store().list("billing").expect("list").len(), 1);
        assert!(
            service.store().list("dx").expect("list").is_empty(),
            "a new service's reports do not land in the default one"
        );
    }

    /// The address is where the report was actually sent, so it wins over a stale template.
    #[test]
    fn the_query_names_the_service_and_the_body_does_not_override_it() {
        let service = service("query-wins");
        let body = r#"{"project":"dx","kind":"bug","title":"t","detail":"d"}"#;
        let posted = request(&format!(
            "POST /report?billing&verbose=1 HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        let response = service.answer(
            &posted,
            body.as_bytes(),
            "203.0.113.9",
            Instant::now(),
            UNIX_EPOCH,
        );
        assert_eq!(response.status, Status::OK, "{}", text(&response));
        assert_eq!(service.store().list("billing").expect("list").len(), 1);
        assert!(service.store().list("dx").expect("list").is_empty());
    }

    /// A bare word, and nothing that could name a directory this store does not own.
    #[test]
    fn a_service_name_that_is_not_a_word_is_refused_in_a_sentence() {
        let service = service("bad-service");
        let body = r#"{"kind":"bug","title":"t","detail":"d"}"#;
        let posted = request(&format!(
            "POST /report?..%2f..%2fetc HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        ));
        let response = service.answer(
            &posted,
            body.as_bytes(),
            "203.0.113.9",
            Instant::now(),
            UNIX_EPOCH,
        );
        assert_eq!(response.status, Status::BAD_REQUEST);
        assert!(
            text(&response).contains("not a service key"),
            "{}",
            text(&response)
        );
    }

    #[test]
    fn a_malformed_body_is_refused_without_being_echoed() {
        let service = service("malformed");
        let body = "<script>alert(1)</script>";
        let response = file(&service, body, "203.0.113.9");
        assert_eq!(response.status, Status::BAD_REQUEST);
        assert!(!text(&response).contains("script"), "{}", text(&response));
    }

    #[test]
    fn every_answer_carries_the_headers_an_app_behind_the_proxy_must_set() {
        let service = service("headers");
        let response = file(
            &service,
            r#"{"kind":"bug","title":"t","detail":"d"}"#,
            "203.0.113.9",
        );
        assert_eq!(
            response.headers.get_str("x-content-type-options"),
            Some("nosniff")
        );
        assert_eq!(response.headers.get_str("x-frame-options"), Some("DENY"));
        assert_eq!(response.headers.get_str("cache-control"), Some("no-store"));
        assert!(
            response
                .headers
                .get_str("content-security-policy")
                .is_some()
        );
    }

    #[test]
    fn the_feed_needs_the_owners_token_and_carries_the_whole_report() {
        let service = service("feed");
        file(
            &service,
            r#"{"kind":"bug","title":"in the feed","detail":"the words"}"#,
            "203.0.113.9",
        );

        let anonymous = request("GET /report/feed?dx HTTP/1.1\r\nHost: x\r\n\r\n");
        let refused = service.answer(&anonymous, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH);
        assert_eq!(refused.status, Status::UNAUTHORIZED);

        let owner = request(
            "GET /report/feed?dx HTTP/1.1\r\nHost: x\r\n\
             Authorization: Bearer secret-token\r\n\r\n",
        );
        let answered = service.answer(&owner, &[], "127.0.0.1", Instant::now(), UNIX_EPOCH);
        assert_eq!(answered.status, Status::OK);
        let payload = text(&answered);
        assert!(payload.contains("in the feed"), "{payload}");
        assert!(
            payload.contains("the words"),
            "the feed carries the detail a checkout folds in"
        );
    }

    /// A 256-bit token is not guessable, but a route that answers "wrong" at line speed is
    /// still a route worth making expensive — and the same allowance stops a token route
    /// being a free amplifier for anyone who finds it.
    #[test]
    fn guessing_at_the_token_costs_the_guesser_an_allowance() {
        // A reading allowance the size of the filing one, so the property is asserted in four
        // requests rather than eleven. The shipped burst is larger, because a subscribed
        // checkout reads on a timer and this limiter exists to make guessing expensive.
        let dir = scratch_dir("token-rate");
        let store = Store::open(&dir).expect("store");
        store.add_project("dx").expect("project");
        let service = Service::new(
            store,
            Config {
                token: Some("secret-token".to_string()),
                per_reader: Rate::new(3, 3.0),
                ..Config::default()
            },
        );
        let now = Instant::now();
        let wrong =
            request("GET /report/feed HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer nope\r\n\r\n");
        for _ in 0..3 {
            assert_eq!(
                service
                    .answer(&wrong, &[], "203.0.113.9", now, UNIX_EPOCH)
                    .status,
                Status::UNAUTHORIZED
            );
        }
        assert_eq!(
            service
                .answer(&wrong, &[], "203.0.113.9", now, UNIX_EPOCH)
                .status,
            Status::TOO_MANY_REQUESTS
        );

        // The health check is deliberately outside that allowance: it runs on the proxy's
        // own timer, and a site must not leave rotation because somebody else was rude.
        let health = request("GET /report/health HTTP/1.1\r\nHost: x\r\n\r\n");
        for _ in 0..5 {
            assert_eq!(
                service
                    .answer(&health, &[], "203.0.113.9", now, UNIX_EPOCH)
                    .status,
                Status::OK
            );
        }

        // And filing is a separate allowance, so a reader that has spent its own — a checkout
        // syncing on a timer, or somebody trying tokens — has not taken the one an agent needs
        // to report what it just hit. A read starving a write is the bug this pair prevents.
        let body = r#"{"kind":"bug","title":"still able to file","detail":"d"}"#;
        assert_eq!(
            service
                .answer(&post(body), body.as_bytes(), "203.0.113.9", now, UNIX_EPOCH)
                .status,
            Status::OK
        );
    }

    #[test]
    fn a_wrong_token_is_refused_and_a_box_with_no_token_has_no_such_route() {
        let service = service("token");
        let wrong =
            request("GET /report/feed HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer nope\r\n\r\n");
        assert_eq!(
            service
                .answer(&wrong, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH)
                .status,
            Status::UNAUTHORIZED
        );

        let dir = scratch_dir("tokenless");
        let store = Store::open(&dir).expect("store");
        store.add_project("dx").expect("project");
        let tokenless = Service::new(store, Config::default());
        let asked = request("GET /report/feed HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(
            tokenless
                .answer(&asked, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH)
                .status,
            Status::NOT_FOUND,
            "a route that cannot be used is not a route to probe"
        );
    }

    #[test]
    fn closing_a_report_removes_it_from_the_feed() {
        let service = service("close");
        let filed = file(
            &service,
            r#"{"kind":"bug","title":"fixed soon","detail":"d"}"#,
            "203.0.113.9",
        );
        let id = text(&filed)
            .split("\"filed\":\"")
            .nth(1)
            .and_then(|rest| rest.split('"').next())
            .expect("id")
            .to_string();

        let body = format!(r#"{{"project":"dx","id":"{id}"}}"#);
        let closing = request(&format!(
            "POST /report/close?dx HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer secret-token\r\n\
             Content-Length: {}\r\n\r\n",
            body.len()
        ));
        let closed = service.answer(
            &closing,
            body.as_bytes(),
            "127.0.0.1",
            Instant::now(),
            UNIX_EPOCH,
        );
        assert_eq!(closed.status, Status::OK);
        assert!(service.store().list("dx").expect("list").is_empty());
    }

    #[test]
    fn the_health_route_says_nothing_about_content() {
        let service = service("health");
        file(
            &service,
            r#"{"kind":"bug","title":"secret title","detail":"d"}"#,
            "203.0.113.9",
        );
        let asked = request("GET /report/health HTTP/1.1\r\nHost: x\r\n\r\n");
        let answered = service.answer(&asked, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH);
        assert_eq!(answered.status, Status::OK);
        assert!(
            !text(&answered).contains("secret title"),
            "{}",
            text(&answered)
        );
    }

    #[test]
    fn a_get_on_the_intake_says_to_post_and_an_unknown_path_is_a_404() {
        let service = service("methods");
        let asked = request("GET /report HTTP/1.1\r\nHost: x\r\n\r\n");
        let answered = service.answer(&asked, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH);
        assert_eq!(answered.status, Status::METHOD_NOT_ALLOWED);

        let elsewhere = request("GET /report/../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n");
        let refused = service.answer(&elsewhere, &[], "203.0.113.9", Instant::now(), UNIX_EPOCH);
        assert_eq!(refused.status, Status::NOT_FOUND);
    }

    #[test]
    fn constant_time_comparison_still_compares() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"sane"));
        assert!(!constant_time_eq(b"same", b"same-but-longer"));
    }

    #[tokio::test]
    async fn the_intake_refuses_to_bind_anywhere_but_loopback() {
        let error = bind("0.0.0.0:0".parse().expect("address"))
            .await
            .expect_err("refused");
        assert!(error.to_string().contains("must be loopback"), "{error}");
        assert!(bind("127.0.0.1:0".parse().expect("address")).await.is_ok());
    }

    /// The end-to-end shape, over a real socket: a report POSTed by something that is not
    /// this crate is stored, and an oversized one is refused before it is read.
    #[tokio::test]
    async fn a_real_request_over_a_real_socket_is_stored() {
        let service = Arc::new(service("socket"));
        let listener = bind("127.0.0.1:0".parse().expect("address"))
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let serving = Arc::clone(&service);
        tokio::spawn(async move {
            let _ = serve(listener, serving).await;
        });

        let body = r#"{"kind":"bug","title":"over a socket","detail":"it works"}"#;
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream
            .write_all(
                format!(
                    "POST /report HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .expect("write");
        let mut answered = Vec::new();
        stream.read_to_end(&mut answered).await.expect("read");
        let answered = String::from_utf8_lossy(&answered).to_string();
        assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
        assert!(answered.contains("\"filed\""), "{answered}");
        assert_eq!(service.store().list("dx").expect("list").len(), 1);

        // A body larger than the cap is refused on its declared length alone.
        let mut stream = TcpStream::connect(address).await.expect("connect");
        stream
            .write_all(
                format!(
                    "POST /report HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n",
                    MAX_BODY + 1
                )
                .as_bytes(),
            )
            .await
            .expect("write");
        let mut answered = Vec::new();
        stream.read_to_end(&mut answered).await.expect("read");
        assert!(
            String::from_utf8_lossy(&answered).starts_with("HTTP/1.1 413"),
            "{}",
            String::from_utf8_lossy(&answered)
        );
    }
}
