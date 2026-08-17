# Roadmap — what is done, and what is left

Honest state of the project. Anything marked **done** has tests and has been
exercised against a running instance; anything else has not been written.

## Done

| area | crate | tests | evidence |
|---|---|---|---|
| HTTP/1.1 messages + dates | `crates/foundation/http` | 70 | header injection, request smuggling, byte ranges, cache validators |
| Config model + validation, surgical config editing | `crates/foundation/config` | 106+ | every problem reported at once, field-named; a repository URL that would run a command refused; `site`/`mail add|remove` edit the file as text and preserve every comment |
| Proxy: TLS, SNI, static, caching, LB, live routing reload, EWS/ActiveSync/Autodiscover | `crates/app/proxy` | 160 | path traversal, Range, 304, health hysteresis; a config edit hot-reloads the routing table with no dropped connection; EWS/ActiveSync Basic-auth gated and only served from `autodiscover.<domain>` |
| ACME client (RFC 8555) | `crates/net/acme` | 44+ | full issuance walked live against Let's Encrypt staging *and* production; a CSR's subject is cleared so a CA cannot mistake rcgen's own placeholder name for the domain |
| Mail: SMTP, submission, DKIM, outbound, IMAP, EWS, ActiveSync (WBXML), Autodiscover | `crates/services/mail` | 225 | open-relay defence, credential protection, framing; a message sent by raw SMTP was read back out of the Maildir; IMAP LOGIN/SELECT/FETCH/STORE walked end-to-end over a live connection; EWS `GetItem`/ActiveSync `Fetch` serve the same store as raw MIME, `CreateItem`/`SendMail` route through the same local/outbound split submission uses |
| DNS wire format + resolver + authority | `crates/net/dns` | 22+ | compression pointers, loops, truncation, SOA contacts; authoritative zone serving wired into `daemon` |
| `doctor`, LAN assessment, DNS watch, mail diagnostics | `crates/app/cli` | 100+ | service identified by behaviour, hardware named, one conclusion; a proxy lookup names the device that made it; `doctor --deep` measured a live ISP's outbound-25 block and PTR gap rather than assuming either |
| JSON values, parsing, serialisation | `crates/foundation/json` | 13 | control characters escaped, depth bounded, trailing input refused, surrogate pairs |
| Service supervision | `crates/foundation/supervisor` | 50 | restart backoff and its reset, log gaps reported, process groups killed whole |
| Service catalogue + control API | `crates/app/admin` | 29 | loopback-only bind, constant-time token, atomic catalogue writes |
| Git deployment: watch, pull, build, restart | `crates/services/git` | 37 | a push reaches the running service, a failed build leaves it stopped, untracked files survive |
| Host firewall reconciliation | `crates/net/firewall` | — | macOS pf, Linux nftables, Windows netsh backends behind one `Manager`; default-inbound-block plus named openings, drift re-asserted on a timer |
| A declarative interface library, `rui` | the `rui` library at <https://github.com/RockyWearsAHat/rui> | 263 | layout, hit testing, focus, scrolling, dragging, easing, and a whole frame — all with no display attached |
| The console itself | `crates/ui/console` | 91 | frames rendered headless at the smallest window; a tunnel that dies takes its `ssh` with it |
| WebSockets (RFC 6455) | `crates/net/ws` | 99 | binary frames only, no extension negotiated, minimal length encodings, bounded fragments; the proxy never parses one |
| Identity, capabilities, audit | `crates/foundation/identity` | 56 | `Policy::decide` table-tested over every (identity, credential, capability) triple; an unattended token is refused a keyboard |
| Remote-desktop protocol | `crates/services/desk` | 153 | total parsers on every attacker-influenced field; the session state machine driven through the secure desktop, a crash loop and a user logging out, with no display attached |
| Screen capture and input injection | `crates/services/screen` | 189 | pure coordinate mapping, key tables and synthetic-event plans; macOS verified, **every Windows arm type-checked and unrun** |
| Network storage | `crates/services/storage` | 321 | traversal, ADS, reserved names, 8.3 aliases and case collisions refused; a full SMB reconcile leaves this Mac's `sharing -l -f json` byte-identical |
| Peer mesh transport | `crates/services/mesh` | 177 | fixed eight-byte header, credit that drops and merges, an HMAC proof bound to one handshake; `GET /api/mesh/link` is now wired on the owner (`crates/app/admin/src/mesh_api.rs`), **but nothing outside `crates/services/mesh` calls `splice`, so an admitted link carries no traffic yet** |

Verified live: HTTPS 200 on a real trusted Let's Encrypt production certificate
for the deployed domain and its `www`, HTTP→HTTPS 308, `206` + `Content-Range`
on a seek, `416` on an impossible range, `304` with zero bytes on both cache
validators, `.m3u8`/`.ts` content types, traversal → 404, smuggling → 400, an
ACME challenge served over cleartext while ordinary paths still redirect, and a
full failover cycle across two backends (5/5 split → one killed → 10/10 to the
survivor → restarted → back to 5/5 → both down → 502). SMTP accepted a real
message over port 25 from an external network and it was read back out of the
Maildir; STARTTLS on port 25 presented the same trusted certificate the site
serves. `watch-dns` verified live too: real clients resolved through it over
both UDP and TCP, and a lookup of a known proxy domain named the address that
made it. The console drives a live daemon, and a service installed through the
control API with a branch to watch cloned that branch from GitHub, ran its
build step, and started — with every step reported in the service's own output.

## Scope notes on what shipped

Worth stating plainly rather than leaving to be discovered: IMAP here is
deliberately narrower than the ambition once written below. There is no
server-side `SEARCH`, no `APPEND`, and no `IDLE`. Command literals (`{n}` and
RFC 7888 `{n+}`) *are* parsed — Apple Mail sends `LOGIN` credentials only that
way, so account setup is impossible without them. What exists is
enough for a normal client to `LOGIN`, `LIST`/`SELECT` the fixed folder set,
`FETCH`, and `STORE` flags — reading mail that already arrived, not the full
RFC 3501/9051 surface. `\Recent` is always reported as `0`: this store's
on-disk format does not distinguish "delivered since this mailbox was last
opened" from an ordinary unread message, so nothing here claims a number it
cannot measure.

Outbound direct delivery (`crates/services/mail/src/client.rs`) is real and TLS-capable,
but whether it can be *used* is an environment fact, not a code one — see
`constraints.md`. A `[mail.relay]` smarthost is the alternative already built
for exactly the deployments where direct delivery is blocked upstream.

## Next, in the order I would do it

### 1. Finish the two subsystems that just landed

Three specific gaps, all small, all named at the code:

- **Call the mesh splice.** `crates/app/admin/src/mesh_api.rs` now answers
  `GET /api/mesh/link` and admits or refuses a dial on its merits — the 404 is
  gone. `crates/services/mesh/src/splice.rs` (joining two mesh channels — distinct from
  the desktop-frame splice below) is written and tested, but nothing outside
  `crates/services/mesh` calls it, so an admitted peer link still carries no traffic
  anywhere. The rule to preserve is the one that made the design safe: **the
  worker dials the owner**, over the console site, so the link passes the same
  source-address gate as every other console request and nothing binds.
- **Wire `Api::standings` into `crates/app/cli/src/desk_task.rs`.** The per-input
  re-check is real but the daemon feeds it the standing the *ticket* established,
  so a revocation mid-stream ends the session at its ceiling rather than at the
  next keystroke. Three lines, no interface change — and until it is done,
  `docs/SECURITY.md` §3.7 SCR-01 says plainly not to read that check as live
  revocation.
- **The splice.** The Windows agent's frames do not reach a viewer, because the
  daemon's session driver takes an owned frame per call and the agent produces a
  message stream. Forward the payloads without interpreting them, rewrite the
  channel id, carry credit end to end. Do **not** reconstruct a surface in the
  daemon: that puts attacker-influenced pixel parsing back in the process that
  serves 80/443 under `panic = "abort"`.

### 2. Run it on Windows

Nine thousand lines have never executed. `HANDOFF.md` §5 is the order, and the
first two steps decide whether the session-0 design works at all.

### 3. Backups

Nightly dump plus an off-site copy. **Untested backups are not backups** —
restore has to be exercised, not assumed.

### 4. The console

**The daemon half is done and verified.** `selfhost daemon` supervises arbitrary
services — MongoDB, a NAS daemon, a site's backend — and serves a loopback
control API the console drives. Restart policy, log capture, the catalogue, and
process-group teardown are tested against real processes.

**The client half is done too.** `selfhost-console` is a native window drawn by
a toolkit written here — geometry, an antialiasing rasteriser, a TrueType engine,
layout, and widgets, all pure and tested headless, over a per-platform layer that
does nothing but open a window, deliver input, and copy a buffer to the screen.
See [`gui.md`](gui.md) for the split and for what the font engine deliberately
does not do.

It now carries four screens — services, files, desktops and people — and so does
the browser console; `gui.md`'s *two new plate families* section is the argument
for both. What is left is the **sites and certificates** views, which wait on an
API that reports them; **running the Windows and X11 backends**, which type-check
for their targets and have never been opened; a **pointer-move handler in `rui`**
(`on_hover` is a boolean and `on_drag` fires only while a button is held, so the
native viewport cannot track a hand moving over the picture — the largest
remaining parity gap between the two consoles); and an **operator-start route**,
because the console's start-the-agent button has nothing to call.

**The SSH transport is done.** `selfhost-console --ssh you@server` runs `ssh` as
a managed child, forwards the control port to loopback here, and reads the
daemon's token over the same connection. It never answers a prompt on the
operator's behalf — `BatchMode=yes` turns each question `ssh` would have asked
into a failure, and the console turns that failure into the one command that
fixes it. See [`gui.md`](gui.md#reaching-a-daemon-on-another-machine).

**Git deployment is done.** A service can carry a branch to watch; when the
branch moves, the daemon stops the service, updates the working copy, runs the
build step, and starts it again. Polling, not webhooks — see
[`gui.md`](gui.md#deploying-from-a-branch) for why, and for what is left: a
webhook receiver that only makes a poll happen *sooner*, and an OAuth device
flow for private repositories that the daemon user's SSH key does not already
reach.

## Known limitations in what is already built

Written down so they are decisions rather than surprises.

- **Proxied responses close the connection.** `server.rs::forward` relays the
  upstream response verbatim and then closes. This is *correct* — the upstream's
  framing reaches the client untouched, so the two cannot disagree — but it costs
  a connection setup per proxied request. Fixing it means parsing upstream
  response framing, which reintroduces exactly the disagreement risk the HTTP
  crate exists to prevent. Do it carefully or not at all.
- **HTTP/1.1 only.** ALPN advertises `http/1.1` and nothing else, deliberately:
  claiming HTTP/2 without implementing it makes browsers open a connection we
  cannot speak on. HTTP/2 means HPACK, framing, and flow control.
- **No response compression.** The matcher logic exists in `mime::is_compressible`
  but nothing calls it. Low priority for a video-heavy site, where most bytes are
  already compressed.
- **No rate limiting.** The biggest remaining gap before public exposure.
- **A relayed WebDAV `PUT` has no deadline after its head.** It streams
  uncapped by design — quotas and the in-flight ceiling are storage's job, and
  the in-flight ceiling *is* enforced (`crates/services/storage/src/quota.rs`, called on
  every write) — so what is left is only the deadline: a client that declares an
  enormous length and then stalls holds one client and one loopback connection
  with nothing to time it out. That is the slow-loris shape still standing, and
  it is a read deadline, not a ceiling.
- **`/dav` has no configuration switch.** It is live wherever a console password
  and a `[[shares]]` block coexist. Authenticated, and behind the console site's
  source gate — but it is the only surface these two subsystems add that is not
  off until a file says otherwise.
- **Nothing publishes the DNS-SD records** a browsable share derives, and Windows
  has no mDNS responder to publish them with even when something does.
- **`selfhost desktop status` answers from the config alone** and cannot see a
  running daemon; `doctor` is the command that asks one.

## Things not to do

Learned the expensive way during the build.

- **Do not reintroduce a container runtime.** It was removed for a specific
  reason: on Windows and macOS it requires a logged-in desktop session.
- **Do not add an external reverse proxy, DNS server, or mail server.** The
  whole point is that the protocol logic is ours. `rustls` and `tokio` are the
  agreed exceptions — cryptography and the async runtime, at the same level as
  the standard library.
- **Do not "fix" strict framing by being lenient.** Every heuristic is a guess
  about what some other implementation would have guessed, and the gap between
  two guesses is the smuggling vulnerability.
- **Do not pop `..` in paths.** `files::resolve` refuses instead, so an attempt
  cannot silently serve a different file and hide itself.
