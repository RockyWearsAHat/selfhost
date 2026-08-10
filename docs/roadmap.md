# Roadmap — what is done, and what is left

Honest state of the project. Anything marked **done** has tests and has been
exercised against a running instance; anything else has not been written.

## Done

| area | crate | tests | evidence |
|---|---|---|---|
| HTTP/1.1 messages + dates | `crates/http` | 70 | header injection, request smuggling, byte ranges, cache validators |
| Config model + validation, surgical config editing | `crates/config` | 106+ | every problem reported at once, field-named; a repository URL that would run a command refused; `site`/`mail add|remove` edit the file as text and preserve every comment |
| Proxy: TLS, SNI, static, caching, LB, live routing reload | `crates/proxy` | 69 | path traversal, Range, 304, health hysteresis; a config edit hot-reloads the routing table with no dropped connection |
| ACME client (RFC 8555) | `crates/acme` | 44+ | full issuance walked live against Let's Encrypt staging *and* production; a CSR's subject is cleared so a CA cannot mistake rcgen's own placeholder name for the domain |
| Mail: SMTP, submission, DKIM, outbound, IMAP | `crates/mail` | 140 | open-relay defence, credential protection, framing; a message sent by raw SMTP was read back out of the Maildir; IMAP LOGIN/SELECT/FETCH/STORE walked end-to-end over a live connection |
| DNS wire format + resolver + authority | `crates/dns` | 22+ | compression pointers, loops, truncation, SOA contacts; authoritative zone serving wired into `daemon` |
| `doctor`, LAN assessment, DNS watch, mail diagnostics | `crates/cli` | 100+ | service identified by behaviour, hardware named, one conclusion; a proxy lookup names the device that made it; `doctor --deep` measured a live ISP's outbound-25 block and PTR gap rather than assuming either |
| JSON values, parsing, serialisation | `crates/json` | 13 | control characters escaped, depth bounded, trailing input refused, surrogate pairs |
| Service supervision | `crates/supervisor` | 50 | restart backoff and its reset, log gaps reported, process groups killed whole |
| Service catalogue + control API | `crates/admin` | 29 | loopback-only bind, constant-time token, atomic catalogue writes |
| Git deployment: watch, pull, build, restart | `crates/git` | 37 | a push reaches the running service, a failed build leaves it stopped, untracked files survive |
| Host firewall reconciliation | `crates/firewall` | — | macOS pf, Linux nftables, Windows netsh backends behind one `Manager`; default-inbound-block plus named openings, drift re-asserted on a timer |
| A declarative interface library, `rui` | `crates/rui` | 263 | layout, hit testing, focus, scrolling, dragging, easing, and a whole frame — all with no display attached |
| The console itself | `crates/console` | 91 | frames rendered headless at the smallest window; a tunnel that dies takes its `ssh` with it |

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

Outbound direct delivery (`crates/mail/src/client.rs`) is real and TLS-capable,
but whether it can be *used* is an environment fact, not a code one — see
`constraints.md`. A `[mail.relay]` smarthost is the alternative already built
for exactly the deployments where direct delivery is blocked upstream.

## Next, in the order I would do it

### 1. Node join and the private mesh

`Config::instance_address` already refuses to address a worker that has no
`mesh_ip`, so the config layer is ready. What is missing is the mesh itself and
a one-command join.

The rule to preserve: **workers are reached over the mesh, never a public
address**, so an application port is never exposed to the internet even on a
remote machine.

### 2. Backups

Nightly dump plus an off-site copy. **Untested backups are not backups** —
restore has to be exercised, not assumed.

### 3. The console

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

What is left is the **sites and certificates** views, which wait on an API that
reports them, and **running the Windows and X11 backends** — both type-check for
their targets but have never been run, because everything so far has been built
on a Mac.

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
