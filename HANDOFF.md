# Handoff — selfhost

**Written:** 2026-07-26 · **Repo:** <https://github.com/RockyWearsAHat/selfhost> ·
**Branch:** `main`
**Prior session:** the question that started this is in
`/tmp/lvlup-self-hosting-handoff.md` — hosting websites from a spare PC, free,
unrestricted, load balanced.

> **State check 2026-08-10:** production moved to ALEX-DESKTOP (Windows,
> `192.168.1.8`), which is a clone of this repo and self-updates from pushes to
> `main` (`[self_update]`, 60 s poll → fetch, rebuild, restart). The admin
> console SPA (`sites/console`) is live at `admin.rockywearsahat.com`,
> VPN-gated to loopback. §3 below predates that move — `index.dx` is the
> current map; this file remains the July orientation snapshot.

---

## 1. Who you're working with

- **CS student, comfortable in Rust and TypeScript.** Reach for that level.
- **He will interrupt you mid-build to challenge an architectural decision, and
  he is usually right.** Three times this session — Docker, then external
  binaries, then external dependencies generally — each redirect made the design
  better and threw away working code. When he pushes back, engage with the
  argument rather than defending the work already done.
- **He values verified claims over asserted ones.** Every number in
  `docs/constraints.md` was measured. When something cannot be measured yet, say
  so plainly instead of estimating.
- **He will tell you when an estimate is wrong.** "Outbound direct is dead on
  arrival" got challenged, and checking properly showed the Spamhaus listing was
  IP-specific and self-service removable. He was right to push.
- **Read first:** `~/.claude/CLAUDE.md` (working discipline, caveman comms with a
  self-decided bypass for genuine architecture reasoning — an architecture
  discussion qualifies, and this project is full of them).

## 2. What this is

A self-hosting platform in Rust. One config file, one binary, no vendor in the
data path.

**The dependency policy is the project's defining constraint, and it was his
call, made explicitly:**

> "We already have something similar in the windows service manager, take docker
> out we write our code, we test our code, we make our code as good as it can
> be."

> "Own everything including mail."

Permitted dependencies, and nothing else:

- **`rustls`** for TLS primitives and **`tokio`** for async I/O — foundations at
  the same level as the standard library. Hand-writing cryptography would make
  this less safe, not more independent.
- **`serde` + `toml`** for the config format.
- **`rcgen`** for self-signed certificate generation.

Everything above the socket is written here: HTTP parsing, the reverse proxy,
load balancing, health checking, byte ranges, SMTP, and — planned — ACME, DNS,
and IMAP.

**Do not reintroduce a container runtime or an external server binary.** The
reason is concrete, not aesthetic: on Windows and macOS a container runtime
requires a logged-in desktop session. The target is a Windows PC that must stay
up unattended. We hit this live during the session — the stack needed
`open -a Docker`, a GUI launch, to come up.

## 3. State — done vs not

**816 tests pass.** `cargo test --workspace`; the table below sums to the same,
doc-tests included.

| crate | what | tests |
|---|---|---|
| `crates/http` | HTTP/1.1 messages + dates, pure, no I/O | 70 |
| `crates/config` | Config model + validation, the Git watch, the daemon note | 57 |
| `crates/json` | JSON, for the control API | 13 |
| `crates/proxy` | TLS, static+Range, caching, routing, LB, health | 60 |
| `crates/mail` | Addresses + SMTP session state machine | 48 |
| `crates/dns` | DNS wire format + resolver | 22 |
| `crates/supervisor` | Runs services and keeps them running | 50 |
| `crates/admin` | The loopback control API | 29 |
| `crates/git` | Watches a branch; stops, updates, builds, starts | 37 |
| `crates/rui` | **`rui`**: the interface library — elements, style, layout, rasteriser, TrueType engine, animation, PNG, windows, headless test harness | 263 |
| `crates/console` | The `selfhost-console` desktop binary + SSH tunnel | 80 |
| `crates/cli` | The `selfhost` binary, `doctor`, LAN assessment, `watch-dns`, `teardown` | 87 |

**Verified against a running instance,** not only in unit tests: HTTPS 200,
HTTP→HTTPS 308 preserving path and query, `206` + `Content-Range` on a seek,
`416` on an impossible range, `.m3u8`/`.ts` content types, path traversal → 404,
smuggling → 400, and a **full failover cycle** with two live backends — 5/5
split, one killed → 10/10 to the survivor with no failed requests, restarted →
back to 5/5 unaided, both down → 502.

**The console is built and runs.** `selfhost-console` is a native window drawn
by an interface library written here, over a per-platform layer that only opens a
window, delivers input, and copies a buffer to the screen. Verified against a
live daemon: services listed and selected, definitions shown, output tailed, and
start/stop/restart/install/uninstall driven from it. See
[`docs/gui.md`](docs/gui.md).

**The toolkit is now a library in its own right: `rui`.** It was
`selfhost-ui` + `selfhost-window` — an immediate-mode toolkit whose call sites
did their own rectangle arithmetic (`split_left`, `control_rect`, `allocate`).
It is now one dependency-free crate with a **declarative** interface: a view is
`Fn(&State) -> El<State>`, structure and style and behaviour are one chained
expression, and a handler is an ordinary `Fn(&mut State)` — so the description
borrows nothing mutably and there is no `Rc`, `RefCell`, or interior mutability
anywhere in it. Layout is the useful half of flexbox (`grow`, `Fraction`,
`min/max`, shrink-what-is-sized-to-content), colours are *roles* resolved against
the theme, and text properties inherit. The console was rewritten onto it: its
views are ~40% shorter and contain no rectangle arithmetic at all. `rui` knows
nothing about selfhost and is documented on its own terms in
[`crates/rui/README.md`](crates/rui/README.md);
`cargo run -p rui --example counter` is a whole program in thirty lines.

**`rui` now has its own repository, and a foundation you can build controls
on:** <https://github.com/RockyWearsAHat/rui>, public, MIT, with CI on macOS,
Windows, and Linux. This workspace still builds it from `crates/rui` by path, so
the two are copies — changes made here have to be pushed there.

It could draw a button and it could not draw a slider, because `draw` was handed
a rectangle and nothing about its own state, and there was no access to the
pointer beyond a click. So: `Painter::visual` tells an application's own drawing
what a button knows (hovered, held, focused, disabled, and how far its hover has
eased); `on_drag` reports where the pointer is *within* an element every frame it
is held; `on_key`, `on_scroll`, and `on_hover` hand over the keyboard, the wheel,
and the pointer arriving; `.layer(Anchor)` hangs an element off its parent's
edge, held inside the window and drawn above what it covers, which is what a
menu, a tooltip, and a dialog are; and `.flow()` runs children onto further
lines. What the pointer is over is now decided once per frame rather than by each
element for itself, so two overlapping things can no longer both think they are
hovered. **No checkbox, toggle, or slider was added** — `examples/controls.rs`
builds all of them from those primitives in a few lines each, and
`tests/recipes.rs` tests them.

**And it is testable without a window.** `rui::testing::Harness` drives the real
frame — describe, lay out, draw, apply — into a buffer, aiming at what a person
would aim at (`click_text`, `hover_text`, `drag`, `type_text`), and answering
where things came out, what the interface says, and what was drawn.
`rui::testing::font` **builds** a TrueType face a table at a time, read back by
the same parser that reads one off the disk, at half an em to a glyph and an em
to a line — so a width in a test is arithmetic rather than whatever face the
machine happened to have. Writing those tests turned up two layout defects, both
now fixed: a box that stated its own width measured its children against the room
it was *offered*, so a paragraph in a narrow column came out one line tall and
three lines long; and a child sized to its content could be laid out wider than
the box that owned it.

**The console has been laid out again, and every part of it went into the
toolkit rather than being drawn into the views.** The interface is *ruled rather
than boxed*: two framed surfaces in the whole window, and inside them
small-capital section labels with a hairline running to the far edge
(`section`). Small capitals needed real letter-spacing, so
`TextStyle` grew a `tracking` field applied in the single advance that
measuring, fitting, wrapping, and drawing all share.

**The look it was given on top of that was wrong, was redone, and is now an
instrument on purpose.** The first version cut corners on everything, put a cyan
accent on a blue-black ground, ruled a grid across the window, haloed panels,
buttons, tabs and status dots alike, bracketed the log, drew a segmented gauge,
and set the title, tabs, headings and figures monospaced and tracked open. Every
one had its own argument; together they read as a film prop. The correction made
`rui` itself rounded, near-neutral and blue-accented — which is what the library
still is and what its defaults still produce.

The console then took the seams the library offers (`App::theme`,
`Theme::with_palette`, `Theme::with_corners`, `App::ground`) and spent them on
a face of its own: a HUD one step off black with one electric cyan, chamfered
plates with corner brackets, every control milled to the same cut as the plate
it sits in, a viewport frame scribed at the window's own edge, a ring gauge
with a lit core, a lamp that pulses when it wants attention, and a sweep of two
counter-rotating arcs drawn only while a link is being made. What keeps that
from being the costume again is stated as three rules — the shape is the only
word the console respells, glow is a fact and not a filter, two hues at rest —
in *And then it was made an instrument on purpose* in
[`docs/gui.md`](docs/gui.md), which keeps the reasoning so it is not repeated.
The fixed-width face is reserved for text the machine produced, and
`cargo run -p rui --example gallery -- .` — and the console's own
`SELFHOST_FRAME_DIR=<dir> cargo test -p selfhost-console reference_frames` — is
how an appearance change is judged before it is committed to.

Two sizing rules replaced numbers somebody had picked: the rail is a share of
the window instead of a fixed 292 units, and the log is promised its height
(`min_h`) while the definition is what shrinks and scrolls. Both are now stated
in the description rather than computed — the layout takes room back off
whatever is sized to its content, so nothing has to work out what fits.

A whole frame at 980 by 680 Retina costs **1.9 ms** measured, against the 8 ms
an animating frame has; it rose about a fifth because there is more interface in
the same window, not because a mark got dearer. The animation clock is *given*
to `rui`, never read by it, which is what keeps easing assertable with no
display. Frames are checked two ways with no window: font-less, so every box
comes out at its minimum and a layout that only fitted because a label was short
fails; and with the real faces via `reference_frames`, which writes every screen
the console can be on out as PNGs and prints that timing table. See
[`docs/gui.md`](docs/gui.md).

**Only ever run on macOS.** The Windows and X11 backends type-check for their
targets and have never been executed. That is the first thing to try when the
Windows machine arrives, and the most likely place for a surprise.

**The console installs as a real macOS application.** `scripts/macos-app.sh
install` builds it, draws the icon, bundles it, installs it to `/Applications`,
pins it to the Dock, and reopens a console that was running so the window on
screen is the build that was just made; `uninstall` reverses all of that. **It
is also the only way a code change reaches that window — see §7.** The icon is
*drawn*
by the library at every size macOS asks for (`crates/rui/examples/icon.rs`, via
the PNG writer in `crates/rui/src/image.rs`) rather than stored as a binary
nobody can review. Verified: the bundle opens from the Dock, and a console
opened before its daemon says so in the header and connects by itself once the
daemon starts.

**Resizing the window used to smear, and no longer does.** macOS tracks a live
resize in a nested run loop that does not return until the drag ends, so the
console drew nothing for the whole gesture and the compositor stretched the last
frame to each new size. A run-loop observer registered for the common modes now
draws from inside AppKit's own loop; three separate ten-megabyte-per-frame costs
were removed alongside it. The full reasoning is in
[`docs/gui.md`](docs/gui.md). **The mechanism is unit-tested but the *feel* of a
drag needs a hand on a mouse — that is the one thing still worth checking by
hand.**

**One crypto stack, not two.** `rustls` defaulted to `aws-lc-rs` while `rcgen`
used `ring`, so every binary carried two independent cryptographic
implementations — two lots of C and assembly, two supply chains, two sets of
advisories. Both are now pinned to `ring`; the lock file went from 87 packages
to 78, and a TLS 1.3 handshake was verified live afterwards rather than
assumed.

**The console reaches a remote daemon, and a push redeploys a service.** Both
are done and verified live, and both are documented in
[`docs/gui.md`](docs/gui.md):

- `selfhost-console --ssh you@server` runs `ssh` as a managed child, forwards the
  control port to loopback here, and reads the daemon's token over the same
  connection. It answers no prompts — `BatchMode=yes` turns each question `ssh`
  would have asked into a failure, and the console turns that failure into the
  command that fixes it, in a banner across the window. Verified against a real
  `sshd` that refused the key: the console said *tunnel down · the server refused
  the key · `ssh-add`*, not *no daemon*, and retried with a growing backoff.
- A service can carry `[service.git]`, and when the branch moves the daemon
  **stops** it, updates the working copy, runs `post_pull`, and starts it again —
  never `restart`, which would race the supervisor's own restart policy. Verified
  live: a service installed over the control API cloned a GitHub branch, ran its
  build step, started, and printed the checked-out file; a second commit stopped
  it, reset the working copy, and started it on the new commit.

**Not built:** ACME (so nothing can be published to a real browser yet), DNS,
the mail connection layer, IMAP, MIME, service install as a system service, node
join, backups, the console's sites-and-certificates views, a webhook receiver to
make a poll happen sooner, and an OAuth device flow for repositories the daemon's
own SSH key does not reach. Full detail and ordering in
[`docs/roadmap.md`](docs/roadmap.md).

## 4. Measured facts — do not re-derive

All in [`docs/constraints.md`](docs/constraints.md). The two that overturn
assumptions from the prior handoff:

**Upload bandwidth is not the constraint.** Assumed ~25 Mbps; measured 99–508
Mbps over Wi-Fi. Even the low reading carries ~40 concurrent 1080p renditions.
The prior handoff's central worry about home-hosting a video site is void.

**Not behind CGNAT, but behind two NATs.** `172.83.7.210` is routable with real
reverse DNS, so the tunnel-based designs that existed to survive CGNAT are
unnecessary. The Netgear is not the edge, though — it NATs to `10.0.12.184`, and
an upstream box you cannot log into holds the public address. Outbound is
unaffected; **inbound needs a forward on both boxes**, so settle it with
FirstDigital before building anything that depends on port 80.

**Mail is the genuinely hard part, and it is environmental, not code:**

- Spamhaus **XBL + CSS listed** — IP-specific; sampled `/24` neighbours are
  clean, so the cause is on this network. **Read on 2026-07-27 from the listing
  detail itself**, which is the evidence that matters and is not fetchable by
  code (Cloudflare refuses non-browser requests):
  - Spamhaus classifies `172.83.7.210` as **part of a proxy network** — malware
    installing a proxy on some device, sending spam **directly to port 25**.
  - Most recent connection they logged: **2026-07-26 19:30 UTC, HELO
    `[172.19.0.8]`**. That address is not on the `192.168.1.0/24` LAN, and it is
    **not** the upstream `10.0.0.0/8` hop either — `172.19.0.0/16` sits inside
    Docker's default bridge pool (`172.17`–`172.31`). So the likeliest sender is
    a **container** (or a VM / VPN virtual adapter) on one of the LAN devices,
    announcing its private container address. It is invisible to a LAN sweep
    twice over: the sweep sees the host, never the bridge network inside it.
  - **Check the container hypothesis first**, on every device that runs Docker or
    a VM: `docker network inspect bridge` and `docker ps` will name what holds
    `172.19.0.x`. That is a cheaper and better-supported lead than the upstream
    segment, which uses different address space entirely.
  - The delisting form **rejects free webmail** (`@gmail` and the rest). Use an
    address at a domain he controls.
- **FCrDNS fails**: the PTR `172-83-7-210.ip.fdtnet.net` has no forward A
  record. This one needs FirstDigital to fix or delegate.
- Outbound port 25 is **open**, and inbound mail is unaffected by any of it.

Consequence, already reflected in the design: outbound supports **both** `direct`
and `relay` as first-class modes, and `selfhost mail doctor` should *measure*
which is usable rather than anyone guessing.

## 5. What I'd do next

In order, with the reasoning in `docs/roadmap.md`:

1. **ACME client (RFC 8555).** Unblocks everything public. HTTP-01, since we
   already own port 80 — do not couple it to the DNS server that does not exist
   yet. The redirect exemption and token serving are **already done**: write
   tokens into `data/acme-challenges/<token>` and the proxy serves them over
   cleartext without redirecting.
2. **SNI certificate selection** — today one certificate carries every hostname.
3. **Mail connection layer** → Maildir store → MIME → IMAP.
4. **DNS**, with a free secondary (Hurricane Electric). A single authoritative
   home box means the domain stops resolving when it is down, which takes mail
   with it.
5. **Service install** — Windows SCM first; it is why Docker went.

## 6. Open questions for him

0. **Where should the project live?** It is on the Desktop, and macOS therefore
   asks the bundled console for permission to read the Desktop folder every time
   it is rebuilt — an ad-hoc signature is derived from the binary's contents, so
   each build is a new identity to TCC. Moving the project somewhere ordinary
   (`~/Projects/selfhost`) removes the prompt entirely and is the cheaper fix
   than obtaining a signing certificate.
1. **Has the proxy device been found and taken off the network, and has he
   opened a ticket with FirstDigital about the missing forward record for his
   PTR?** Delisting before the device is found earns a second, stickier listing —
   XBL expires on its own once the behaviour stops. `selfhost watch-dns` is the
   vantage point that names the device, but it only sees devices the router has
   pointed at this machine, which is a change he has to make in the router.
   The call itself is scripted in [`docs/isp-script.md`](docs/isp-script.md) —
   its first question, whether `172.83.7.210` is dedicated or shared, decides
   whether the infected device is even on this network.
2. **Is the Windows PC available yet, and what are its specs?** Everything has
   been built and tested on the Mac. Nothing is Mac-specific, and the
   cross-compile targets are installed, but it has never been run on Windows.
3. **Which domain goes first?** `leveluplongboarding.surf` is on Namecheap DNS
   (not Netlify, contrary to the prior handoff) pointing at Netlify. Recommend
   proving the chain on a throwaway subdomain before cutting the live site over.
4. **Has he verified inbound 80/443 actually reach the machine?** Untestable
   until something listens and the router forwards, and it must be tested from
   *outside* the network. Many ISPs filter them.

## 7. Traps

- **A change to the console is not delivered until `scripts/macos-app.sh
  install` has run.** He looks at the application in `/Applications`, and that
  bundle holds a *copy* of the binary — editing `crates/rui` or `crates/console`,
  or even running `cargo build`, changes nothing about what is on his screen.
  This is not hypothetical: a whole session of interface work was reported as
  done and looked untouched to him, because the bundle was three hours older
  than the code. So: **any session that touches `crates/rui`, `crates/console`,
  or the icon ends with `scripts/macos-app.sh install`, before
  the work is called done.** The script quits a running console, force-closing
  one that will not go, and reopens it afterwards if it was open — assume he is
  developing, that the console is running, and that he will look at it the
  moment you stop, so leave the installed build current and running rather than
  asking him to restart anything. Never ask him to close it for you.
- **Do not be lenient about HTTP framing.** Every heuristic is a guess about
  what some other implementation would have guessed, and that gap is the
  smuggling vulnerability. `crates/http/src/request.rs` rejects ambiguity on
  purpose.
- **Do not pop `..` in paths** — `files::resolve` refuses instead, so an attempt
  cannot silently serve a different file.
- **Do not touch the open-relay rule in `smtp.rs` without reading its tests.**
  It is one rule in one place, and the tests cover the ways it gets bypassed:
  case-folded domains, obsolete source routes, and the null path as recipient.
- **`acme = "production"` allows five duplicate certificates per week.** Climb
  the ladder: `self-signed` → `staging` → `production`.
- **Proxied responses deliberately close the connection.** It costs a setup per
  request but guarantees our framing and the upstream's cannot disagree. Fixing
  it means parsing upstream framing — reintroducing the exact risk the HTTP crate
  exists to prevent. Careful or not at all.
- **Do not let the console answer an `ssh` prompt.** Accepting an unknown host
  key on the operator's behalf throws away the only check that makes the tunnel
  worth anything, and a passphrase prompt with no terminal hangs the window with
  no visible cause. `BatchMode=yes` is why neither can happen; the fix belongs in
  `advice_for`, as a sentence telling the operator what to run.
- **Do not weaken the loopback check in `selfhost_admin::bind`** to make remote
  access easier. That check is the security boundary and the tunnel is the answer.
- **A deployment stops the service; it does not restart it.** Updating a working
  copy under a running process makes its exit look like a crash, and the restart
  policy then fights the deployment for the process. The sequence and its reason
  are in `crates/git/src/deploy.rs`.
- **A repository URL is untrusted input.** It arrives over the control API, and
  `git`'s `ext::` transport runs its argument as a command. The transports are an
  allow-list in `selfhost_config::git`; do not widen it to "whatever git accepts".
- **The console writes `data/services.toml` and nothing else.** The old rule was
  that the GUI must stay read-only, so `selfhost.config.toml` remained the single
  source of truth; that is gone, because a service manager that cannot install a
  service is not one. The concern behind it still holds and is met differently:
  two files, one writer each. A person writes `selfhost.config.toml` by hand and
  the daemon never touches it — serialising it back would destroy every comment
  in it, including the ACME rate-limit warning. The daemon owns
  `data/services.toml`. Do not give either file a second writer.

## 8. Suggested skills

- **`/grilling`** before any further architecture — it is how the three good
  redirects happened this session.
- **`/tdd`** for ACME and IMAP. Both are specified protocols with well-defined
  wire behaviour, which is exactly where tests-first pays.
- **`/code-review`** and **`/simplify`** once ACME lands.
- **`/research`** for the two facts that must not be guessed: whether FirstDigital
  will delegate PTR, and current Spamhaus delisting mechanics.
