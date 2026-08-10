# Handoff — selfhost

**Started:** 2026-07-26 · **§3 and §5 rewritten:** 2026-08-10 ·
**Repo:** <https://github.com/RockyWearsAHat/selfhost> · **Branch:**
`service-manager` (production tracks `main`)
**Prior session:** the question that started this is in
`/tmp/lvlup-self-hosting-handoff.md` — hosting websites from a spare PC, free,
unrestricted, load balanced.

> **Read this first.** Production is ALEX-DESKTOP (Windows, `192.168.1.8`), a
> clone of this repo that self-updates from pushes to `main` (`[self_update]`,
> 60 s poll → fetch, rebuild, restart). The admin console SPA (`sites/console`)
> is live at `admin.rockywearsahat.com`, VPN-gated to loopback. Two large
> subsystems — **remote desktop** and **network storage** — landed on this
> branch on 2026-08-10 and have never run on that box. §3 is the current state
> and §5 is what has to be confirmed there, in order. **Do not soften §3: about
> nine thousand lines of this workspace have never executed anywhere.**
>
> The maps are elsewhere and are kept true: `index.dx` (the file tree),
> `selfhost.dx` (the platform in one page), `desktop-lab.dx` and `nas-lab.dx`
> (the two new subsystems, with runnable checks), `console-lab.dx` and
> `web-console-lab.dx` (the two consoles), `docs/SECURITY.md` (the guidebook
> you must read before writing anything networked). This file is orientation
> and judgement; it does not repeat them.

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
- **`ring`** — the one cryptographic implementation, and `rustls`/`rcgen` are
  both pinned to it. Accepting each crate's default provider compiles *two*
  independent crypto stacks into one binary, which is two supply chains and two
  advisory feeds to do one job.
- **`serde` + `toml`** for the config format.
- **`rcgen`** for self-signed certificate generation, and **`webpki-roots`** for
  the trust anchors ACME and the mesh dialler verify against.

Nothing else, and the six crates added in 2026-08 kept to it: `ws`, `identity`,
`desk`, `mesh`, `screen` and `storage` add **no** crates.io package between them.
Platform integration is raw `extern "C"`/`extern "system"` FFI, and the operating
system's own SMB server is driven as a program the way `git` and `ssh` are.

Everything above the socket is written here: HTTP parsing, the reverse proxy,
load balancing, health checking, byte ranges, ACME, the DNS wire format, SMTP,
IMAP, RFC 6455 WebSockets, WebDAV, and this project's own remote-desktop
protocol. If a protocol is on the wire, we own it.

**Do not reintroduce a container runtime or an external server binary.** The
reason is concrete, not aesthetic: on Windows and macOS a container runtime
requires a logged-in desktop session. The target is a Windows PC that must stay
up unattended. We hit this live during the session — the stack needed
`open -a Docker`, a GUI launch, to come up.

## 3. State — what is verified, and where

**3,117 tests pass** (`cargo test --workspace`), `cargo clippy --workspace
--all-targets` is silent, `cargo build --workspace` warns about nothing, and the
whole workspace also type-checks for `x86_64-pc-windows-gnu`. That last figure is
the one that matters most and is the one most easily misread — see *§3.3 What has
never executed*.

The per-crate table that used to live here is gone rather than updated: it went
stale between sessions and it duplicated `docs/roadmap.md`, which is the
authoritative list and is kept current crate by crate. `index.dx` is the file-tree
map. What follows is only what those two cannot say.

### 3.1 Verified against a running instance

Everything in this list was done by running it, not by testing it:

- **The public web path.** HTTPS 200 on a real trusted Let's Encrypt production
  certificate for the deployed domain and its `www`, HTTP→HTTPS 308 preserving
  path and query, `206` + `Content-Range` on a seek, `416` on an impossible
  range, `304` with zero bytes on both cache validators, `.m3u8`/`.ts` content
  types, traversal → 404, smuggling → 400, an ACME challenge served over
  cleartext while ordinary paths still redirect, and a full failover cycle across
  two live backends (5/5 → one killed → 10/10 to the survivor with no failed
  request → restarted → back to 5/5 → both down → 502).
- **Mail.** A real message accepted over port 25 from an external network and
  read back out of the Maildir; STARTTLS on 25 presenting the same trusted
  certificate the site serves; Apple Mail set up against IMAP end to end (which
  needed command-literal parsing — `LOGIN` credentials arrive only that way).
- **DNS.** Real clients resolved through `watch-dns` over UDP and TCP, and a
  lookup of a known proxy domain named the address that made it.
- **Deployment.** A service installed through the control API cloned a GitHub
  branch, ran its build step, and started; a second commit stopped it, updated
  the working copy, and started it on the new commit.
- **The route to the console.** `admin.rockywearsahat.com` answers 200 with TLS
  through the Secure-VPN tunnel, verified end to end on 2026-08-09.
- **The native console against a live daemon.** Services listed, definitions
  shown, output tailed, and start/stop/restart/install/uninstall driven from it,
  including over a managed `ssh -L` tunnel whose refused key was reported as
  *tunnel down · the server refused the key · `ssh-add`* rather than as a missing
  daemon.

### 3.2 The two new subsystems, and exactly how far they got

Both are **off unless a file says otherwise** and **neither binds a socket** —
checked rather than asserted: there are zero occurrences of `TcpListener`,
`UdpSocket` or `::bind(` in `crates/{desk,screen,ws,mesh,identity,storage}`. The
admin API is still `127.0.0.1:9191` and the only public surface is still the
proxy on 80/443.

**Remote desktop** (`desktop-lab.dx` is the document; `docs/SECURITY.md` §3.7
SCR-01…03 is the specification). The protocol, the capture and injection layers,
the ticket mint, the freshness rule, the per-message capability re-check, the
audit trail, the kill switch and both consoles' plates are written and tested. On
this Mac the whole recovery path is exercised without a display by feeding
observations to a state machine. **What is not done:** the agent's frames do not
reach a viewer on a session-0 Windows service — the *splice* between the agent's
message stream and the daemon's `FrameSource` seam is unwritten, and until it
exists a session-0 daemon supervises a live agent and tells the console it cannot
reach the desktop, with the reason. A Windows daemon started from a signed-in
session captures directly and that path is served in full. **And one thing that
reads stronger than it is:** the daemon drives sessions with `TicketStanding`
(`crates/cli/src/desk_task.rs`), which reports the standing the *ticket*
established, so a mid-stream revocation ends the stream at its ceiling rather
than at the next keystroke. The real directory (`Api::standings`) exists and is
not wired. Three lines in `crates/cli`, no interface change.

**Network storage** (`nas-lab.dx`; `docs/SECURITY.md` §3.7 NAS-01…03). Shares,
the confining resolver, the descriptor walk, quotas, the JSON API and its bulk
byte plane, WebDAV at `/dav` (relayed by the proxy, answered by the admin API
behind its own Basic-over-TLS door), the SMB reconciler for all three platforms,
DNS-SD derivation, `selfhost share|sync|storage` and the doctor checks are
written and tested. The acceptance test that mattered passes on this Mac: a full
`sync()` leaves `sharing -l -f json` **byte-identical**, so the pre-existing
guest share point survives untouched. **What is not done:** no real client has
ever mounted a share — no Finder, no Explorer, no `cadaver`; nothing publishes
the DNS-SD records; `storage smb apply` has deliberately never been run; and
`/dav` has **no configuration switch**, so it is live wherever a console password
and a `[[shares]]` block coexist.

**The peer mesh** is dialled but not answered: `crates/mesh/src/accept.rs` exists
and the owner has **no `/api/mesh/link` route**, so a worker's dial lands on a
404 and the registry records the reason. The dialler also verifies the owner's
certificate against the bundled Mozilla roots with no accept-any path, so an
owner on `acme = "self-signed"` cannot be dialled at all.

### 3.3 What has never executed, anywhere

Be exact about this, because everything above is macOS.

- **7,292 lines live in Windows-only files** — `crates/screen/src/windows/*`
  (5,131), `crates/rui/src/shell/platform/windows.rs` (980),
  `crates/storage/src/fs/windows.rs` (634), `crates/storage/src/smb/windows.rs`
  (547) — and with the `cfg(windows)` arms in `crates/cli`
  (`desk_local`, `desk_supervisor`, `service_install`), `crates/admin/src/token.rs`,
  `crates/rui/src/shell/fonts.rs` and `crates/firewall/src/backend/netsh.rs`, it
  is **roughly nine thousand lines**. None of it has ever run. Not once, not
  anywhere.
- **What the Windows check does and does not prove.** `cargo check --workspace
  --all-targets --target x86_64-pc-windows-gnu` passes cleanly — test targets
  included, no diagnostics — and that is worth having: the
  struct layouts, the `extern "system"` signatures and the whole call graph
  compile against real Windows headers, so a wrong argument type or a missing
  field is a build error here rather than a crash there. It proves **nothing**
  about linking and **nothing whatever** about behaviour. Note the invocation —
  the `cargo` and `rustc` on `PATH` are Homebrew's and have no Windows std, so
  the rustup shims must come first on `PATH`, not merely be named by absolute
  path. Getting that wrong reports `can't find crate for core` on every crate,
  which reads like a broken tree and is a broken command.
- **The X11 backend** type-checks and has never run either. X11 keycodes are not
  mapped at all, so desktop keystroke forwarding from a Linux console does
  nothing — an X11 keycode is an index into a per-server keymap with no fixed
  meaning.
- **No desktop stream has ever crossed a real socket** to a real agent, in either
  console.
- **The SMB backends for Windows and Linux** — the `SmbShare` cmdlets, the
  `icacls` forms, `testparm -s`, `smbcontrol all reload-config` — are written
  from documentation and have met no host. macOS is the opposite: flags read off
  this machine's own `sharing` usage text, parser tested against its real JSON,
  and the `sharing: must be run as root` denial observed by running the command
  unprivileged.
- **Windows discovery is absent, not partial.** Windows has no general mDNS
  responder; Explorer's Network node is WSD and segment name resolution is
  LLMNR. A Mac will not see a Windows box's WebDAV share in Finder however many
  records this code derives. WSD is not implemented.

### 3.4 Two rules that keep catching people

- **A drawing change is not on screen until `scripts/macos-app.sh install` has
  run.** The bundle in `/Applications` holds a *copy* of the binary. See §7.
- **`rui` has its own repository** (<https://github.com/RockyWearsAHat/rui>,
  public, MIT, CI on macOS/Windows/Linux). This workspace builds it from
  `crates/rui` by path, so the two are copies and changes made here have to be
  pushed there. Its own practices document is `crates/rui/rui.dx`.

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

## 5. What must be confirmed on ALEX-DESKTOP, in this order

Everything above is macOS. This is the priority list for the first session on the
Windows box, ordered so that a failure at step *n* makes steps after it
meaningless. **Do not skip ahead to the interesting part**: steps 1 and 2 decide
whether the remote-desktop design works at all on a service deployment, and every
later step assumes them.

1. **Is the daemon actually LocalSystem?** `WTSQueryUserToken` returning
   `ERROR_ACCESS_DENIED` means it is not, and the entire session-0 plan is
   inoperative. The fault names the call. Say so once, loudly, and stop retrying
   in a tight loop.
2. **Does the agent spawn, connect, and stay up?** Watch for three specific
   things: `CreateNamedPipeW` + `ERROR_PIPE_BUSY`/`ERROR_ACCESS_DENIED` (a
   previous agent has not exited, or something local is squatting the name —
   `FILE_FLAG_FIRST_PIPE_INSTANCE` is what makes that detectable rather than
   silent); the agent's `Hello` arriving inside the **20 s start deadline**
   (without `connected` the supervisor kills it as `NeverConnected` and charges
   it a failure, which is a crash loop caused by a missing call rather than a
   broken agent); and the per-hour respawn cap being spent, which surrenders out
   loud and stays surrendered until the operator presses start.
3. **Check the pipe's ACL before trusting anything else.**
   `(Get-Acl \\.\pipe\selfhost-desk-1).Access` must name only
   `NT AUTHORITY\SYSTEM` and the console user. **The DACL is the
   authentication** — there is no agent secret to leak, so a wrong DACL is the
   whole security model gone, not a degraded one.
4. **Confirm UIPI is intact.** With an elevated window focused, keys, text,
   buttons and wheel must be refused with `input-refused (elevated window)` while
   pointer movement still works. Success is never inferred from `SendInput`'s
   return count — UIPI discards silently and `GetLastError` says nothing. **If a
   keystroke reaches an elevated window, stop everything**: that is remote
   privilege escalation, not a feature. The agent is never SYSTEM and never gets
   `uiAccess`; both refusals are permanent.
5. **Confirm the secure desktop is never captured.** A UAC consent dialog or the
   login window must produce a *named state* in the console, not pixels.
6. **Only then, the picture.** A Windows daemon started from a signed-in session
   is the path that is served in full — try that before the service, because it
   isolates a capture problem from the session-0 splice that is still unwritten.
7. **The audit trail.** `wc -l data/audit.log` grows by exactly one line per
   control action; typed text is a unit count and is never quoted. Nothing
   rotates this file — a long drive session is one line per keystroke.
8. **Then storage.** `selfhost storage smb plan`, read it, then `apply`, then
   confirm every pre-existing Windows share point is still there. `New-SmbShare`
   with no access parameter grants `Everyone: Read`, so check that the created
   share names `BUILTIN\Administrators` by SID and that guest exposure reads
   false. Remember 445 is LAN-only, forever, never forwarded, and that
   `selfhost_firewall::desired_rules` does not open it — on a managed firewall an
   export is created, advertised, and unreachable, which is the safe failure.
9. **Then a real client.** Mount a share in Explorer over WebDAV and watch what
   it does with the PROPPATCH `403` it sends after each `PUT` — predicted as
   *"some attributes could not be copied"* with the file itself intact. **The
   Windows mount will not work behind a self-signed certificate**, so this needs
   a real certificate first. Then Finder from the Mac, which is where SMB
   discovery either appears or does not.
10. **`cargo run -p rui --example counter`** on Windows and on Linux. The window
    backends have never been opened. This is cheap, it is the most likely place
    for a surprise, and everything visual depends on it.

**What to do first back on the Mac, independent of the Windows box:** wire
`Api::standings` into `crates/cli/src/desk_task.rs` so a revocation ends a stream
at the next keystroke rather than at its ceiling (§3.2), add
`fn operator_start(&self)` to `selfhost_admin::Fleet` plus a route so the
console's start button has something to call, and decide whether `/dav` should
have a config switch. All three are small and all three are named in the labs.

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
2. **Which domain goes first?** `leveluplongboarding.surf` is on Namecheap DNS
   (not Netlify, contrary to the prior handoff) pointing at Netlify. Recommend
   proving the chain on a throwaway subdomain before cutting the live site over.
3. **Has he verified inbound 80/443 actually reach the machine?** Untestable
   until something listens and the router forwards, and it must be tested from
   *outside* the network. Many ISPs filter them.
4. **Does he want remote desktop turned on at all, and with a keyboard?** It is
   the highest-privilege capability in this repository and it is off by default
   for reasons written out in `docs/SECURITY.md` §3.7 SCR-01. Viewing and driving
   are separate decisions and the second one should be his, explicitly, rather
   than something a session enables to demonstrate it works.
5. **Where should a share be rooted on ALEX-DESKTOP, and does anyone need an OS
   account for SMB?** A root may not sit inside `data_dir`, the TLS store or the
   repository. SMB authenticates against OS accounts, so a person who is to reach
   a share over SMB needs an account on that box — the console password cannot do
   it, on any platform.
6. **Should `/dav` have an off switch?** It is live wherever a console password
   and a `[[shares]]` block coexist, with no `[storage]` setting to disable it.
   Defensible — it is authenticated, and the site it rides is source-gated — but
   it is the one place in these two subsystems where something is on by default.

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
- **Do not "fix" the two injection refusals.** On Windows the injector refuses
  keys while an elevated window has focus, and on macOS it refuses keyboard and
  text while `IsSecureEventInputEnabled` is true. Both look like bugs and both
  are the feature: a channel that can drive a UAC consent dialog or a login
  window is remote privilege escalation. Pointer movement is still injected in
  both cases so the session does not look dead. The agent is never SYSTEM and
  never gets `uiAccess`, forever.
- **A WebDAV `401` must never feed the console's global failure gate.** Every
  WebDAV client's first request is unauthenticated by protocol design, so
  mounting one share would otherwise lock the operator out of the console they
  would use to unmount it. The counter is per credential, deliberately.
- **A refusal after authentication on `/dav` is never a second `401`.** macOS and
  Windows discard the keychain item and prompt for ever when they see one. This
  is the opposite of the uniform-401 rule everywhere else in this codebase, and
  it is safe only because the sole credential that opens `/dav` holds every
  share. If a per-person WebDAV credential is ever added, that reasoning has to
  be revisited in the same edit.
- **Do not pop `..` in a share path, and do not match it before trimming trailing
  dots and spaces.** Windows strips those before the filesystem sees a component,
  so `".. "` passes an exact-equality refusal and normalises back to `..`. That
  is a directory traversal, not a naming nicety, and it is the single most likely
  way a NAS gets rooted. The rule is on every platform and never behind a `cfg`.
- **`crates/proxy/src/files.rs` is not reusable for the share write path** and
  was deliberately not reused: `confine()` canonicalises, which returns ENOENT
  for every path being created, and `resolve` invents paths, which on a file
  share means serving a different file than was asked for.
- **`storage smb apply` can remove an export.** Which is why `apply` is a spelled
  word rather than a flag, dry-run is the default, and the reconciler never
  touches a share point selfhost did not create. The ownership ledger
  (`storage.smb-owned`) is what makes "did not create" a fact rather than a
  guess — do not bypass it to make a cleanup easier.
- **Do not put the desktop input switch on the wire.** It travels on the agent's
  command line, fixed by `CreateProcessAsUserW` at spawn and read once before the
  link is opened. The pipe's DACL admits SYSTEM and the console user's own SID —
  Windows cannot tell two same-user processes apart on a named object — so a
  switch that arrived as a frame would be assertable by anything that can talk to
  the pipe.
- **The console gate is a source address, not an identity.** The tunnel exits on
  loopback, so `allowed_cidrs = ["127.0.0.1/32"]` admits every co-hosted web app
  on this box. Never justify a control by the gate. Every one of them has to
  stand as a credential check, a capability check, a freshness check or a file.

## 8. Suggested skills

- **`/grilling`** before any further architecture — it is how the three good
  redirects happened this session.
- **`/tdd`** for ACME and IMAP. Both are specified protocols with well-defined
  wire behaviour, which is exactly where tests-first pays.
- **`/code-review`** and **`/simplify`** once ACME lands.
- **`/research`** for the two facts that must not be guessed: whether FirstDigital
  will delegate PTR, and current Spamhaus delisting mechanics.
