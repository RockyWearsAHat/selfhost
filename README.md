# selfhost

Host websites, databases, DNS, mail, files, and a machine's own screen from your
own hardware. One config file, one binary, no vendor.

## Why this exists

The starting question was whether a spare PC could replace a stack of paid
services. Measured on the target connection before any of this was designed:

| fact | measurement |
|---|---|
| upload bandwidth | 99–508 Mbps (Wi-Fi, two runs) |
| idle latency | ~31 ms |
| public IP | routable, **not** CGNAT |
| outbound SMTP (:25) | open |
| reverse DNS | generic ISP PTR, **no forward A record** |

Upload bandwidth was assumed to be the thing that made home hosting unworkable
for a video-heavy site. It is not: even the low reading carries roughly 40
concurrent 1080p streams. The genuine obstacles are elsewhere, and are recorded
in [`docs/constraints.md`](docs/constraints.md) rather than discovered twice.

## What it does not depend on

There is no container runtime, no reverse-proxy binary, no DNS server, and no
mail server in this project's dependency list. Those are all written here.

Two exceptions, both deliberate:

- **`rustls` for TLS, `tokio` for async I/O.** These are foundations, at the
  same level as the standard library. Hand-writing cryptography would make this
  less safe, not more independent. `rustls` and `rcgen` are both pinned to
  **`ring`** rather than to their own defaults: accepting the defaults compiles
  two independent cryptographic implementations into one binary — rustls brings
  `aws-lc-rs` and rcgen brings `ring` — which is two lots of C and assembly, two
  supply chains, and two sets of advisories to do one job.
- **MongoDB**, because the first site hosted on this platform already stores its
  media there.

Two programs are *run* rather than depended on, and both sit outside the data
path — nothing a visitor sends reaches either:

- **`ssh`**, as the console's transport to a remote daemon. The authentication
  and encryption of the channel that controls every service on a machine are not
  a place to debut new cryptography, and OpenSSH already holds the operator's
  keys and known hosts.
- **`git`**, when a service is configured to redeploy from a branch. It runs only
  when an operator's own branch moves. Reimplementing the pack protocol would buy
  no independence — the repository is GitHub's either way.

Everything above the socket is ours: HTTP parsing, the reverse proxy, load
balancing, health checking, byte ranges, ACME, the DNS wire format, SMTP, IMAP,
RFC 6455 WebSockets, WebDAV, and this project's own remote-desktop protocol. The
six crates added in August 2026 — `ws`, `identity`, `desk`, `mesh`, `screen`,
`storage` — add **no** package to the dependency list between them; platform
integration is raw FFI, and the operating system's own SMB server is *run* rather
than reimplemented, like `ssh` and `git`.

The reason is not purity. An external binary drags in its own release cadence,
its own platform matrix, its own checksum-and-download layer, and its own
failure modes — and on Windows and macOS a container runtime additionally
requires a **logged-in desktop session**, which is disqualifying for a machine
whose job is to stay up unattended.

## Status

**3,117 tests pass.** The proxy runs and serves, the daemon supervises
services, the desktop console drives it — over an SSH tunnel it manages itself —
and a push to a watched branch redeploys the service built from it. ACME
issuance, the authoritative DNS server (split-horizon, dynamic apex A), the mail
server (SMTP, submission, IMAP), the firewall manager, and the web console all
run today — [`docs/roadmap.md`](docs/roadmap.md) has the honest breakdown of
what remains.

Two subsystems landed in August 2026 and both are **off unless a file says
otherwise**: **network storage** (shares served over the console API, over
WebDAV at `/dav`, and over the operating system's own SMB server) and **remote
desktop** (a machine's screen and keyboard, reached through the console site,
authorised by a single-use ticket rather than a cookie, with watching and driving
as separate capabilities and driving requiring a *fresh* credential). Neither
binds a socket — the admin API is still loopback-only and the only public surface
is still the proxy on 80/443. Neither has ever run on Windows: about nine
thousand lines of Windows-only code type-check for `x86_64-pc-windows-gnu` and
have never executed. `docs/labs/desktop-lab.dx` and `docs/labs/nas-lab.dx` carry the evidence,
including what is unverified, and `docs/SECURITY.md` §3.7 is the specification
they answer to.

Selfhost also updates *itself*: an opt-in `[self_update]` section names the
repository this deployment is a clone of, the daemon polls the branch, and a
push fetches, rebuilds, and restarts every selfhost process — no SSH required.
It only ever fast-forwards (local commits and modified tracked files refuse the
deployment rather than being discarded), a failed build rolls back and leaves
the old build running, and the restart is just an exit: launchd, systemd, or the
Windows Scheduled Task brings the new binary up.

Verified against a running instance, not only in unit tests: HTTPS with
keep-alive, HTTP→HTTPS redirect preserving path and query, `206` + `Content-Range`
on a video seek, `416` on an impossible range, path traversal refused, malformed
framing refused, and a full failover cycle across two live backends — one killed,
traffic moves with no failed requests; restarted, it returns unaided. The
console drives a live daemon over a tunnel it opened itself, and a service
installed with a branch to watch cloned it from GitHub, ran its build step, and
started — every step reported in the service's own output.

New here? Start with [`docs/getting-started.md`](docs/getting-started.md).
Something not working? Run `selfhost doctor --deep` and see
[`docs/troubleshooting.md`](docs/troubleshooting.md). Blocklisted, and the LAN
scan settles nothing? `selfhost watch-dns` answers DNS for the network and names
the device asking for a residential proxy service. Some of it is not yours to
fix — reverse DNS and the NAT in front of the router belong to the ISP, and
[`docs/isp-script.md`](docs/isp-script.md) is what to ask them for.

## Layout

The five directories under `crates/` are a dependency order, not a filing
convention: a crate may depend on its own layer and on the layers above it, and
never downward. `docs/principles.dx` carries the check that proves it.

One dependency of ours is deliberately **not** in this tree. `rui` — the
declarative interface library both desktop applications are written in;
elements, style, layout, rasteriser, TrueType engine, windows, no dependencies —
is its own project at <https://github.com/RockyWearsAHat/rui>, because nothing in
it knows what selfhost is. It is consumed as a git dependency pinned to an exact
revision. It was vendored here by path until 2026-08-17, which meant two copies
kept in step by hand; they had drifted about 2,300 lines apart. To change it,
clone it beside this repository and uncomment the `[patch]` block in
`Cargo.toml` — the instructions are there.

```
crates/
  foundation/   Primitives. Nothing here opens a socket of its own.
    json/       JSON, for the control API.
    http/       HTTP/1.1 parsing and serialisation. Pure, no I/O.
    config/     Deployment config model and validation. The source of truth.
    identity/   Who the caller is and what they may do. Below everything asking.
    login/      Shared password and session handling.
    supervisor/ Runs services and keeps them running.
  net/          The wire. Protocols we own, byte for byte.
    igd/        UPnP IGD port mapping.
    ws/         RFC 6455 WebSockets. Binary frames only; five of six modules pure.
    dns/        DNS wire format, stub resolver, authoritative zones.
    acme/       RFC 8555 certificate issuance.
    firewall/   Host firewall reconciliation (pf, nftables, netsh).
  services/     The capabilities a deployment actually offers.
    desk/       The remote-desktop protocol. Pure; `unsafe_code = "forbid"`.
    screen/     This machine's pixels and input devices. The FFI lives here.
    mail/       Addresses and the SMTP session state machine.
    mesh/       One outbound link carrying many channels. A worker dials;
                nothing listens.
    storage/    Shares: the confining resolver, WebDAV, quotas, and the OS's own
                SMB server driven as a program.
    git/        Watches a branch and redeploys the service built from it.
    reports/    The public report intake, its database, and its account layer.
    app-deploy/ Webhook deploys: build first, swap only on success.
  ui/           The two desktop applications. Not the toolkit — see below.
    console/    The `selfhost-console` desktop binary, written in `rui`.
    vpn-ui/     SelfHostVPN.app, the desktop VPN panel.
  app/          The top. Composes everything below.
    admin/      The loopback control API the console drives.
    proxy/      TLS termination, static serving, reverse proxy, load balancing,
                and the two loopback relays (/api/* and /dav). Here rather than
                in net/ because it depends on mail and admin.
    cli/        The `selfhost` binary, including `doctor` and `daemon`.
docs/           principles.dx (how to work here), architecture.dx, surfaces.dx,
                the security guidebook, measured constraints, roadmap.
  labs/         One runnable document per subsystem, with recorded verdicts.
index.dx        The map. Start here.
scripts/        macos/ windows/ shared/ for loose scripts; securevpn/,
                mail-discovery/ and ui-frames/ are whole tools that span both.
```

## Security properties enforced in code

These are unit-tested rather than asserted:

- **Header injection** — a field value containing CR, LF, or NUL is refused at
  construction, so a response cannot be split into two.
- **Request smuggling** — ambiguous framing is rejected outright rather than
  resolved by a heuristic: `Transfer-Encoding` alongside `Content-Length`,
  conflicting repeated `Content-Length`, a transfer coding not ending in
  `chunked`, obsolete line folding, and whitespace before a header colon. Every
  heuristic is a guess about what some *other* implementation would have
  guessed, and that gap is the vulnerability.
- **Response framing** — body length is derived when the head is written, so a
  declared length cannot disagree with the bytes sent.
- **The control API binds loopback and refuses anything else**, so there is no
  remote mode to misconfigure. Its bearer token is 256 bits of entropy in a
  `0600` file and is compared in constant time.
- **Teardown cannot escape the project.** `selfhost teardown` resolves every
  path it is about to remove and refuses any that is not inside the project
  directory, so a working copy configured elsewhere — or a `path` of `/` typed
  into the catalogue — is reported and left alone rather than obeyed.
- **A share path refuses `..` rather than popping it**, and matches it *after*
  trimming trailing dots and spaces, on every platform — Windows strips those
  before the filesystem sees a component, so `".. "` would pass an exact-equality
  refusal and normalise back to `..`. Confinement is then enforced again at the
  open, by a descriptor walk, because canonicalise-then-open is a race the moment
  a caller can create a symlink — and on a share they can.
- **Driving a machine needs a fresh credential, not a live session.** A control
  ticket is minted only when the login it rides was proved by password or passkey
  within a configured window (default 120 s), is single-use, expires in 30 s, and
  is checked again at the handshake and again on every input message. Watching
  and driving are separate capabilities, and an unattended bearer token is
  refused the keyboard unless a config field says otherwise.
- **A kill switch that is not the console.** `touch <data_dir>/desktop.disabled`
  ends every desktop stream within one poll and refuses every new one. It is a
  file rather than a command so that nothing — not the config, not the API, not a
  password, not the daemon's health — has to still be working to use it, and it
  fails closed.

Verified live against a running instance, not only in unit tests: `401` without
a token and with a wrong one against the control API, `404` for three encodings
of a path traversal, `400` for a `Content-Length`/`Transfer-Encoding` smuggling
attempt, a refusal to bind the control API to `0.0.0.0`, and a TLS 1.3
handshake.

## Building

```sh
cargo test        # run the suite
cargo build --release
```

### Installing the console on macOS

```sh
scripts/macos/macos-app.sh install     # build, bundle, install, pin to the Dock, reopen
scripts/macos/macos-app.sh uninstall   # unpin, remove the bundle and the CLI link
```

Run `install` after every change to the console or the interface library. The bundle in
`/Applications` holds a copy of the binary, so a rebuilt `target/release` is not
what the Dock launches, and a console left open is still running the build it
started from. `install` quits it — force-closing one that will not go — replaces
the bundle, and reopens it if it was open, so the window on screen is the code
in the working tree.

The icon is drawn by the library itself at every size macOS asks for — see
the `rui` library documentation at <https://github.com/RockyWearsAHat/rui> — rather than stored as a picture nobody can
review. Removing the application deliberately leaves your project and its data
alone; `selfhost teardown` is what removes those.

A daemon records the directory it is running in, so a console opened from the
Dock finds it without being told where to look. Opening the console first is
fine: it says no daemon is running and connects as soon as one is.

Cross-compiling the server binary from a Mac:

```sh
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```
