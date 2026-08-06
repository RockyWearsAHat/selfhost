# selfhost

Host websites, databases, DNS, and mail from your own hardware. One config file,
one binary, no vendor.

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
balancing, health checking, byte ranges, ACME, the DNS wire format, SMTP, and
IMAP.

The reason is not purity. An external binary drags in its own release cadence,
its own platform matrix, its own checksum-and-download layer, and its own
failure modes — and on Windows and macOS a container runtime additionally
requires a **logged-in desktop session**, which is disqualifying for a machine
whose job is to stay up unattended.

## Status

**984 tests pass.** The proxy runs and serves, the daemon supervises services,
the desktop console drives it — over an SSH tunnel it manages itself — and a push
to a watched branch redeploys the service built from it. ACME, the authoritative
DNS server, and the mail connection layer do not exist yet — see
[`docs/roadmap.md`](docs/roadmap.md) for the honest breakdown.

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

```
crates/
  http/     HTTP/1.1 parsing and serialisation. Pure, no I/O, no dependencies.
  config/   Deployment config model and validation. The source of truth.
  proxy/    TLS termination, static serving, reverse proxy, load balancing.
  mail/     Addresses and the SMTP session state machine.
  dns/      DNS wire format and a stub resolver.
  supervisor/ Runs services and keeps them running.
  admin/    The loopback control API the console drives.
  json/     JSON, for that API.
  git/      Watches a branch and redeploys the service built from it.
  rui/      `rui`: a declarative interface library — elements, style, layout,
            rasteriser, TrueType engine, windows. No dependencies, and nothing
            in it knows about selfhost. Its own repository is at
            github.com/RockyWearsAHat/rui. See crates/rui/README.md.
  console/  The `selfhost-console` desktop binary, written in `rui`.
  cli/      The `selfhost` binary, including `doctor` and `daemon`.
docs/       Getting started, measured constraints, roadmap.
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
scripts/macos-app.sh install     # build, bundle, install, pin to the Dock, reopen
scripts/macos-app.sh uninstall   # unpin, remove the bundle and the CLI link
```

Run `install` after every change to the console or the interface library. The bundle in
`/Applications` holds a copy of the binary, so a rebuilt `target/release` is not
what the Dock launches, and a console left open is still running the build it
started from. `install` quits it — force-closing one that will not go — replaces
the bundle, and reopens it if it was open, so the window on screen is the code
in the working tree.

The icon is drawn by the library itself at every size macOS asks for — see
`crates/rui/examples/icon.rs` — rather than stored as a picture nobody can
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
