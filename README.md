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
  less safe, not more independent.
- **MongoDB**, because the first site hosted on this platform already stores its
  media there.

Everything above the socket is ours: HTTP parsing, the reverse proxy, load
balancing, health checking, byte ranges, ACME, the DNS wire format, SMTP, and
IMAP.

The reason is not purity. An external binary drags in its own release cadence,
its own platform matrix, its own checksum-and-download layer, and its own
failure modes — and on Windows and macOS a container runtime additionally
requires a **logged-in desktop session**, which is disqualifying for a machine
whose job is to stay up unattended.

## Status

**279 tests pass.** The proxy runs and serves. ACME, the authoritative DNS
server, and the mail connection layer do not exist yet — see
[`docs/roadmap.md`](docs/roadmap.md) for the honest breakdown.

Verified against a running instance, not only in unit tests: HTTPS with
keep-alive, HTTP→HTTPS redirect preserving path and query, `206` + `Content-Range`
on a video seek, `416` on an impossible range, path traversal refused, malformed
framing refused, and a full failover cycle across two live backends — one killed,
traffic moves with no failed requests; restarted, it returns unaided.

New here? Start with [`docs/getting-started.md`](docs/getting-started.md).
Something not working? Run `selfhost doctor --deep` and see
[`docs/troubleshooting.md`](docs/troubleshooting.md). Blocklisted, and the LAN
scan settles nothing? `selfhost watch-dns` answers DNS for the network and names
the device asking for a residential proxy service.

## Layout

```
crates/
  http/     HTTP/1.1 parsing and serialisation. Pure, no I/O, no dependencies.
  config/   Deployment config model and validation. The source of truth.
  proxy/    TLS termination, static serving, reverse proxy, load balancing.
  mail/     Addresses and the SMTP session state machine.
  dns/      DNS wire format and a stub resolver.
  cli/      The `selfhost` binary, including `doctor`.
gui/        Console rough draft (static, no API behind it yet).
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

## Building

```sh
cargo test        # run the suite
cargo build --release
```

Cross-compiling the server binary from a Mac:

```sh
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target x86_64-unknown-linux-gnu
```
