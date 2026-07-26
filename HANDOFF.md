# Handoff — selfhost

**Written:** 2026-07-26 · **Repo:** <https://github.com/RockyWearsAHat/selfhost> ·
**Branch:** `main`
**Prior session:** the question that started this is in
`/tmp/lvlup-self-hosting-handoff.md` — hosting websites from a spare PC, free,
unrestricted, load balanced.

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

**252 tests pass.** `cargo test --workspace`.

| crate | what | tests |
|---|---|---|
| `crates/http` | HTTP/1.1 messages + dates, pure, no I/O | 57 |
| `crates/config` | Config model + validation | 18 |
| `crates/proxy` | TLS, static+Range, caching, routing, LB, health | 60 |
| `crates/mail` | Addresses + SMTP session state machine | 48 |
| `crates/dns` | DNS wire format + resolver | 19 |
| `crates/cli` | The `selfhost` binary, `doctor`, LAN device assessment | 50 |

**Verified against a running instance,** not only in unit tests: HTTPS 200,
HTTP→HTTPS 308 preserving path and query, `206` + `Content-Range` on a seek,
`416` on an impossible range, `.m3u8`/`.ts` content types, path traversal → 404,
smuggling → 400, and a **full failover cycle** with two live backends — 5/5
split, one killed → 10/10 to the survivor with no failed requests, restarted →
back to 5/5 unaided, both down → 502.

**Not built:** ACME (so nothing can be published to a real browser yet), DNS,
the mail connection layer, IMAP, MIME, service install, node join, backups, and
the admin API behind the GUI. Full detail and ordering in
[`docs/roadmap.md`](docs/roadmap.md).

## 4. Measured facts — do not re-derive

All in [`docs/constraints.md`](docs/constraints.md). The two that overturn
assumptions from the prior handoff:

**Upload bandwidth is not the constraint.** Assumed ~25 Mbps; measured 99–508
Mbps over Wi-Fi. Even the low reading carries ~40 concurrent 1080p renditions.
The prior handoff's central worry about home-hosting a video site is void.

**Not behind CGNAT.** `172.83.7.210` is routable with real reverse DNS, so the
tunnel-based designs that existed to survive CGNAT are unnecessary.

**Mail is the genuinely hard part, and it is environmental, not code:**

- Spamhaus **XBL + CSS listed** — but IP-specific; sampled `/24` neighbours are
  clean, so self-service removal should stick. (XBL is the compromised-host
  list, so something on the LAN may have earned it — worth telling him again.)
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

1. **Has he requested Spamhaus delisting, and opened a ticket with FirstDigital
   about the missing forward record for his PTR?** Both are prerequisites for
   `direct` outbound mail and neither is something code can do.
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
- **The GUI must stay read-only.** The config file is the single source of truth;
  a GUI that writes creates a second one, and they drift the first time someone
  edits the file over SSH.

## 8. Suggested skills

- **`/grilling`** before any further architecture — it is how the three good
  redirects happened this session.
- **`/tdd`** for ACME and IMAP. Both are specified protocols with well-defined
  wire behaviour, which is exactly where tests-first pays.
- **`/code-review`** and **`/simplify`** once ACME lands.
- **`/research`** for the two facts that must not be guessed: whether FirstDigital
  will delegate PTR, and current Spamhaus delisting mechanics.
