# Roadmap — what is done, and what is left

Honest state of the project. Anything marked **done** has tests and has been
exercised against a running instance; anything else has not been written.

## Done

| area | crate | tests | evidence |
|---|---|---|---|
| HTTP/1.1 messages + dates | `crates/http` | 57 | header injection, request smuggling, byte ranges, cache validators |
| Config model + validation | `crates/config` | 18 | every problem reported at once, field-named |
| Proxy: TLS, static, caching, LB | `crates/proxy` | 60 | path traversal, Range, 304, health hysteresis |
| SMTP session + addresses | `crates/mail` | 48 | open-relay defence, credential protection, framing |

**183 tests.** Verified live: HTTPS 200, HTTP→HTTPS 308, `206` + `Content-Range`
on a seek, `416` on an impossible range, `304` with zero bytes on both cache
validators, `.m3u8`/`.ts` content types, traversal → 404, smuggling → 400, an
ACME challenge served over cleartext while ordinary paths still redirect, and a
full failover cycle across two backends (5/5 split → one killed → 10/10 to the
survivor → restarted → back to 5/5 → both down → 502).

## Next, in the order I would do it

### 1. ACME client (RFC 8555) — unblocks everything public

Until this exists, the only certificates available are self-signed, so nothing
can be published to a real browser.

- Account key (ES256) and JWS signing. `aws-lc-rs` ships with `rustls`.
- `newNonce` → `newAccount` → `newOrder` → HTTP-01 challenge → CSR → poll →
  download.
- **HTTP-01 is the right challenge here** because we already own port 80. DNS-01
  would need the DNS server, which does not exist yet — do not couple them.
- CSR generation is PKCS#10 DER. `rcgen` is already a dependency and can build
  one; check before hand-rolling ASN.1.
- Renew at 30 days remaining, not at expiry.
- **Test against the staging CA only.** Production allows five duplicate
  certificates per week.

**The redirect trap is already closed.** `/.well-known/acme-challenge/*` is
exempt from the HTTPS redirect and served from `data/acme-challenges/`, with the
token confined to a plain filename so a challenge fetch cannot become a
traversal. The ACME client only has to write tokens into that directory.

### 2. SNI certificate selection

One certificate per hostname instead of one certificate with every hostname as
an alternate. `rustls` wants a `ResolvesServerCert` implementation.

Today `cli/src/main.rs` builds a single certificate covering every domain — fine
for a handful of sites, wrong once sites are added and removed independently,
because every change reissues one shared certificate.

### 3. Finish the mail server

The session state machine is done. What is missing:

- **The connection layer** — bind :25, :465, :587, drive `Session`, handle
  `STARTTLS` upgrade mid-connection, read `DATA` until a lone `.`.
- **A message store.** Maildir is the sane choice: one file per message, written
  to `tmp/` and renamed into `new/`, so a crash never leaves a half-written
  message visible. It also makes backup a file copy.
- **MIME parsing.** This is the single largest piece of the mail work, and it is
  required by both IMAP revisions, so no revision choice avoids it. Needed for
  `BODYSTRUCTURE` and partial `FETCH`.
- **IMAP.** Advertise `IMAP4rev1 IMAP4rev2` both. rev2 (RFC 9051) is rev1 with
  the cruft removed, so implementing rev2 gets most of rev1 free — but Apple
  Mail, iOS Mail, and Outlook still open with rev1 commands, so advertising rev2
  alone risks a mail server your own phone cannot open.
  - Hardest parts, in order: `BODYSTRUCTURE`, `SEARCH`, and UID/sequence-number
    correctness. The last one is the classic source of "my client shows deleted
    mail."
- **Outbound**, both modes:
  - `relay` — hand to a smarthost that already has reputation.
  - `direct` — MX lookup and delivery. Needs the DNS resolver.
- **DKIM signing**, and SPF/DMARC records generated into the zone.
- **`selfhost mail doctor`** — measures deliverability rather than assuming it:
  DNSBL across zones, FCrDNS, port 25 reachability, DMARC alignment, and a live
  test send. `direct` should be chosen when this passes, not when someone hopes
  it will.

**Read [`constraints.md`](constraints.md) before starting outbound.** The target
IP is Spamhaus XBL+CSS listed and its PTR has no forward record. Neither is a
code problem and neither is fixed by writing more code.

### 4. Authoritative DNS

- Wire format parse/serialise, authoritative-only — no recursion, which removes
  a whole class of amplification risk.
- `A`, `AAAA`, `MX`, `TXT`, `CNAME`, `NS`, `SOA`, `CAA`.
- UDP with TCP fallback for large responses, and AXFR to a secondary.
- **A secondary nameserver is not optional.** With only this box authoritative,
  the domain stops resolving entirely whenever it is down — which takes mail with
  it, not just the website. Hurricane Electric offers free secondary DNS.
- Dynamic-IP updating, since a residential address can change.

### 5. Service install

The reason Docker was dropped: on Windows and macOS a container runtime needs a
logged-in desktop session, which is disqualifying for a machine meant to stay up
unattended.

- **Windows Service via SCM** — the primary target.
- **launchd plist** on macOS, **systemd unit** on Linux.
- Must survive reboot with no user logged in.
- Cross-compilation already works: `x86_64-pc-windows-gnu` and
  `x86_64-unknown-linux-gnu` are installed.

### 6. Node join and the private mesh

`Config::instance_address` already refuses to address a worker that has no
`mesh_ip`, so the config layer is ready. What is missing is the mesh itself and
a one-command join.

The rule to preserve: **workers are reached over the mesh, never a public
address**, so an application port is never exposed to the internet even on a
remote machine.

### 7. Backups

Nightly dump plus an off-site copy. **Untested backups are not backups** —
restore has to be exercised, not assumed.

### 8. The GUI

A rough draft exists at `gui/index.html` — static, with the real data shapes but
no live data behind it. It needs a read-only admin API to become real. See
[`gui.md`](gui.md).

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
