# DNS cutover, port 25, and mail — operational notes

Snapshot: 2026-08-08. Box public IP **172.83.6.109** (dynamic — `dynamic_ip` in
`[dns]` keeps the apex `A` current in the zone this box serves; see
`crates/dns/src/updater.rs`). Box LAN IP 192.168.1.8.

## Moving a site from its temporary/old IP to the real IP

"Temporary IP → real IP" means repointing each site's DNS **A records** from its
current host to the box's public IP `172.83.6.109`. The box already serves all
sites (verified `200` locally); only DNS still sends visitors elsewhere.

Do this per site, and only after confirming the box serves it (it does today):

1. **Lower the TTL first** (a day ahead if you can): set the A record TTL to
   `60`–`300`s so the switch propagates fast and is easy to roll back.
2. **Change the A records** (apex `@` and `www`) to `172.83.6.109`. Remove any
   CNAME to the old host (Netlify) on those names.
3. **Watch**: `dig +short A <domain> @1.1.1.1` should return `172.83.6.109`,
   then load the site over HTTPS and confirm the certificate is the box's Let's
   Encrypt cert. The box auto-issues a cert for the name on first request.
4. **Roll back** by restoring the old A record if anything looks wrong (that's
   what the low TTL buys you).

### Per-site specifics

| Site | Domain | DNS host now | A record now | Action |
|------|--------|--------------|--------------|--------|
| rockywearsahat | rockywearsahat.com | Namecheap (`registrar-servers.com`) | **172.83.6.109** | Already on the box — a normal **public** site. |
| admin (console) | admin.rockywearsahat.com | Namecheap (`registrar-servers.com`) | *(not set)* | Add an `A` record `admin` → **172.83.6.109**. The console is VPN-gated (public hits get `404`), but this record lets the box's ACME client issue a real certificate for the name — without it the console works over the VPN but shows a self-signed-cert warning. See `docs/VPN.md`. |
| lvlup | leveluplongboarding.surf | Namecheap (`registrar-servers.com`) | Netlify (75.2.60.5, 99.83.231.61) | In Namecheap → Advanced DNS: set `@` and `www` A records to `172.83.6.109`; delete the Netlify CNAME/ALIAS. |
| mayr | mayrconsultingservices.com | **NS1 / nsone.net** (not Namecheap) | Netlify (52.52.192.191, 13.52.188.95) | DNS is managed at **NS1** (likely via Netlify DNS). Change the A records **where those nameservers are administered** — probably the Netlify dashboard for this domain — to `172.83.6.109`. If you'd rather manage it at Namecheap, repoint the domain's nameservers to Namecheap first, then set the A records. |

## The end state: this box is the nameserver

The per-record edits above are the *interim* answer — what to type while a
domain's DNS still lives in somebody else's panel. The end state is that no
panel is involved at all: each domain's **`NS` delegation points at this box**,
and this box answers every record for it authoritatively.

There is deliberately no registrar-API integration here, and no dynamic-DNS
client pointed at a third party. Both were removed: they are a second copy of
the zone that can silently disagree with the served one, and they need
credentials for an account this deployment should not hold. One nameserver, one
zone, one source of truth — `[dns]` in `selfhost.config.toml`.

**Cutting a domain over to this box:**

1. Confirm the box already serves the zone: `selfhost dns` prints every zone and
   its derived records, and probes whether port 53 is answering.
2. Confirm the world can reach port 53 — the router/edge must forward **UDP and
   TCP** 53 here. `selfhost outside` proves this with a real off-network query
   (see below); `selfhost doctor` reports the edge.
3. At the registrar — the company that sold the domain, which is the one thing
   that stays external because it is what the TLD's registry reads — set the
   domain's nameservers to this box's.
4. Watch: `dig +short NS <domain> @1.1.1.1`, then `dig +short A <domain>
   @<this box>`.

Once delegated, every record in the tables above is derived from the config and
served automatically: site `A` records, and the full mail set (MX, SPF, DMARC,
DKIM once the key exists, CAA, client-setup `A` records, RFC 6186 SRVs, and the
`_ua-auto-config` PACC digest — see below). Nothing is typed twice, so nothing
can drift. A changing public IP is followed by `dynamic_ip` in `[dns]`, which
rewrites the apex `A` in the zone this box already serves.

## Account setup without typing server names — what is published, and what works today

Four mechanisms are published for a mail domain, in the order clients came to
them. Nothing here needs a per-client profile, and none of it costs a port —
Autodiscover/EWS/ActiveSync rides the existing proxy on 443 exactly as PACC
does (`crates/proxy/src/server.rs`'s `dispatch`), not a listener of its own.

| Mechanism | What is published | Who uses it |
|-----------|-------------------|-------------|
| Guessable hostnames | `A` records + certificate SANs for `mail.`, `imap.`, `smtp.` | Nearly every client, as a guess after discovery fails. This is why setup works today once the two hostnames are typed. |
| RFC 6186 SRV | `_imaps._tcp` → `0 1 993 imap.<domain>`, `_submission._tcp` → `0 1 587 smtp.<domain>`, `_submissions._tcp` → `0 1 465 smtp.<domain>` | Thunderbird and others. **Not macOS/iOS Mail** — a sweep of the dyld shared cache on macOS 15.5 finds those service labels zero times (`discovery-lab.dx`). |
| **PACC** (`draft-ietf-mailmaint-pacc`) | `A` + certificate for `ua-auto-config.<domain>`, the document served at `https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json`, and a `_ua-auto-config` `TXT` carrying `v=UAAC1; a=sha256; d=<base64 SHA-256 of the document>` | Nothing shipping yet — Apple co-authors the draft and was implementing a client in July 2026. Published now because it is inert to clients that have never heard of it and is the only specified path that ends with an address and a password being enough. |
| **Exchange Autodiscover, EWS, and ActiveSync** | `A` + certificate for `autodiscover.<domain>`; `POST /autodiscover/autodiscover.xml` on that host and on the bare mail domain (`selfhost_mail::autodiscover`); `POST /EWS/Exchange.asmx` (`selfhost_mail::ews`) and `POST /Microsoft-Server-ActiveSync` (`selfhost_mail::eas`), both Basic-auth gated against the same `Authenticator` IMAP/submission already trust | **This is the one macOS/iOS Mail actually act on — once the user picks "Microsoft Exchange" as the account type.** Confirmed live 2026-08-13 (see below): Mail ignores RFC 6186 SRV and the IMAP/SMTP blocks of a plain Autodiscover response — the only server-driven path it follows is an `EXCH`/`ASUrl` block naming a working EWS endpoint, and it then drives the mailbox over EWS, not IMAP. iOS Mail's equivalent is ActiveSync, reached via the same Autodiscover response's `MobileSync` block. Both are real, working protocol servers here (folder listing, message fetch as raw MIME, send, flag, delete), backed by the same `Maildir` IMAP/submission use — not a stub that only answers discovery. |

**2026-08-13 — real-device test, and a correction.** Added `alex@rockywearsahat.com`
on an actual Mac. Typing only the address and clicking Continue produced *no*
server-side activity at all — that path is "Other Mail Account," a manual-IMAP-only
flow that never invokes discovery, confirmed by watching the daemon's access log live.
Explicitly picking **Microsoft Exchange** as the account type produced the full expected
sequence: `GET /autodiscover/autodiscover.json/v1.0/<address>?Protocol=EWS`,
`POST /autodiscover/autodiscover.xml`, two `POST /EWS/Exchange.asmx` calls, all against
`autodiscover.rockywearsahat.com`, all succeeding — account confirmed working end to end.

This corrects an assumption baked into the row above and into how this feature was
originally framed: macOS/iOS never attempt Exchange-style discovery against an arbitrary
typed domain without the user first selecting the Exchange account type — that is not a
gap in this deployment, it is how every non-Google/iCloud/Yahoo custom domain has always
worked on Apple's mail clients. The literal "type an address, nothing else, no account-type
click" experience is what **PACC** (the row above this one) is for, and it is not yet
implemented client-side by any shipping Apple Mail build. "Zero-touch" for this feature,
accurately: no server hostnames are ever typed — address, password, and (until PACC ships
client-side) one account-type selection.

The document, the digest, and the hostname all come from one derivation
(`crates/config/src/pacc.rs`), so the served zone after any config change
republishes a digest that matches the bytes the proxy serves. Check them against
each other any time:

```bash
curl -s https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json \
  | openssl dgst -binary -sha256 | base64      # must equal the d= tag below
dig +short TXT _ua-auto-config.<domain>
```

The digest matching is not the whole check: the document is fetched over HTTPS
or not at all, so the PACC host also needs a certificate that names it. Confirm
the issuer is Let's Encrypt and not the `rcgen` self-signed fallback:

```bash
echo | openssl s_client -connect <box>:443 -servername ua-auto-config.<domain> \
  2>/dev/null | openssl x509 -noout -subject -issuer
```

`ua-auto-config.` (and, since this feature, `autodiscover.`) joins the existing
mail certificate's SAN set rather than taking one of its own, and
`crates/cli/src/acme_task.rs` reissues an order whose name set has grown — a
certificate is not left uncovering a host it should name just because it is
young. That rule exists because of what 2026-08-12 found: document, digest, and
`A` record all correct, and the host still served the `rcgen` self-signed
fallback, because the mail certificate was three days old and nothing compared
its names to the order's. Resolved the same night — all six orders reissued,
the mail certificate now naming `mail`/`imap`/`smtp`/`ua-auto-config` and valid
to 2026-11-10 (`autodiscover` joined the same set later, when EWS/ActiveSync
shipped — same rule, same reissue path, no repeat of the gap).

**2026-08-13 — `doctor --deep` kept reporting the same hosts as self-signed
after that, and it was `doctor` that was wrong, not the certificate.** The
renewal-trigger rule above (`needs_certificate`) worked correctly the whole
time — a live loopback fetch of the actual served certificate for
`imap.`/`smtp.`/`autodiscover.`/`ua-auto-config.` on both domains showed one
real `Let's Encrypt production` cert, issued `2026-08-12`, valid to
`2026-11-10`, naming all ten mail client hosts, and public DNS resolved every
one of them. The false WARN was a separate bug: `stamp_issued` recorded the
"this is a real, dated ACME certificate" marker only under an order's
canonical hostname, so `doctor`'s per-host report — which checks every stored
hostname independently, not just canonical ones — found no marker for any
alias and reported the self-signed fallback regardless of what was actually
being served. First fix attempt (writing the marker under every domain in the
order) turned out to only help *future* issuances — it never runs unless a
reissue happens, and the certs already on disk didn't need one. Actual fix:
`doctor` now resolves each hostname to its order's canonical host
(`acme_task::canonical_host`, built from the same order computation the ACME
task itself uses) before reading the marker — correct immediately, no
backfill and no waiting for the next renewal.

## Port 25 (outbound) — 2026-08-08: blocked; 2026-08-12: open, and mail is live

Original finding, kept for the record — as of 2026-08-08 outbound 25 was
blocked on both hosts:

| From | :25 (SMTP delivery) | :587 (submission) |
|------|--------------------|-------------------|
| Box (ALEX-DESKTOP) | **BLOCKED** | open |
| Mac | **BLOCKED** | open |

**Superseded 2026-08-12.** Re-checked via `selfhost doctor` / `doctor --deep` on
the box and `dig` from an external Mac: outbound 25 is now **open**, and the
whole mail path from that older finding onward has moved. Concretely, as of
2026-08-12:

- `rockywearsahat.com` now resolves to the box (`172.83.6.109`) for the apex,
  `www`, `admin`, and `blog` — the "no domain resolves here yet" state this doc
  described earlier no longer holds.
- MX (`10 rockywearsahat.com`), SPF (`v=spf1 mx -all`), DMARC
  (`v=DMARC1; p=reject; rua=mailto:postmaster@rockywearsahat.com`), and DKIM
  (selector `s1`, ed25519, published at `s1._domainkey.rockywearsahat.com`) are
  all live, publicly resolving, and all PASS in `selfhost doctor`. Inbound MX
  points at the box now, not Namecheap forwarding.
- `doctor` reports outbound port 25 as **PASS — open, direct delivery is
  possible from this network**, and live SMTP handshakes succeeded directly
  against both `gmail-smtp-in.l.google.com` and
  `outlook-com.olc.protection.outlook.com`, each confirming the connecting
  address as `172.83.6.109`.

### What this means for mail

- The self-host mail server **can now deliver outbound mail directly**: MX,
  SPF, DKIM, and DMARC are live and passing, and outbound 25 handshakes
  successfully against both Gmail and Outlook. The "receive-capable-but-not-
  send-capable" state below no longer applies.
- **The remaining blocker is not SPF/DKIM/DMARC or port 25 — it's reverse DNS.**
  `doctor --deep` found that mail passing every authentication check was still
  landing straight in Junk, because forward-confirmed reverse DNS (FCrDNS)
  fails for this IP: the PTR for `172.83.6.109` is
  `172-83-6-109.ip.fdtnet.net`, but that hostname has no forward `A` record, so
  it doesn't resolve back to `172.83.6.109`. Gmail and Outlook weight FCrDNS
  heavily for inbox placement independent of SPF/DKIM/DMARC, so mail can pass
  every published check and still get dumped to Junk purely because of this
  one broken link.
- **This is not fixable from this repo or this box.** The reverse zone
  `6.83.172.in-addr.arpa` is controlled by the ISP (First Digital, nameservers
  `ns1.firstdigital.com` / `ns2.firstdigital.com`), not by us — only they can
  add the missing forward record or delegate the PTR. Contact:
  **`ipadmin@firstdigital.com`**. Ask for either:
  1. a forward `A` record for `172-83-6-109.ip.fdtnet.net` pointing at
     `172.83.6.109` (so the PTR resolves forward-and-back), **or**
  2. delegation of the PTR for `172.83.6.109`, so it can be pointed directly at
     `rockywearsahat.com`.

  Also worth asking in the same email: whether a **static IP** is available —
  a residential lease renumbering would silently break whichever fix above
  gets applied, along with every DNS record that references this address. A
  ready-to-send draft of this request already lives at
  `docs/isp-ptr-request-email.txt`.
- Blocklist status could not be confirmed via public resolvers (1.1.1.1,
  8.8.8.8) or the LAN router resolver — Spamhaus refuses all three and answers
  `127.255.255.254`, which `crates/dns/src/resolver.rs::is_real_listing()`
  correctly treats as "refused", not "listed". The prior IP (`172.83.7.210`)
  *was* Spamhaus XBL+CSS listed (see `docs/constraints.md`); that's moot now
  since the IP changed to `172.83.6.109`, and `doctor --deep`'s neighbour
  sampling shows 0 of 8 sampled neighbours of the new IP are listed, so any
  future listing here would be specific to this address, not a dirty ISP pool.

### Options for working outbound mail

1. **Wait on the ISP fix above (recommended, no new dependency)**: once First
   Digital adds the forward record or delegates the PTR, FCrDNS passes and
   direct delivery — which already works end-to-end for SPF/DKIM/DMARC/port 25
   — should land in the inbox instead of Junk. This is the only known root-cause
   fix; everything else below is a workaround for the wait.
2. **Smart-host relay over 587, as a stopgap while waiting on the ISP**: relay
   outbound mail through an authenticated submission server (587 is open and
   confirmed working). A relay's own IP — not ours — is what the receiver
   evaluates, so this sidesteps the FCrDNS problem entirely without waiting on
   First Digital. This is a real option to reach for if the PTR fix is slow,
   **not** something to set up speculatively: it needs a real relay account
   (e.g. SendGrid/Mailgun/SES/Postmark) and credentials the operator supplies —
   there's no `[mail.relay]` configured today, and none should be fabricated.
3. **Ask the ISP to unblock outbound 25** — already done; see above. Kept here
   only as a historical option, superseded by the 2026-08-12 finding that 25 is
   open.

The domain's `MX` should stay pointed at the box (not reverted to Namecheap
forwarding) — inbound and outbound both work today. The only open item is
getting mail out of Junk, which is the FCrDNS fix above, optionally sped up by
a relay while it's pending.
