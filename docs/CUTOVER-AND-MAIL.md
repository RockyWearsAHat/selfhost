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
| **Exchange Autodiscover, EWS, and ActiveSync** | `A` + certificate for `autodiscover.<domain>`; `POST /autodiscover/autodiscover.xml` on that host and on the bare mail domain (`selfhost_mail::autodiscover`); `POST /EWS/Exchange.asmx` (`selfhost_mail::ews`) and `POST /Microsoft-Server-ActiveSync` (`selfhost_mail::eas`), both Basic-auth gated against the same `Authenticator` IMAP/submission already trust | **This is the one macOS/iOS Mail actually act on.** Per the research behind this feature: Mail ignores RFC 6186 SRV and the IMAP/SMTP blocks of a plain Autodiscover response — the only server-driven path it follows is an `EXCH`/`ASUrl` block naming a working EWS endpoint, and it then drives the mailbox over EWS, not IMAP. iOS Mail's equivalent is ActiveSync, reached via the same Autodiscover response's `MobileSync` block. Both are real, working protocol servers here (folder listing, message fetch as raw MIME, send, flag, delete), backed by the same `Maildir` IMAP/submission use — not a stub that only answers discovery. **Needs a real device to close the loop**: Apple's client-side EWS/EAS subset is reverse-engineered, not documented, so the final proof is adding the account on an actual Mac/iPhone, not a test suite. |

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

## Port 25 (outbound) — rechecked, still blocked

| From | :25 (SMTP delivery) | :587 (submission) |
|------|--------------------|-------------------|
| Box (ALEX-DESKTOP) | **BLOCKED** | open |
| Mac | **BLOCKED** | open |

Outbound TCP 25 is blocked by the network on both hosts; 587 works. This is the
ISP/carrier blocking direct SMTP (common on residential lines, and consistent
with the earlier CGNAT/Spamhaus history).

### What this means for mail

- The self-host mail server **cannot deliver outbound mail directly**: recipient
  mail servers accept delivery on port 25, which is blocked outbound here. It can
  still *receive* on 25 (inbound 25 is forwarded to the box).
- Inbound mail for `@rockywearsahat.com` currently does **not** reach the box:
  the domain's `MX` still points at Namecheap email forwarding
  (`eforward*.registrar-servers.com`), not `172.83.6.109`. Inbound self-hosted
  mail would require changing the `MX` to the box **and** confirming inbound 25
  works end to end.

### Options for working outbound mail

1. **Smart-host relay over 587** (recommended, no ISP change): relay outbound
   mail through an authenticated submission server (a provider's 587 or a
   transactional service). 587 is open from both hosts. This keeps deliverability
   (SPF/DKIM/DMARC handled by the relay) without needing port 25.
2. **Ask the ISP to unblock outbound 25** (FirstDigital). Even if unblocked, a
   residential IP has poor sending reputation — a relay is still the better path
   for deliverability.
3. **Keep Namecheap email forwarding** for inbound and use a relay for outbound;
   don't self-host the full mail path until 25 and reputation are sorted.

Until one of these is in place, treat the mail server as receive-capable-but-not-
send-capable, and keep the domain's `MX` on Namecheap forwarding.
