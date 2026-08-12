# DNS cutover, port 25, and mail — operational notes

Snapshot: 2026-08-08. Box public IP **172.83.6.109** (dynamic — a DDNS updater
keeps records current; see `crates/dns`). Box LAN IP 192.168.1.8.

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

Namecheap DDNS can keep these current automatically once pointed at the box —
add a `[[namecheap_ddns]]` block per record (see `crates/config` docs) with the
per-domain Dynamic-DNS password from Namecheap's Advanced DNS tab. NS1-managed
`mayr` won't use Namecheap DDNS; if the public IP changes, its A record must be
updated at NS1/Netlify (or move it to Namecheap to get automatic DDNS).

## Pushing the records automatically — `selfhost dns sync`

Everything the tables above say to type into a DNS panel can be pushed over the
registrar's API instead. Add a `[registrar]` section to `selfhost.config.toml`
(secrets live only in that local, gitignored file — never anywhere committed),
then run the sync:

```bash
selfhost dns sync            # dry-run: prints the plan per domain, writes nothing
selfhost dns sync --apply    # writes the plan
```

For every registered domain the config serves (site domains and mail domains,
grouped — `www.example.com` and `example.com` are one zone), the command derives
the records the config implies (site A records, and the full mail set: MX, SPF,
DMARC, DKIM once the key exists, CAA, client-setup A records, RFC 6186 SRVs,
and the `_ua-auto-config` PACC digest — see below),
lists what the registrar currently serves, and prints the diff. Records point at
the box's discovered public IP, falling back to the config's `[dns]` apex A if
discovery fails. **Dry-run is the default; only `--apply` writes.**

**The safety law:** a record whose `(host, type)` the config does not claim is
never deleted or modified — your own TXT verifications and elsewhere-pointing
CNAMEs survive every sync verbatim, on every provider.

One-time setup per provider (`selfhost check` names anything missing):

| Provider | Config | Where the credential lives |
|----------|--------|----------------------------|
| `namecheap` | `api_user`, `api_key`, `client_ip` | Profile → Tools → API Access. **Eligibility gate:** Namecheap only enables the API for accounts with 20+ domains, or $50+ account balance, or $50+ spent in the last two years. **IP whitelist:** the API rejects calls from any address not whitelisted there — `client_ip` is that address (the box's public IP). The API also cannot write SRV records; the sync says so and prints them for the Advanced DNS panel. |
| `cloudflare` | `api_key` | dash.cloudflare.com → My Profile → API Tokens: a token scoped to Zone:Read + DNS:Edit for the zones. |
| `godaddy` | `api_key`, `api_secret` | developer.godaddy.com → API Keys: a **production** key pair. |
| `porkbun` | `api_key`, `api_secret` | porkbun.com → Account → API Access, and enable API access per domain in its details panel. |
| `manual` | *(nothing)* | No API at all — the sync prints every record in copy-pasteable panel form (type, host, value, TTL) for you to add by hand. This is the answer for every registrar without an API: Squarespace, NS1-managed `mayr`, and friends. |

Example, for this deployment's Namecheap domains:

```toml
[registrar]
provider = "namecheap"
api_user = "<account name>"
api_key = "<from the API Access page>"
client_ip = "172.83.6.109"
```

## Account setup without typing server names — what is published, and what works today

Three mechanisms are published for a mail domain, in the order clients came to
them. Nothing here needs a per-client profile, and none of it costs a port.

| Mechanism | What is published | Who uses it |
|-----------|-------------------|-------------|
| Guessable hostnames | `A` records + certificate SANs for `mail.`, `imap.`, `smtp.` | Nearly every client, as a guess after discovery fails. This is why setup works today once the two hostnames are typed. |
| RFC 6186 SRV | `_imaps._tcp` → `0 1 993 imap.<domain>`, `_submission._tcp` → `0 1 587 smtp.<domain>`, `_submissions._tcp` → `0 1 465 smtp.<domain>` | Thunderbird and others. **Not macOS/iOS Mail** — a sweep of the dyld shared cache on macOS 15.5 finds those service labels zero times (`discovery-lab.dx`). |
| **PACC** (`draft-ietf-mailmaint-pacc`) | `A` + certificate for `ua-auto-config.<domain>`, the document served at `https://ua-auto-config.<domain>/.well-known/user-agent-configuration.json`, and a `_ua-auto-config` `TXT` carrying `v=UAAC1; a=sha256; d=<base64 SHA-256 of the document>` | Nothing shipping yet — Apple co-authors the draft and was implementing a client in July 2026. Published now because it is inert to clients that have never heard of it and is the only specified path that ends with an address and a password being enough. |

The document, the digest, and the hostname all come from one derivation
(`crates/config/src/pacc.rs`), so a `selfhost dns sync` after any config change
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

`ua-auto-config.` joins the existing mail certificate's SAN set rather than
taking one of its own, and `crates/cli/src/acme_task.rs` reissues an order whose
name set has grown — a certificate is not left uncovering a host it should name
just because it is young. Verified on 2026-08-11: document, digest, and `A`
record all correct; the certificate was still the self-signed fallback because
the old marker recorded no names, which is the gap that check now closes.

Namecheap's API cannot write SRV records (the sync says so per domain), but the
PACC `TXT` and `A` records are ordinary records it writes without complaint.

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
