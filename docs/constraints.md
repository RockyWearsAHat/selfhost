# Measured constraints

Facts about the target environment, measured rather than assumed. Re-measure
before trusting any of these; the commands are given so that is cheap.

**Superseded 2026-08-07/08 in a live deployment session, from the box itself
(`ALEX-DESKTOP`) rather than the Mac.** The ISP collapsed the double NAT
described below sometime between the two measurements — the router now holds
the public IP directly — and the address itself moved (`.210` → `.109`). The
network section is corrected below; the mail-deliverability *shape* (PTR fails
forward-confirmation, outbound direct delivery is not usable) is unchanged,
only the specific IP and the confirmation method. Original 2026-07-26 numbers
kept struck through rather than deleted, since the NAT-collapse and IP-move
are themselves worth having on record.

## Network

| fact | value | how |
|---|---|---|
| public IP | `172.83.6.109` (was `172.83.7.210`) | router UPnP `GetExternalIPAddress`, matches what the box itself sees outbound |
| ISP | FirstDigital Communications (AS13415), Salt Lake City | `ipinfo.io` |
| CGNAT | **no** — routable address | — |
| NAT layers | **one** — the router holds the public IP directly now | router UPnP WAN address matches the address seen outbound; the second-router hop described below is gone |
| outbound :25 | **blocked** | see "Outbound port 25 is blocked" below — measured from the box, not guessed from a single tool's verdict |
| outbound :587, :465, :443, :53(tcp) | open | `Test-NetConnection -Port <port>` from the box |
| inbound :80, :443, :25, :587 | open, port-forwarded | `scripts/forward-soap.ps1`; verified live by Let's Encrypt's own validators reaching the box from outside, and by SMTP/submission connecting from off the LAN |

### Outbound port 25 is blocked — confirmed, not assumed

Three independent signals, not one tool's say-so:

1. ICMP ping to Gmail's and Outlook's mail exchangers succeeds (~10ms) — general
   routing is fine.
2. A TCP connection attempt to either one's port 25 does not get refused
   (instant RST) — it **hangs for 85+ seconds** before the OS gives up
   (`Measure-Command { Test-NetConnection -Port 25 }` → ~86.7s). A silent drop,
   not a rejection.
3. No local Windows Firewall outbound rule blocks port 25 — checked directly.

ICMP-fine-but-TCP/25-silently-dropped, on two unrelated destinations, with
nothing local doing it, is the standard signature of an ISP transparently
blackholing outbound SMTP — normal practice for consumer connections, meant to
stop spam from compromised home devices. It is fixable only by asking the ISP
(see the mail section below), or bypassed entirely by sending through a
`[mail.relay]` smarthost instead of direct MX delivery.

### The double NAT is gone; one hop now

*(2026-07-26, superseded)* Two layers of NAT existed — the Netgear NATed to
`10.0.12.184`, and a second, unadministrable router upstream held the real
public IP. That second hop is gone: the ISP now terminates the public IP
(`172.83.6.109`) directly on the Netgear, confirmed by the router's own UPnP
`GetExternalIPAddress` matching what the box sees as its outbound address, with
nothing in between. A forward on the Netgear is now a forward from the real
internet, full stop — no second box to coordinate with FirstDigital about.

### Upload bandwidth is not the constraint

The prior assumption was ~25 Mbps up, which would have capped the site at 8–10
concurrent 1080p viewers and made home hosting marginal for video. The measured
floor is 99 Mbps — roughly 40 concurrent 1080p renditions at ~2.5 Mbps each, and
the readings varied enough to suggest Wi-Fi contention rather than a link
ceiling. Measure again from the server over Ethernet before sizing anything.

## Mail deliverability

This is the hard part of the project, and none of it is guesswork.

| check | result |
|---|---|
| PTR for `172.83.6.109` | `172-83-6-109.ip.fdtnet.net` |
| forward A for that PTR name | **none — FCrDNS fails**, same shape as the `.210` finding below |
| reverse zone | `6.83.172.in-addr.arpa`, served by `ns1/ns2.firstdigital.com` |
| who to ask | `ipadmin@firstdigital.com` — named by `doctor --deep`'s own investigation, not guessed |
| `zen.spamhaus.org` for `172.83.6.109` | **not re-checked since the IP moved** — the `.210` listing below predates the move; do not assume it carries over, and do not assume it doesn't |

**FCrDNS is the harder problem and it is the ISP's.** The PTR name has no forward
A record, so forward-confirmed reverse DNS fails on the new IP exactly as it did
on the old one. Gmail and Outlook both weight this heavily. Fixing it requires
FirstDigital either repairing their forward zone or delegating PTR for this
address — ask in the same message as the outbound-25 request, and ask about a
static IP while at it, since a lease that moves again invalidates both fixes.

Consequence for the design, unchanged: outbound mail supports **both** `direct`
and `relay` as first-class modes (`crates/mail/src/client.rs` and
`[mail.relay]` respectively). Neither is hardcoded as impossible — but on *this*
network, today, `direct` cannot be used until the ISP lifts the port-25 block,
measured above, not assumed.

**Inbound mail is unaffected by any of this**: port 25 is open inbound (verified
by a real SMTP conversation completing from off the LAN) and the MX can be
pointed here — see the DNS records in `docs/roadmap.md`'s evidence trail. Only
*sending directly* is blocked.

### 2026-07-26 findings, for the record (address `172.83.7.210`, now retired)

| check | result |
|---|---|
| `zen.spamhaus.org` | listed: XBL + CSS |
| neighbours `.1 .50 .100 .209 .211` in the same /24 | all clean |
| PTR for `172.83.7.210` | `172-83-7-210.ip.fdtnet.net` |
| forward A for that PTR name | none — FCrDNS failed |
| outbound :25 | reported open by a single `nc -z` at the time — **superseded**; the 2026-08 measurement above, taken from the box itself with three corroborating signals, found it blocked. Trust the newer one. |

The listing was IP-specific, not a dirty ISP pool (every sampled neighbour was
clean), so Spamhaus's free self-service removal would have held rather than
re-triggered — moot now that the address itself has changed, but worth keeping
as a record that XBL/CSS listings on this ISP's residential ranges are
per-address, not pool-wide.

## The site being hosted

`leveluplongboarding.surf`, currently Netlify + MongoDB Atlas.

| fact | value |
|---|---|
| nameservers | Namecheap (`dns1/dns2.registrar-servers.com`) — **not** Netlify |
| A records | `99.83.231.61`, `75.2.60.5` (Netlify) |
| MX | Namecheap free email forwarding |
| media size | 464 MB, against a 512 MB Atlas free tier shared with ~17 MB of other projects |

DNS control is therefore at Namecheap, which is where records get pointed — or
where nameservers get delegated once this platform serves its own zones.

## Electricity — the honest cost

A desktop idling at 50–100 W costs roughly **$5–15/month**. That is the same
order as the $8/month Atlas Flex bill this was meant to avoid, so "free" is
really "trade a subscription for electricity, effort, and responsibility."

What genuinely changes: the 512 MB storage ceiling disappears, egress is not
metered, and `yt-dlp` and `ffmpeg` exist in production for the first time — so
scheduled syncs can package HLS ladders on the server instead of only on a
laptop.

## Do not promise uptime

A home box on residential power and internet is not a 99.9% service. The
question worth asking is what an hour of downtime actually costs — for this site,
probably very little, which is a fine answer and should be said plainly.
