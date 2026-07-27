# Measured constraints

Facts about the target environment, measured rather than assumed. Re-measure
before trusting any of these; the commands are given so that is cheap.

Measured 2026-07-26 from the development Mac on the same LAN as the intended
server, so LAN-side numbers are a proxy for the server's own.

## Network

| fact | value | how |
|---|---|---|
| public IP | `172.83.7.210` | `curl -s https://ifconfig.me` |
| ISP | FirstDigital Communications (AS13415), Salt Lake City | `ipinfo.io` |
| CGNAT | **no** — routable address, not `100.64.0.0/10` | compare router WAN against the above |
| router WAN | `10.0.12.184` — **not** the public address | UPnP `GetExternalIPAddress` |
| NAT layers | **two** — a second router sits upstream | the two rows above disagree |
| upload | 99–508 Mbps across two runs, over Wi-Fi | `networkQuality` |
| download | 225–751 Mbps | `networkQuality` |
| idle latency | ~31 ms | `networkQuality` |
| outbound :25 | **open** | `nc -z gmail-smtp-in.l.google.com 25` |

### Upload bandwidth is not the constraint

The prior assumption was ~25 Mbps up, which would have capped the site at 8–10
concurrent 1080p viewers and made home hosting marginal for video. The measured
floor is 99 Mbps — roughly 40 concurrent 1080p renditions at ~2.5 Mbps each, and
the readings varied enough to suggest Wi-Fi contention rather than a link
ceiling. Measure again from the server over Ethernet before sizing anything.

### No CGNAT, but two layers of NAT

Both tunnel-based designs that had been proposed existed to survive CGNAT. The
address is routable and has reverse DNS, so inbound port-forwarding is on the
table and no third party is needed in the data path.

It is not one hop, though. The Netgear NATs to `10.0.12.184`; a second router
holds `172.83.7.210`. Measured by traceroute (`192.168.1.1` → `10.0.0.1` →
`172.83.7.209`, the ISP gateway) and confirmed by asking the Netgear its own WAN
address over UPnP. `10.0.0.1` answers ping but refuses 22/23/80/443/8443, so
there is no admin surface on it from in here.

**What this does not affect: outbound.** Sending mail, ACME's outbound calls, and
every measurement in this file stay valid — they were taken through both layers.

**What it does affect: inbound.** A forward has to exist on *both* boxes, and
only one of them is administrable from here. Ask FirstDigital, in preference
order: bridge/passthrough so the Netgear holds `172.83.7.210` directly; else a
static forward of 80/443 to `10.0.12.184`; else a DMZ to it. Same call as the PTR
forward-record request.

**Still unverified:** whether FirstDigital filters inbound 80/443. This cannot be
tested until something is listening and *both* routers forward — it is a build
step, not a preliminary.

**Consequence for the spam hunt:** everything behind `10.0.0.1` shares the public
address. If that box feeds anything besides the Netgear, a compromised device
could sit where `--scan-lan` can never reach it, and `doctor` now says so rather
than reporting an empty sweep as an all-clear.

## Mail deliverability

This is the hard part of the project, and none of it is guesswork.

| check | result |
|---|---|
| `zen.spamhaus.org` | **listed: XBL + CSS** |
| neighbours `.1 .50 .100 .209 .211` in the same /24 | all clean |
| PTR for `172.83.7.210` | `172-83-7-210.ip.fdtnet.net` |
| forward A for that PTR name | **none — FCrDNS fails** |

The DNSBL query path was validated against Spamhaus's own test entries
(`2.0.0.127` lists, `1.0.0.127` does not), so these are genuine listings and not
a resolver artefact.

**The listing is IP-specific, not a dirty ISP pool.** Every sampled neighbour is
clean, so Spamhaus's free self-service removal should stick rather than
re-trigger. Worth noting for its own sake: XBL is the *compromised host* list, so
something on the LAN may have earned it.

**FCrDNS is the harder problem and it is the ISP's.** The PTR name has no forward
A record, so forward-confirmed reverse DNS fails. Gmail and Outlook both weight
this heavily. Fixing it requires FirstDigital either repairing their forward zone
or delegating PTR for this address.

Consequence for the design: outbound mail supports **both** `direct` and `relay`
as first-class modes. Neither is hardcoded as impossible. `selfhost mail doctor`
measures the real blockers — DNSBL across zones, FCrDNS, port 25, DMARC
alignment, and a live test send — and `direct` is chosen when that passes rather
than when someone guesses it should.

Inbound mail is unaffected by any of this: port 25 is open and the MX is ours.

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
