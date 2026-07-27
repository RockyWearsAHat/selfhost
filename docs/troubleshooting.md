# Troubleshooting

Start here:

```sh
selfhost doctor              # everything checkable without sending traffic
selfhost doctor --deep       # also opens real connections to Gmail and Outlook
selfhost doctor --scan-lan   # also shortlists devices on your network
selfhost watch-dns           # answers DNS for the network and names the device
                             # asking for a residential proxy service
```

You do not need to know how any of this is built to read the output. Each check
prints what was tested, what came back, and — when there is something to do — an
arrow with the fix.

```
  [FAIL] forward-confirmed reverse DNS
         PTR is 172-83-7-210.ip.fdtnet.net, but that name has no A record
      →  Gmail and Outlook weight this heavily for inbox placement, and only
         your ISP can fix it.
```

`doctor` exits non-zero when anything failed, so it works in a script or a
health check.

## Reading the verdicts

| verdict | meaning |
|---|---|
| `PASS` | tested, working |
| `WARN` | working, but you should know about it |
| `FAIL` | broken; the deployment will not do its job until fixed |
| `????` | **could not be tested from here** — not the same as passing |
| `SKIP` | deliberately not configured |

`????` is the one to pay attention to. A diagnostic that reports "could not
test" as "fine" is how somebody ends up believing their mail works when it has
never been tried once.

## `--deep`

Adds live SMTP handshakes with Gmail and Outlook. It opens a connection, sends
`EHLO`, reads the reply, and sends `QUIT`. **No mail is sent and no message is
delivered.**

Worth running because it answers two things nothing else can:

1. Whether major receivers will talk to your address at all.
2. **Which address they see you as** — they echo it in the reply. If that
   disagrees with what the rest of the report was checked against, every
   blocklist and reverse-DNS result above it is worthless, and `doctor` says so
   rather than letting you trust them.

That second check exists because this tool got it wrong. See below.

## The bug that shaped this tool

The first version discovered the public IP by querying `whoami.akamai.net` — a
standard trick. It reported a clean address, passed every blocklist check, passed
reverse DNS, and declared mail healthy.

It was checking **the ISP's resolver**, not this machine. Those `whoami` services
answer with the address of *whoever asked*, and the query went through the router
to the ISP's resolver. The ISP's own resolver is, unsurprisingly, not
blocklisted and has correct reverse DNS.

The real address was blocklisted with broken forward-confirmed reverse DNS.

Two things changed as a result, and both are worth knowing when you extend this:

- The address now comes from **an outbound TCP connection**, which is the path
  that actually carries mail and visitors.
- It is **cross-checked against what the receiver reports**, and a disagreement
  is a `FAIL`, not a footnote.

## Common problems

### "It works on my machine but not from the internet"

The single most common home-server problem, and `doctor` marks it `????` on
purpose: **it cannot be tested from inside your own network.** Traffic to your
public IP from your own LAN never leaves the building, so it proves nothing.

Test it properly:

1. Start `selfhost run`.
2. On your phone, **turn Wi-Fi off** so you are on mobile data.
3. Open `http://<your-public-ip>/`.

Times out? Either the router is not forwarding 80 and 443 to this machine, or
the ISP filters them. Both are outside this program.

While you are in the router, give the machine a **static DHCP lease** — otherwise
the port forward eventually points at whatever device took that address.

### "Permission denied" binding port 80 or 443

Unix reserves ports below 1024. Either:

```sh
sudo setcap 'cap_net_bind_service=+ep' ./target/release/selfhost   # Linux, once
```

or bind a high port and let the router forward 80 → 8080 and 443 → 8443.

### "Address already in use"

Usually `selfhost` is already running. Otherwise:

```sh
lsof -i :443                          # macOS / Linux
netstat -ano | findstr :443           # Windows
```

### The browser warns about the certificate

Expected when `acme = "self-signed"`. That is the default so a first run needs no
network, no account, and cannot burn a rate limit.

For a public site, climb the ladder in order — `self-signed` → `staging` →
`production`. Production Let's Encrypt allows **five duplicate certificates per
week**, and a retry loop against a domain that does not yet point at you will
exhaust that in minutes and lock you out for a week.

### Tracking down WHY you are blocklisted

`--deep` adds an **Investigation** section that chases causes rather than
restating symptoms. It answers three questions the listing itself does not.

**Which list matched, and does it mean anything?** The return code's last octet
says which. They are not interchangeable:

| code | list | what it means |
|---|---|---|
| `127.0.0.2` | SBL | observed sending spam; reviewed by people |
| `127.0.0.3` | CSS | snowshoe-pattern sending, low volume spread thin |
| `127.0.0.4`–`.7` | **XBL / CBL** | **a machine here looks compromised** |
| `127.0.0.9` | SBL DROP | the whole netblock is listed; not yours to fix |
| `127.0.0.10`, `.11` | PBL | residential range — **expected, not a fault** |

PBL is a *policy label*: "this is a home connection, mail should not come from
it directly." Nothing is broken. XBL is an *observation*: something on your
network behaved like a compromised host. Confusing the two wastes days.

**Is it you or your provider?** It samples neighbouring addresses in your /24.
If most are listed, the range is dirty and delisting yours achieves nothing —
that is an ISP conversation. If only yours is, the cause is on your network and
delisting will hold once you fix it.

**Who can fix your reverse DNS?** You cannot set your own `PTR`. The tool reads
the reverse zone's `SOA` and prints the exact address to email:

```
  [PASS] who controls your reverse DNS
         zone 7.83.172.in-addr.arpa — contact ipadmin@firstdigital.com
```

### Finding the compromised device

An XBL listing says *a machine on your network* is compromised — and a home
network rarely has an inventory. `--scan-lan` builds one, works out what each
device is, and **names the one to act on**:

```
  [PASS] what the local network shows
         Nothing is implicated outright. 1 of 10 devices could not be fully ruled out.
      →  In the router, block outbound TCP 25 for all devices with logging turned
         on. That stops any spam immediately, and the log then names the internal
         address that tried to send.

  [WARN] 192.168.1.14 — not ruled out
         Brother, "BRN001BA9326ED8.local", 00:1b:a9:32:6e:d8
      →  It also exposes 23 (accepted the connection and said nothing), which
         fixed-function consumer hardware has no need for.

  [PASS] other devices
         9 behaving as expected — 192.168.1.1 (Netgear…), 192.168.1.6 (Sonos…),
         192.168.1.25 (Amazon, 14:0a:c5:23:51:20 — matches Amazon Echo / Alexa
         device), …
```

Three ideas do the work, and each replaced something that did not.

**It asks a port what it is, instead of reading the number.** A port number is a
convention, not a fact, and the interesting device is exactly the one not
following it. Every open port gets spoken to — SOCKS5, then HTTP tunnelling,
then plain HTTP — so `1080` serving a web page is reported as a web server, and
a proxy on `8888` is not missed for being in the wrong place.

**It identifies the hardware.** `192.168.1.25` tells you nothing; *Amazon
hardware that publishes no name* tells you where to walk. Three questions get
asked, because a device that dodges one usually answers another: the vendor from
its MAC address (which it cannot withhold, since the router already learned it),
a reverse lookup over mDNS, and an SSDP search — which streaming devices answer
with a model string precise enough to name the product.

**It weighs the observation against the device.** A SOCKS proxy is unremarkable
on a laptop and damning on a speaker, so nothing maps an observation straight to
a verdict. Devices that behave as their hardware should are counted in one line,
not listed — a diagnostic that prints everything it looked at has handed the
diagnosis back to you.

#### A refusal is not an alibi

The first version of this tool reported the device above as **`PASS` — "not an
open proxy and not the cause of a blocklisting"**, because it refused to relay
when asked. That was wrong, and it cleared the prime suspect during an active
infection.

**Residential proxy malware does not accept connections from strangers.** It
dials *out* to a controller and relays traffic back down that tunnel, so the
only client it ever serves is the one it called. Probed from your LAN it refuses
— exactly as innocent hardware would. The refusal is what the malware looks
like, so it can never be the evidence that clears it.

Only positive evidence clears a device now: it behaves as its hardware should.
Being turned away at the door proves nothing either way, and the tool says so.

#### …and stock behaviour is not an accusation

The correction above was then overcorrected, on the same device. Rewritten to
weigh a proxy against the hardware running it, the tool reported the Amazon
device at `192.168.1.25` as a **`PRIME SUSPECT`** — fixed-function consumer
hardware has no business running a SOCKS server, and this one answered with a
reply code the specification does not define.

It is an **Amazon Echo, and that is exactly what a stock Echo does.** Ports 1080
and 8888 are open out of the box — reported on
[r/AmazonEchoDev](https://www.reddit.com/r/AmazonEchoDev/comments/cyk24g/), on
the [Amazon device forum](https://www.amazonforum.com/s/question/0D54P00007y83AzSAI/),
and in an IACIS scan of an Echo Dot. Port 1080 carries audio-group traffic
between Alexa devices, which is why it accepts a session and then refuses every
destination you ask for.

The test that settled it was a **control**: the Fire TV on the same network
exposes 8009 and 9080 and neither 1080 nor 8888. Same vendor, different product,
different fingerprint — so the ports were specific to that device, not to Amazon.
Comparing a suspect against a known-good sibling should have been the first move
and was nearly the last.

`assess::STOCK_BEHAVIOURS` now records service patterns a vendor is documented to
ship, and a device whose every open port is accounted for by one is not accused.
Each entry carries its source so you can check the claim instead of trusting it.
Two guards keep this from becoming the original bug again: the match is tested
*after* the open-relay test, so a device caught actually relaying is never
excused, and a device that matches the pattern **and does anything else** stops
matching — the extra thing is exactly what would matter.

Both mistakes were the same one: a verdict outrunning the evidence. Reporting a
refusal as innocence sends you past the guilty device; reporting stock behaviour
as guilt sends you to factory-reset an innocent one.

**Reachability is the other half.** A service on your LAN cannot be abused by
anyone outside if nothing reaches it, so the tool reads the router's port
forwards over UPnP:

```
  [PASS] ports open to the internet
         the router forwards nothing, and it holds the public address — so no
         device on your network is reachable from outside
```

That check earns its place twice over: it also catches forwards **you never
asked for**. UPnP lets any program on your network punch a hole in the firewall
silently, which is a common way a machine becomes internet-reachable without its
owner knowing.

**But an empty forwarding table only means something if that router is the
edge.** So the tool asks it what address it holds on its outside interface and
compares that against the address the internet actually sees:

```
  [WARN] what sits between you and the internet
         your router's outside address is 10.0.12.184, but the internet sees
         172.83.7.210 — a second router sits between them
```

When they disagree, "nothing is reachable from outside" is unprovable from here —
the upstream box has a forwarding table this machine cannot read — so the verdict
drops to unknown rather than passing. It also caps what `--scan-lan` can claim:
everything behind the upstream router shares your public address, so a sweep that
names no culprit is not an all-clear, and the report says so.

The forwarding table and the sweep are compared, because the interesting case is
where they disagree — a forward pointing at an address that answered nothing:

```
  [WARN] 192.168.1.5 — not ruled out
         did not answer the sweep at all
      →  The router forwards 56618/UDP to this address … no open port, no name,
         and no entry in this machine's ARP cache. The mapping calls itself
         Teredo, which is an IPv6 tunnel …
```

It is `not ruled out` rather than a suspicion: a mapping outlives whatever
created it, so a laptop that opened one and left the house leaves exactly this
trace. The router's DHCP client list settles which it is.

It also probes this machine's own loopback, because malware frequently listens
locally and is driven by something else.

The sweep is bounded on purpose — a fixed port list, short timeouts, capped
concurrency — so it finishes in seconds. It only touches your own network.

#### What it cannot do

Nothing on your LAN can observe a device's *outbound* connections, and that is
where this class of malware lives. Two vantage points can settle it, and the
scan names both: **the router, blocking outbound TCP 25 with logging on** — the
log names the internal address that tried to send — and **`selfhost watch-dns`**,
below. Everything here is what narrows it down first.

### When the LAN scan finds nothing

Common, and it does not mean the listing is wrong. If nothing relays and nothing
is forwarded, the abuse was **outbound** — a device making connections rather
than accepting them — or the listing is **inherited from whoever held your
address before you**, which happens constantly on residential connections with
dynamic addresses.

Either way the next step is the same, and it is the one thing this tool cannot
do for you: **read the listing detail at**
`https://check.spamhaus.org/query/ip/<your ip>`. An XBL entry records what was
observed and when. If the last-seen timestamp predates your having the address,
it is inherited — delist and move on. If it is recent, something on your network
did it, and the detail usually names the malware family or protocol.

### Naming the device: `selfhost watch-dns`

The scan can only report what answered it, and residential proxy malware answers
nothing. It does have to do one thing before it can relay anything at all: **look
its controller up by name.** That lookup goes to whichever resolver the network
handed out, so become that resolver and the device names itself.

```
selfhost watch-dns                     # binds :53, forwards to the system resolver
selfhost watch-dns --upstream 1.1.1.1:53
sudo selfhost watch-dns                # port 53 needs privilege
```

Then, in the router, set the DHCP DNS server to this machine's LAN address and
let the devices renew their leases. Nothing is blocked or rewritten — every query
goes upstream unchanged and every answer comes back unchanged, over UDP and TCP
both, because a diagnostic that breaks the household's internet gets switched off
before it finds anything.

A hit prints the moment it happens:

```
!! 192.168.1.5 asked for pawns.app
   Pawns.app (IPRoyal) — a paid bandwidth-sharing app feeding IPRoyal's proxy supply
```

`Ctrl-C` prints the conclusion. Two things it is careful about:

**One lookup is a lead, not a verdict.** Somebody reading `honeygain.com` in a
browser produces exactly one query. A proxy client comes back to its controller
on a timer, and that repetition is what tells them apart — so a single sighting
is reported as a lead and the wording says why.

**Silence is not a clean bill of health,** and the report says so rather than
printing a reassuring nothing. Three things make a device invisible here: it
never renewed its lease, it resolves over DoH/DoT (reported separately, because
it explains an *absence* of findings), or the service is one
`proxyware::INDICATORS` does not know by name. Blocking outbound 53 and 853 for
every device except this one closes the first two.

### Mail is not being delivered

Run `selfhost doctor --deep` and work through the `Mail` section. The two
problems it usually finds are **neither of them code**:

**A blocklist listing.** Removal is free and self-service, but find the cause
first or it comes straight back. A Spamhaus XBL listing (`127.0.0.4` through
`127.0.0.7`) specifically means a device on your network looks *compromised* —
most often malware, or a "free VPN" app quietly proxying traffic through your
machine. Delisting without fixing that just restarts the clock.

**Broken forward-confirmed reverse DNS.** Your ISP publishes a PTR record for
your address, but the name it points at has no matching forward record. Gmail and
Outlook both weight this heavily. Only the ISP can fix it.

Find who to ask — the reverse zone's SOA names the contact:

```sh
selfhost doctor --deep     # prints the PTR name
```

Then ask them for **either** a forward `A` record for the PTR name, **or**
delegation of the PTR so you can point it at your own mail hostname. Ask about a
static IP at the same time; a residential lease can move.

Note what a listing does and does not cost you. Gmail and Outlook do **not**
consult Spamhaus — they use their own reputation systems, which is why the
handshake can pass while the listing stands. What a listing does break is the
large population of corporate filters, universities, and smaller providers that
*do* query it.

And a handshake passing is **not** delivery. A receiver can accept the connection
and the envelope, then junk or drop the message. The only way to know about
inbox placement is to send a real one.

### Blocklist results say "the blocklist refused the query"

Blocklists signal a refusal by answering in `127.255.255.0/24` — the same address
space as a real verdict. `doctor` tells them apart, but the usual cause is
querying through a large public resolver like `8.8.8.8` or `1.1.1.1`, which
Spamhaus rejects outright.

If `doctor` warns that it could not determine your system resolver, point it at
your router or ISP resolver:

```sh
selfhost doctor --resolver 192.168.1.1
```

## Checking the config alone

```sh
selfhost check     # validates, reports every problem at once
selfhost routes    # shows which hostname serves which site
```

`check` never stops at the first error — one run lists everything wrong, each
naming the field responsible:

```
✗ config describes an unworkable deployment:
  nodes: exactly one node must have role "owner" (found 2)
  sites[1].domains[0]: "example.com" is already served by sites[0]
  sites[0].health.timeout_secs: timeout (10s) must be shorter than the interval (5s)
```

## Watching a running server

Health transitions and one line per request go to stderr:

```
[health] levelup: 127.0.0.1:5050 unreachable, removed from rotation
[health] levelup: 127.0.0.1:5050 recovered, back in rotation
[access] 203.0.113.9 https example.com GET /videos 4ms
[proxy] 203.0.113.9: refused — ambiguous message framing: both Transfer-Encoding and Content-Length present
```

A `refused` line is the server rejecting a malformed or ambiguously framed
request. That is deliberate, not a bug — see `docs/roadmap.md` under "Things not
to do".

## Reporting a problem

Include the output of:

```sh
selfhost doctor --deep 2>&1
selfhost check
```

`doctor` prints no passwords, no keys, and no message content. It does print
your public IP and your domain names.
