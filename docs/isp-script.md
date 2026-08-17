# Calling FirstDigital

What to say, and what a good answer sounds like. Read the **bold** lines; the rest
is there so an unexpected answer does not derail the call.

Every fact below was measured, not assumed. Sources are in
[`constraints.md`](constraints.md).

**Superseded 2026-08-08.** The double-NAT problem this script used to open
with is gone — the ISP now terminates the public IP directly on the router,
and inbound 80/443 (and, since, 25/587) are already forwarded and verified
working. The old bridge-mode/second-router asks are kept below, struck
through, in case that topology ever regresses.

**Superseded 2026-08-12: outbound port 25 is no longer blocked.** `selfhost
doctor --deep` now measures it open and gets a live SMTP handshake through to
both `gmail-smtp-in.l.google.com` and `outlook-com.olc.protection.outlook.com`,
each confirming the connecting address is `172.83.6.109`. The port-25 ask that
used to open this script is resolved and has been removed; **Ask 1 below — the
PTR record — is now the whole reason for this call.** Mail passes SPF/DKIM/DMARC
and still lands straight in Junk at Gmail/Outlook because the reverse DNS does
not forward-confirm.

**Re-measured 2026-08-16 — nothing has changed and nothing can be changed from
here.** `dig -x 172.83.6.109` still returns `172-83-6-109.ip.fdtnet.net`, and
that name still has no A record. The reverse zone `6.83.172.in-addr.arpa` has
`SOA ns1.firstdigital.com. ipadmin.firstdigital.com. 2026012302` and is
delegated to `ns1/ns2.firstdigital.com` — **not** to `ns1/ns2.rockywearsahat.com`,
which serve only the forward zone. A PTR written into our own zone would never
be asked for by any resolver on the internet, so this record cannot be set
ourselves; only FirstDigital can set it, or delegate it. Prefer delegation
(Ask 1's second half) — it is the one outcome that means never making this call
again. Note that if delegation is granted, `crates/net/dns` needs work first: the
wire codec handles `PTR` (`RecordType::Ptr`, `wire.rs:38`) but the zone layer
has no PTR record kind at all — `data_type` maps `RecordData::Name` to `CNAME`
only (`zone.rs:468`), so the server cannot yet answer a reverse query.

## Facts to have in front of you

| | |
|---|---|
| Public IP | `172.83.6.109` |
| Reverse DNS on it | `172-83-6-109.ip.fdtnet.net` |
| Reverse zone | `6.83.172.in-addr.arpa`, served by `ns1/ns2.firstdigital.com` |
| Symptom | mail from this address passes SPF, DKIM, and DMARC but is still junked by Gmail/Outlook, because the PTR name has no matching forward A record (forward-confirmed reverse DNS fails) |
| Contact named by prior correspondence | `ipadmin@firstdigital.com` |
| Draft of the same ask, in writing | `docs/isp-ptr-request-email.txt` — useful to read verbatim if the rep prefers something you can dictate, or to send after the call as a follow-up they can reference |

**Open with the technical ask, not "I want to run a mail server."**
Front-line support has a script for that framing and it ends the call.

## Ask 1 — the reverse record has no forward record

> **"The PTR on 172.83.6.109 is 172-83-6-109.ip.fdtnet.net, but that name has
> no A record, so forward-confirmed reverse DNS fails. Can you either add the
> matching A record, or delegate the PTR for that address to a hostname I
> control?"**

Either outcome works; delegation is better long-term because it survives
changing hostnames later.

- If they ask **why you want it**: "Receiving mail servers check that the
  reverse name resolves back to the same address. Right now it doesn't, so
  mail from this address is treated as suspicious." True, concrete, and not a
  policy question.
- If they say **residential lines don't get custom PTR**: ask what a static IP
  or business line costs, and whether PTR delegation comes with it. Get the
  price rather than a yes/no — it turns a refusal into a decision you can make.

## Ask 2 — confirm the IP is static

> **"Is 172.83.6.109 a static assignment, or could it change on a lease
> renewal? If it isn't already static, can you make it one?"**

Worth asking while you have them — a lease that moves would undo the PTR fix
above, silently, at some later and less convenient time.

## Before you hang up

- **Ticket number**, for every ask that wasn't resolved on the call.
- **Which asks need a callback**, and when.
- Mention the `ipadmin@firstdigital.com` correspondence if the rep seems
  unsure who owns this — it may be the team that actually does.

## Retired asks (topology since resolved)

~~The router's WAN address is private, so there's carrier NAT in front of
it — I need TCP 80/443 forwarded to it, or that device bridged so my router
holds the public address directly.~~ The ISP collapsed this on its own; the
router now holds `172.83.6.109` directly and forwards ports itself. Kept here
only so a future regression is recognised for what it is, not re-diagnosed
from scratch.

## What not to do yet

**Do not request Spamhaus delisting speculatively.** The previous IP
(`172.83.7.210`) was listed; this one (`172.83.6.109`) has not been re-checked
since the move (see `constraints.md`). Check before acting on it either way,
and if it does turn out listed, XBL expires on its own once the causing
behaviour stops — delisting early and getting relisted produces a stickier
listing than the first one.
