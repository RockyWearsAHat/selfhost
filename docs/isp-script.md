# Calling FirstDigital

What to say, and what a good answer sounds like. Read the **bold** lines; the rest
is there so an unexpected answer does not derail the call.

Every fact below was measured, not assumed. Sources are in
[`constraints.md`](constraints.md).

**Superseded 2026-08-08.** The double-NAT problem this script used to open
with is gone — the ISP now terminates the public IP directly on the router,
and inbound 80/443 (and, since, 25/587) are already forwarded and verified
working. What is left, and what this call is now about, is outbound port 25
and the PTR record. The old bridge-mode/second-router asks are kept below,
struck through, in case that topology ever regresses.

## Facts to have in front of you

| | |
|---|---|
| Public IP | `172.83.6.109` |
| Reverse DNS on it | `172-83-6-109.ip.fdtnet.net` |
| Reverse zone | `6.83.172.in-addr.arpa`, served by `ns1/ns2.firstdigital.com` |
| Symptom | outbound TCP 25 silently dropped (confirmed: ICMP to the same hosts succeeds, no local firewall rule blocks it, two unrelated destinations both hang ~85s rather than refuse instantly — see `constraints.md`) |
| Contact named by prior correspondence | `ipadmin@firstdigital.com` |

**Open with the technical asks, not "I want to run a mail server."** Front-line
support has a script for the second framing and it ends the call.

## Ask 1 — unblock outbound port 25

> **"Outbound connections on TCP port 25 from my IP, 172.83.6.109, are being
> silently dropped — not refused, dropped. I've confirmed it isn't my
> equipment. Can you remove the outbound port 25 filter for this address?"**

- If they say **residential lines don't get this**: ask about a business tier
  or a static-IP add-on that doesn't filter it, and whether it can be handled
  as a one-off exception tied to the account instead of a plan change.

## Ask 2 — the reverse record has no forward record

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

## Ask 3 — confirm the IP is static

> **"Is 172.83.6.109 a static assignment, or could it change on a lease
> renewal? If it isn't already static, can you make it one?"**

Worth asking while you have them — a lease that moves would undo both fixes
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
