# Getting started

Fifteen minutes from a clone to a page served over HTTPS by your own code, with
nothing published to the internet until you decide to publish it.

## What you need

- **Rust 1.85 or newer.** `rustc --version`. If it is missing:
  <https://rustup.rs>.
- Nothing else. No Docker, no web server, no database — not for this part.

## 1. Build it

```sh
git clone https://github.com/RockyWearsAHat/selfhost
cd selfhost
cargo build --release -p selfhost-cli
```

The binary lands at `target/release/selfhost`. Put it on your `PATH` if you
like, or call it by path — the examples below assume it is on your `PATH`.

**`-p selfhost-cli` is deliberate, and it is the whole server.** A bare
`cargo build --release` also builds the two desktop applications
(`selfhost-console`, `SelfHostVPN.app`), which are *clients*, not part of the
thing you are about to run — and which pull `rui`, a separate repository, at a
pinned revision. If you only want the server, you do not need that fetch.
Measured on an Apple-silicon Mac from a fresh clone: **1 m 25 s** for
`-p selfhost-cli`, with the crates.io packages already downloaded. Your first
build also fetches 64 transitive packages.

## 2. Create a deployment

Make a directory to hold *your* deployment — config, site files, and data. Keep
it separate from the source checkout.

```sh
mkdir ~/my-server && cd ~/my-server
selfhost init --email you@example.com
```

That writes two things:

```
selfhost.config.toml     the only file you edit
sites/hello/index.html   something to serve
```

Look at the config. It is deliberately short, and every setting has a comment
explaining what it does and why the default is what it is.

## 3. Run it

```sh
selfhost daemon
```

One command runs the whole deployment — websites, mail, DNS, supervised
services and the control API — in one process. (`selfhost run` is a kept alias
for the same thing; do not run both at once.)

```
selfhost daemon
  control api  http://127.0.0.1:9191
  token        <your directory>/data/admin.token
  catalogue    <your directory>/data/services.toml

No services installed yet. Install one from the console, or add it to
<your directory>/data/services.toml.

Reach this from another machine by tunnelling, never by binding publicly:
  ssh -L 9191:127.0.0.1:9191 <this-host>

admin: no console password at <your directory>/data/console.passwd; console
login is disabled until `selfhost console-password` sets one

listening
  http  127.0.0.1:8080  (redirects to https)
  https 127.0.0.1:8443
  site  localhost → hello (0 instance(s))
```

Open <https://localhost:8443>. Your browser will warn about the certificate —
that is correct and expected. The starter config uses a **self-signed**
certificate, which needs no network, no account, and has no rate limit. Click
through the warning.

Three things worth noticing:

```sh
# The certificate is real TLS, just not one a browser trusts yet.
curl -k https://localhost:8443/

# Plain HTTP redirects, preserving the path and query.
curl -i http://localhost:8080/some/page?a=1

# Byte ranges work, which is what video seeking needs.
curl -k -i -H 'Range: bytes=0-99' https://localhost:8443/
```

Stop it with Ctrl-C.

## 4. Understand the config

One file describes the whole deployment. Everything else is derived from it.

```toml
version = 1

[server]
http_bind  = "127.0.0.1:8080"    # 0.0.0.0:80  when you go live
https_bind = "127.0.0.1:8443"    # 0.0.0.0:443 when you go live
acme_email = "you@example.com"
acme       = "self-signed"        # then "staging", then "production"
data_dir   = "./data"

[[nodes]]
name = "home"
role = "owner"

[[sites]]
name        = "hello"
domains     = ["localhost"]
static_root = "./sites/hello"
spa         = false
```

### The rules worth knowing early

**Exactly one node has `role = "owner"`.** The owner holds every stateful
service — databases, mail, certificates. Two machines each running their own
database is two different websites, not one load-balanced website.

**`domains` — the first one is canonical.** Every other one redirects to it, so
`www.example.com` sends visitors to `example.com` rather than serving the site
twice at two addresses.

**Paths resolve the way a static site expects.** `/about` serves `about.html`,
`/docs/` serves `docs/index.html`, and `/docs` redirects to `/docs/` so the
page's relative links point inside the directory. Write links without the
extension; the files stay as your generator emitted them.

**`spa = true`** makes any *still* unmatched path return `index.html`. Turn it on
for React/Vue/Svelte builds, or a reload on `/videos/2024` will 404.

**`acme` is a ladder, and you climb it in order.** `self-signed` → `staging` →
`production`. Production Let's Encrypt allows five duplicate certificates per
week; a retry loop against a domain that does not yet point at you will burn
that in minutes and lock you out for a week.

## 5. Check your work before running

```sh
selfhost check     # validates the config, reports every problem at once
selfhost routes    # shows which hostname serves which site
```

And, once it is running, two that ask whether it is actually *working* rather
than whether it is configured:

```sh
selfhost health         # four loopback round trips: DNS, 80, 443, the control API
selfhost service check  # is the OS registration still what it was installed as?
```

`health` prints what it asked and what came back for each part, and exits
non-zero only for something that is running and **not serving** — so on a
laptop where nothing is up it says `untestable` four times and exits zero.
`docs/labs/supervision-lab.dx` is why both exist: a nameserver died every
seventy-two hours for months while every process-is-alive signal stayed green.

**`dns` is only checked if you asked for DNS.** Most deployments point a
registrar's nameservers at this box and serve only HTTP, and those get
`dns  not declared` and a zero exit — nothing to test here, not a failure.
The line becomes a real check when this deployment says it serves DNS, which
has two spellings: a `[dns]` section, or an installed `selfhost-lan-dns`
registration (which is how the production box does it, with no `[dns]` section
at all). If you *meant* to be authoritative and see `not declared`, the detail
on that line names both and says which one is missing.

This is worth a paragraph rather than a footnote because it was wrong until
2026-08-17, and getting it wrong was expensive: naming a site was read as
volunteering to be a nameserver, so an ordinary deployment reported `dns NOT
SERVING` for ever, `selfhost health` exited non-zero for ever, and — worst — the
daemon's repair loop spent all three attempts restarting a nameserver you never
asked for. `docs/labs/first-run-lab.dx` §8 has the transcripts either side of
the fix; `docs/labs/supervision-lab.dx` has the reasoning.

`check` reports *all* problems in one run, each naming the field responsible:

```
✗ config describes an unworkable deployment:
  nodes: exactly one node must have role "owner" (found 2)
  sites[1].domains[0]: "example.com" is already served by sites[0]
  sites[0].health.timeout_secs: timeout (10s) must be shorter than the interval (5s)
```

## 6. Add an application

A static site is one thing. Most real sites are a static build plus an API.

```toml
[[sites]]
name        = "levelup"
domains     = ["example.com", "www.example.com"]
static_root = "./sites/levelup/dist"
spa         = true
app_paths   = ["/api/*"]          # these go to the app; everything else is a file

[[sites.instances]]
node = "home"
port = 5050

[[sites.instances]]               # a second copy, for load balancing
node = "home"
port = 5051

[sites.health]
path            = "/api/health"   # probed on its own timer, not on user traffic
interval_secs   = 10
timeout_secs    = 3
unhealthy_after = 2               # consecutive failures before leaving rotation
healthy_after   = 2               # consecutive successes before rejoining
```

Start your app twice — once on 5050, once on 5051 — and the proxy balances
across both, probes both, and drops either one the moment it stops answering.

### Prove the failover rather than trusting it

```sh
# With both instances up, requests spread across them.
for i in $(seq 1 10); do curl -sk https://example.com/api/health; done

# Kill one. Within (interval × unhealthy_after) seconds, all traffic
# moves to the survivor and no request fails.

# Start it again. Within (interval × healthy_after) seconds it is back
# in rotation, with no intervention.
```

The log tells you when it happens:

```
[health] levelup: 127.0.0.1:5050 unreachable, removed from rotation
[health] levelup: 127.0.0.1:5050 recovered, back in rotation
```

**Instances need explicit ports, not a replica count.** Two copies on one machine
cannot share a port, and writing both ports means a collision is caught by
`selfhost check` rather than by one process silently failing to start at boot.

## 7. Going live

Not yet automated — this is the honest state of things. In order:

1. **Forward ports 80 and 443** on your router to this machine, and give it a
   static DHCP lease so the forward does not drift to another device.
2. **Change the binds** to `0.0.0.0:80` and `0.0.0.0:443`.
3. **Point DNS** at your public IP. Find it with `curl -s https://ifconfig.me`.
4. **Verify from outside your network** that 80 and 443 actually reach you. Many
   ISPs filter them. Testing from your own LAN proves nothing — the traffic never
   leaves the building.
5. **Move `acme` to `staging`** and confirm a certificate is issued.
6. **Only then move to `production`.**

Step 5 is not a formality. It is the difference between finding a
misconfiguration on a CA with generous limits and finding it on one that will
lock you out for a week.

## 8. Let it update itself

Once the deployment directory is a clone of your repository, add:

```toml
[self_update]
repository = "https://github.com/you/selfhost.git"
branch = "main"
```

The daemon polls the branch (every 60 s by default), and a push fetches,
rebuilds, and restarts every selfhost process — no SSH needed again. It only
ever fast-forwards: modified tracked files or local commits in the deployment
refuse the update rather than being discarded, and a failed build rolls back
and leaves the old build running.

## 9. Serve files from it (a share)

A share is a directory this box serves to *you*, over three doors that do not
share a credential. Nothing here is on until you write the block.

```toml
[[shares]]
id = "vault"                  # [a-z0-9-]; this is also the URL segment
root = "D:/Shares/Vault"      # absolute, must exist
read_only = false             # omit this and the share is read-only
browsable = true              # advertise over DNS-SD where the OS will publish
quota_bytes = 500000000000
```

Three rules the validator enforces, worth knowing before you pick a root:

- **A root may not sit inside `data_dir`, the TLS store, or the repository.** A
  share rooted at the checkout is a write primitive into a tree the self-updater
  builds and runs — remote code execution on the next push.
- **Roots may not nest with each other**, because nested shares make permissions
  ambiguous.
- **A share is read-only unless you say otherwise.** Writability is never
  acquired by accident.

Check it and look at what the box will do before it does anything:

```sh
selfhost check
selfhost share list
selfhost share usage
```

### Through the console

Both consoles grow a **FILES** screen the moment the daemon reports a share:
the share rail with a segmented quota gauge, a breadcrumb, a sortable listing,
upload, download, new folder, rename and delete. This is the door that uses the
console session — cookie or bearer token, CSRF-protected — and it is the one to
use for ordinary work.

### Mounting it in Finder (WebDAV)

*Go → Connect to Server* (`⌘K`), then:

```
https://admin.rockywearsahat.com/dav/vault
```

The password is the **console password** (`selfhost console-password`). The user
name is not checked — Finder insists on one, so type anything. You must be on the
VPN, because `/dav` sits behind the console site's own `allowed_cidrs` gate
exactly as `/api/*` does.

Two honest warnings:

- **Finder is chatty.** Every copy is a fresh connection today (the proxy closes
  a relayed connection deliberately, so its framing and the upstream's cannot
  disagree), so a folder of five hundred files is five hundred TLS handshakes.
  It works; it is not fast.
- **`/dav` has no off switch.** It is reachable the moment a console password and
  a `[[shares]]` block both exist. If you do not want it, do not set a console
  password on that deployment — or say so and it will get a config flag.

### Mounting it in Explorer (WebDAV) — read this before trying

*This PC → Map network drive → `https://admin.rockywearsahat.com/dav/vault`*.

**It will not work behind a self-signed certificate.** The Windows
Mini-Redirector refuses a certificate it does not trust and reports something
unhelpful about the folder name being invalid. Get a real certificate first
(`acme = "staging"`, then `"production"`, §7). The Mini-Redirector also probes
the *site root* with `OPTIONS /` during mount discovery, which is not routed to
WebDAV — only `/dav` and `/dav/*` are — so if mounting still fails after the
certificate is real, that is the next thing to look at.

### Exporting it over SMB

SMB is the operating system's own server, driven the way this project drives
`git` and `pf`. Add a block under the share:

```toml
  [shares.smb]
  name = "Vault"
  encrypt = true            # require SMBv3 encryption
  read_only = false
```

Then look at the plan, and only then apply it:

```sh
selfhost storage smb plan     # dry run: what would change, and what is left alone
selfhost storage smb apply    # `apply` is a word, not a flag — this can remove an export
selfhost storage discover     # what a laptop on this network would see, and who publishes it
```

- **SMB authenticates against OS accounts** (NTLM/Kerberos/`smbpasswd`). **The
  console password can never open an SMB session, on any platform.** A person who
  is to reach a share over SMB needs an account on that machine. This is a fact
  about SMB, not a gap here, and it is the single most common surprise.
- **Guest access is refused and is not configurable.** On Windows the share names
  `BUILTIN\Administrators` by SID; widening that to a non-admin OS account has to
  be done with Windows' own tools.
- **Applying a plan never starts the service.** `445` opens only when you ask for
  it explicitly, and it is **LAN-only, forever, never forwarded**. If the box's
  firewall is managed by selfhost, note that `445` is *not* in the rule set — an
  export can be created, advertised, and unreachable. That is the safe failure.
- **Your existing share points are not touched.** The reconciler removes only
  what it created, proved by an ownership ledger rather than by a name match.

## 10. Reach its screen (remote desktop)

This is the only capability here that **drives the machine** rather than serving
data. A hijacked desktop session reads every password typed at that machine,
including the one you use to authorise it. Read `docs/SECURITY.md` §3.7 before
turning it on; the short version is that it is off, and every dangerous field
inside it is separately off.

```toml
[desktop]
enabled = true             # a window
allow_input = false        # a keyboard — a separate decision, deliberately
reauth_window_secs = 120   # a control ticket needs a password or passkey this recent
max_session_secs = 14400   # 4 h ceiling; the console session's own expiry still wins
max_viewers = 2
allow_clipboard = false
bearer_may_control = false # an unattended automation token should not drive a keyboard
```

The config refuses a block that is merely *dishonest* — `enabled = false` beside
`allow_input = true` is rejected rather than quietly reduced, because the next
person to read the file will act on what it appears to say. Turning any of it on
is a config edit and a daemon restart: **none of it is reachable from the
console**, by design, because an attacker who reached the console would already
be holding that switch.

```sh
selfhost check
selfhost desktop status     # what is on, and whether the kill switch is in place
selfhost doctor             # the capture agent, and the permissions it is missing
```

### Watching, and then driving

In either console, the **DESKTOP** screen picks a machine and offers two separate
actions. **WATCH** opens a stream that carries viewing and nothing else — no key,
pointer or wheel event is forwarded on it. **TAKE CONTROL** closes that stream and
opens a *new* one, because the abilities of a live stream are fixed in its opening
message and cannot be widened.

Control asks for a **fresh** credential at the moment you click it, however long
the console has been open: a password or a passkey proved within
`reauth_window_secs`. That is the whole point — a twelve-hour cookie in a browser
left open on an unlocked laptop is not a keyboard. The refusal is legible
(*reauthenticate*), not a login page you are already past. In the native console
there is no passkey prompt, so a stale login sends you to the browser console to
re-prove it.

### The kill switch

```sh
selfhost desktop disable    # writes <data_dir>/desktop.disabled
selfhost desktop enable     # removes it
touch data/desktop.disabled # exactly the same thing
```

Every open stream ends within one five-second poll and every new one is refused.
It is a **file** rather than a command on purpose: anyone who can reach a shell, a
Finder window, an SMB mount or a recovery boot can engage it, and nothing they
need — not the config, not the admin API, not a password, not the daemon's own
health — has to still be working. It fails closed: anything that is not a clean
"no such file" counts as engaged.

### macOS: the permission dies on every rebuild

macOS keys a Screen Recording grant to the **code identity** of the binary that
asked, and this workspace ships ad-hoc-signed binaries — so every `cargo build`
produces a new cdhash and, to TCC, a program that has never been granted
anything. On a box running `[self_update]`, which rebuilds on every push:

> **Screen Recording is revoked by every deployment and must be re-given by
> hand, at the machine, after the binary has been rebuilt.**

There is no way around it short of Developer ID signing with a stable identity.
`selfhost doctor` reports the loss the moment it happens rather than leaving you
to discover it while watching a wallpaper. Screen Recording and Accessibility are
**two** grants in two panes, revoked independently — a session that only watches
is never blocked by the permission it will never use.

### Windows: what does not work yet

A daemon installed as a Windows *service* runs as `SYSTEM` in session 0, which
has no interactive desktop. The agent that owns the console session's pixels is
spawned and supervised, but its frames do not yet reach a viewer — so a
session-0 daemon tells the console it cannot reach the desktop, **and why**,
rather than showing a black rectangle. A daemon started from a signed-in session
captures directly and works in full. None of the Windows code has ever run;
`HANDOFF.md` §5 is the order to confirm it in.

## 11. Let somebody else use it

Everything above is a deployment with one human in it. A second person needs two
things, and they are deliberately **separate decisions**: a way to prove they are
who they say (a passkey), and a set of powers (a grant). `crates/app/admin/src/invite.rs`
argues the separation at length; the short version is that minting a credential
and handing out authority are different acts, and an invitation that carried
grants would collapse them into one.

You need a console site first — the passkey's relying party is that site's first
domain, and there is nowhere else to take it from.

```toml
[[sites]]
name = "console"
domains = ["admin.example.com"]
static_root = "./sites/console"
spa = true
console = true
allowed_cidrs = ["10.66.0.0/24"]   # a /24 or narrower; the VPN subnet, or 127.0.0.1/32
```

Then, in order:

```sh
selfhost check                                   # a console site with no allowed_cidrs is refused
selfhost console-password                        # your own login; theirs will be a passkey
selfhost daemon                                  # restart: the console site is read at startup
selfhost people invite mom console.read,files.read:vault
```

That last command prints a link, once. Send it to them; opening it on their own
device asks for a fingerprint or face and registers a passkey under the name
**from the invitation, never from the request** — an invite for `mom` can only
ever make a passkey called `mom`. `selfhost people invited` shows what is
pending, `selfhost people uninvite <name>` withdraws a code sent to the wrong
address, and re-inviting supersedes rather than adds, so there is never more
than one live code per person.

Some things worth knowing before you send one:

- **Naming capabilities on the invite is optional, and skipping it is a
  cul-de-sac.** `selfhost people invite mom` with no list mints a credential for
  somebody who will log in to an empty console. The command says so, and
  `selfhost people list` now names anybody who has enrolled and holds nothing so
  the grant is not forgotten — but nothing chases you. Decide the grant when you
  send the invitation if you can.
- **A capability is a whole word with its target.** `selfhost people capabilities`
  lists every one. `desktop.view` alone is refused; `desktop.view:alex-desktop`
  is a grant.
- **`selfhost people` writes the file directly and never calls the API**, on
  purpose: it is the tool you reach for when the console is the broken thing.
- **The person's share access is the console's FILES screen and nothing else.**
  Of the three doors into a share, WebDAV authenticates against the *console
  password* (yours, not theirs) and SMB against an *operating-system account*.
  Per-person credentials stop at the console's own door today.
- **Half the vocabulary opens nothing yet.** `site.admin`, `dns.admin` and
  `mail.admin` are real entries in a real registry that no route consumes.
  Granting one hands over a promise.

**One thing to know before you rely on this.** Everything up to and including
the door answering the code is proven — on this Mac and on the production box,
with the output recorded. **The last step is not.** Nobody has yet opened an
`/#invite=` link on a device and touched a fingerprint reader, so the passkey
ceremony itself has never been performed by anyone; and it will need a
certificate the browser trusts, because WebAuthn requires a secure context. If
you are the first, expect to find something, and write down what.

`docs/labs/people-lab.dx` is the subsystem's own document; `docs/labs/first-run-lab.dx`
walks this path end to end with recorded output, and its "NOT PROVEN HERE"
section is the list of what is still taken on trust.

## Where things live

```
selfhost.config.toml    the only file you edit
sites/                  your websites' files
data/                   everything the daemon owns, and nothing you edit
  tls/                  private keys, owner-readable only
  services.toml         services installed through the console
  admin.token           the control API's bearer token, 0600
  console.passwd        the console login, PBKDF2
  console.people        who else may use this box, and what each may do (0600)
  console.passkeys      the registered passkeys — the credentials, not the powers
  console.invites       outstanding invitations, as digests; never the codes
  audit.log             one line per control action, append-only
  repair.log            one line per fault, repair and escalation the daemon saw
  desktop.disabled      the kill switch — present means everything is off
  storage.smb-owned     which SMB exports selfhost created (and may remove)
```

A first run creates only `admin.token` and `tls/`; every other file appears the
first time the thing it records is used.

`data/` is what the backups are for. Deleting it loses the deployment.

## What is not built yet

Being straight with you so you do not go looking:

- **Nothing Windows has ever executed.** Roughly nine thousand lines — screen
  capture and input injection, the session-0 agent, the SMB backend, the Win32
  window backend — type-check for `x86_64-pc-windows-gnu` and have never run.
- **No file manager has ever mounted a share.** WebDAV is routed and tested from
  both ends; no Finder and no Explorer has met it.
- **Nothing publishes the DNS-SD records**, so a share does not yet appear in
  Finder's sidebar by itself. Windows has no mDNS responder at all.
- **The peer mesh is answered but carries nothing.** This used to say there was
  no `/api/mesh/link` route on the owner; there is — `crates/app/admin/src/mesh_api.rs`,
  reached through `StreamRoute::PeerLink`, and it admits or refuses a dial on its
  merits. What is still missing is the splice: `crates/services/mesh/src/splice.rs`
  exists and is tested, and nothing outside its own crate calls it, so an
  admitted link moves no traffic anywhere.
- **Nobody has ever completed the passkey ceremony.** The invitation door is
  proven live on this Mac and on the production box — a real code is answered
  with the invited person's name — but the last step needs a human and a
  fingerprint reader, and has not happened. `docs/labs/first-run-lab.dx` is the
  record.

`docs/roadmap.md` is the crate-by-crate list and the ordering; `docs/labs/desktop-lab.dx`
and `docs/labs/nas-lab.dx` are the two subsystems with runnable checks you can execute
yourself rather than take on trust.
