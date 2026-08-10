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
cargo build --release
```

The binary lands at `target/release/selfhost`. Put it on your `PATH` if you
like, or call it by path — the examples below assume it is on your `PATH`.

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
selfhost run
```

```
selfhost listening
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

## Where things live

```
selfhost.config.toml    the only file you edit
sites/                  your websites' files
data/                   certificates, and later databases and mail
  tls/                  private keys, owner-readable only
```

`data/` is what the backups are for. Deleting it loses the deployment.

## What is not built yet

Being straight with you so you do not go looking:

- **ACME** — `staging` and `production` are not implemented. `self-signed` works.
- **DNS, mail delivery, the GUI, and service install** — see
  [`roadmap.md`](roadmap.md).

The proxy, the load balancer, the config layer, and the SMTP session logic are
done and tested. Everything else is honestly labelled.
