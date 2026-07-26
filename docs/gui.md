# The console (GUI)

Rough draft at [`../gui/index.html`](../gui/index.html). Open it in a browser —
it is a single self-contained file with sample data and needs no server.

## What exists

A read-only dashboard showing: site count and instance health as summary tiles,
each site with its aliases and per-instance state (in rotation / removed,
in-flight count, load bar, cumulative failed probes), and a certificate table
with expiry.

Adapts to light and dark, and scrolls tables horizontally on a phone rather than
scrolling the page sideways.

## What makes it a draft

The sample data is hard-coded in one constant, `SAMPLE`. There is no admin API.

The shapes were written to mirror the Rust types deliberately — `SAMPLE.sites[]`
matches `selfhost_config::Site`, and `instances[]` matches what
`selfhost_proxy::upstream::Upstream` already tracks (`healthy`, `in_flight`,
`total_failures`). Connecting it should be replacing one constant with a
`fetch`, not reshaping the UI.

## The one design rule

**Read-only.** Nothing in the console changes the deployment.

`selfhost.config.toml` is the single source of truth, and every other artifact is
derived from it. A GUI that also writes configuration creates a second source,
and the two drift the moment someone edits the file by hand — which they will,
over SSH, at some point, because that is faster.

So the console answers "what is happening right now" — which is exactly the
question a config file cannot answer. To *change* something, edit the file and
run `selfhost check`.

If live editing is ever wanted, the honest version is a form that produces a
config diff for the operator to apply, never a hidden write.

## The API it needs

Three read-only endpoints. All bound to loopback, all behind authentication, and
none of them reachable from a site's own hostname — a bug in a hosted site must
not become a way to read the deployment's state.

```
GET /_selfhost/api/status
  { sites: [ { name, domains[], staticRoot, health: { path, intervalSecs },
               instances: [ { node, address, healthy, inFlight, totalFailures } ] } ] }

GET /_selfhost/api/config     the parsed config as JSON
GET /_selfhost/api/certs
  { certificates: [ { host, issuer, daysLeft } ] }
```

`status` is the only one that needs care: it reads live atomics out of the
`Pool`, so it must not take a lock that a request path also takes.

## Serving it

Simplest workable route: a reserved `/_selfhost/*` prefix on a dedicated
loopback listener, separate from the public binds. Not on a site's hostname —
the isolation matters more than the convenience.

Authentication is unsolved and should not be skipped. A token in the data
directory, readable only by the service account and passed as a header, is
sufficient for a single-operator deployment and is a great deal better than
nothing.

## Later, roughly in order

1. Wire it to the real API.
2. Live updates — poll every few seconds, or Server-Sent Events over the existing
   HTTP/1.1 support.
3. Health-event history, so a flapping instance is visible as a pattern rather
   than a single current state.
4. Log tail.
5. Mail queue and deliverability status, once mail exists — this is where
   `selfhost mail doctor` output belongs, because DNSBL and FCrDNS status is
   exactly the kind of thing nobody remembers to check from a terminal.
