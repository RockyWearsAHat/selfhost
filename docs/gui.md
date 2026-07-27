# The console

One place to see and control everything running on the machine — the Windows
Service Manager's job, on every platform, for any program: MongoDB, a NAS daemon,
a site's own backend.

## Shape: a daemon and a client

The server runs `selfhost daemon`, headless. The console is a **separate desktop
program on your own machine** that connects to it.

This split is not incidental. A GUI that has to run *on the server* would need a
logged-in desktop session there — the exact objection that removed Docker from
this project, since the target is a Windows PC that must stay up unattended. A
daemon plus a remote client has neither problem, and it means one console can
drive several machines.

```
your laptop                          the server
┌──────────────┐   ssh -L tunnel    ┌──────────────────────────┐
│   console    │ ─────────────────▶ │ selfhost daemon          │
│ (desktop UI) │                    │  ├─ supervisor: services │
└──────────────┘                    │  └─ control API (loopback)│
                                    └──────────────────────────┘
```

## The rule that changed, and why

Earlier revisions of this document said the console was **read-only**, so that
`selfhost.config.toml` stayed the single source of truth. That rule is gone: the
console configures services, because a service manager that cannot install a
service is not one.

The concern behind the old rule was real, though, and is still addressed — just
differently. Serialising a parsed config back to TOML **destroys every comment in
it**, and the config `selfhost init` writes carries the ACME rate-limit warning
and the bind-address reasoning in exactly those comments. So instead of one file
with two writers, there are two files with **one writer each**:

| file | written by | holds |
|---|---|---|
| `selfhost.config.toml` | a person, by hand | server, nodes, sites |
| `data/services.toml` | the daemon, only | services installed from the console |

Neither writer can destroy the other's work, and no file has to be locked or
merged. Hand edits to `services.toml` are read back, but the daemon rewrites that
whole file when a service changes, so comments added there do not survive — which
the file's own header says.

## The control API

Bound to `127.0.0.1` and **refused if configured otherwise**, because whoever
reaches this port controls every service on the machine. It is served on its own
listener rather than as a path on a site: a bug in a hosted website must not
become a way to control the deployment, and a reserved path prefix on a shared
listener is one routing mistake away from being public.

Remote access is deliberately not a feature of this port. The console reaches a
remote daemon by tunnelling over SSH, so the encryption and the authentication
are OpenSSH's rather than something invented here:

```sh
ssh -L 9191:127.0.0.1:9191 you@server
```

Authentication is a bearer token in `data/admin.token`, mode `0600`, generated
from the operating system's entropy and compared in constant time.

```
GET    /api/health                       no auth; is a daemon listening?
GET    /api/services                     every service and what it is doing
GET    /api/services/{name}              one service: live state + definition
PUT    /api/services/{name}              install or edit          → services.toml
DELETE /api/services/{name}              uninstall                → services.toml
GET    /api/services/{name}/logs?from=N  incremental output tail
POST   /api/services/{name}/start|stop|restart
```

Lifecycle actions answer `202`: the command was accepted, not that it finished.
Supervision is asynchronous, so the console polls for the outcome — which it must
do anyway, for state changes nobody asked for.

`logs` is incremental. Every line carries a sequence number, and the reply
includes `nextSeq` to ask from next time plus `missed`, the number of lines
evicted before the reader got to them. A console that has fallen behind is
**told** rather than being handed a shorter answer that looks complete; a silent
gap in a log reads as evidence that nothing happened.

## What a service is

See [`selfhost_config::service`](../crates/config/src/service.rs) for the full
model. The parts that matter:

- **`program` and `args`, not a command line.** A single string has to be
  word-split by someone, and every implementation splits quoting differently. A
  path containing a space is the common case that breaks, silently, at start.
- **`start_mode`** — `automatic`, `manual`, or `disabled`, as the SCM has it.
- **`restart`** — `never`, `on-failure` (the default), or `always`. `on-failure`
  is the default because a clean exit is usually a program that was asked to
  stop, and restarting it fights the operator.
- **`stop_command`** — how to ask this service to shut down cleanly, before any
  signal. This exists because a graceful stop is *not portable*: Unix has
  `SIGTERM`, Windows has nothing that reaches a process with no console. Many
  programs ship their own answer (`mongod --shutdown`, `nginx -s quit`), and
  naming it makes the stop clean everywhere instead of only on Unix. For a
  database on Windows this is the difference between a clean stop and corruption.

Restarts back off exponentially from `restart_delay_secs`, capped at five
minutes, and the failure counter resets once the service has stayed up for a
real stretch — so a service healthy for a week is not treated as if it had just
crashed, and a crash loop cannot reset its own budget every cycle.

Stopping a service stops **everything it started**. Services are spawned into
their own process group, because nearly every real service is launched through a
wrapper — a shell script, `npm start` — that forks the program actually holding
the port. Signalling only the direct child kills the wrapper and reparents the
real worker to init, still listening, so the next start fails to bind and blames
the wrong thing.

## State

**Built and tested.** The daemon half is complete and verified against real
processes: supervision, restart policy, log capture, the catalogue, and the
control API. Run it with `selfhost daemon`; `selfhost services` lists what is
installed without needing the daemon running.

**Not built.** The desktop console itself, and the toolkit it is drawn with. The
old static mock at `gui/index.html` is unrelated to this design and is kept only
as a reference for the sites-and-certificates view.

The toolkit is written here rather than taken as a dependency, on the same
reasoning as the rest of the project. Platform windowing and text APIs are the
*platform* — the same category as `socket()` — so the plan binds directly to
AppKit, Win32, and X11, and hand-rolls nothing that a hand-rolled version would
be worse at. Notably **text is delegated to the platform's own stack** (Core
Text, DirectWrite, Xft): font parsing, glyph rasterisation, and Unicode shaping
are where hand-written toolkits fail, and a coverage bitmap from the OS costs no
dependency.

Everything above the platform layer — geometry, the rasteriser, layout, event
routing, and the widgets — is pure and renders into a plain pixel buffer, so it
is testable headless. `unsafe` is confined to three backend files.
