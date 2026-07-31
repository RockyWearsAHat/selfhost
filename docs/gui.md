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
remote daemon by tunnelling over SSH — see
[reaching a daemon on another machine](#reaching-a-daemon-on-another-machine).

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

## Reaching a daemon on another machine

```sh
selfhost-console --ssh you@server
```

That runs `ssh -N -L 127.0.0.1:9191:127.0.0.1:9191 you@server` as a child of the
console, waits for the forwarded port to start accepting, and talks to the near
end of it. The encryption and the authentication are OpenSSH's, which is a better
answer than anything this program could invent — the same trade that keeps
`rustls` in a project that writes its own protocols.

**The console manages the tunnel rather than assuming one.** A tunnel brought up
by hand is a second thing to remember, in a second window, that dies silently.
Running it as a child means the console can say *tunnel down: permission denied*
instead of *no daemon* — the same symptom, with completely different fixes.

**It never answers a prompt for you.** `ssh` asks two questions: to confirm an
unknown host key, and for a key passphrase. A graphical program has no terminal
to answer them on, so a prompt would hang the tunnel with no visible cause. Every
invocation therefore passes `-o BatchMode=yes`, which turns each question into an
immediate failure — and the console turns that failure into the one instruction
that fixes it, in a banner across the top of the window:

| what `ssh` said | what the console says to do |
|---|---|
| `Host key verification failed` | run `ssh <server>` once in a terminal, check the fingerprint, accept it |
| `Permission denied (publickey)` | `ssh-add` the key, name it with `--identity`, or `ssh-copy-id` it |
| `Address already in use` | the local port is taken; pass `--local-port` |
| `Could not resolve hostname` | check the name, or use the address |

Accepting a host key on the operator's behalf would throw away the only check
that makes the tunnel worth anything, so the console reports it and stops.

The forward is bound to `127.0.0.1` at both ends explicitly. A bare
`-L 9191:127.0.0.1:9191` follows `GatewayPorts`, which on a machine configured
for it would put a remote server's control port on this machine's network.
`ExitOnForwardFailure=yes` means a forward that cannot be established takes
`ssh` down with it, rather than leaving the console talking to whatever else
happens to hold that port.

**The token comes over the same connection.** `--ssh` reads
`data/admin.token` from the server with `ssh <server> cat …`, which needs no new
secret distribution: whoever can open this tunnel already controls every service
on that machine, so a token they may not read would protect nothing. Pass
`--remote-token <path>` when the daemon's project directory is not the login
directory, or `--token-file <path>` to use a copy already on this machine.

Closing the window kills `ssh` and waits for it, so a closed console does not
leave a forwarded port behind. A console that is *killed* — `SIGKILL`, a crash —
cannot run that, and its `ssh` outlives it exactly as a hand-started one would.

## Deploying from a branch

A service can carry a branch to watch. When the branch moves, the daemon stops
the service, updates the working copy, runs the build step, and starts it again.

```toml
[[service]]
name = "levelup"
program = "/usr/bin/node"
args = ["server.js"]
cwd = "checkouts/levelup"

[service.git]
repository = "git@github.com:RockyWearsAHat/lvl-up-longboarding.git"
branch = "main"
path = "checkouts/levelup"
interval_secs = 60
post_pull = ["npm", "ci"]
```

**Polling, not webhooks.** A webhook is an event that has to arrive, and it does
not arrive when the network hiccups, when the hook was configured against a URL
form the sender does not use, or when nobody configured one at all — each of them
silently. Polling a remote ref costs one small request per interval and cannot
fail silently: a poll either answers with a commit or reports why it could not.
A webhook can be added later as a way to make a poll happen *sooner*; it is not
allowed to become the only path. This is the one design decision carried over
from `windows-service-manager`, which learned it the same way.

**Stopped, then updated, then started — never restarted.** Updating a working
copy under a running process rewrites the files it is executing, and a process
that then exits looks to the supervisor exactly like a crash: the restart policy
fights the deployment for the process, and a service mid-`npm install` when its
old copy exits reads as a crash loop. The window is honest downtime, visible in
the console, rather than a restart that sometimes works.

**A failed build leaves the service stopped.** Starting it would run the previous
build against the new code. The reason is written into the service's output,
which is where the operator is already looking.

**The reset is hard, and untracked files survive.** A deployment that merges can
stop on a conflict at four in the morning, so the working copy is reset to the
fetched commit. Nothing is cleaned: `node_modules`, a build cache, and an `.env`
the operator put there all live untracked, and a deployment that deletes them is
one that also has to restore them.

**`git` is a program here, not a protocol we implement.** Everything this project
serves on a wire it writes itself, because a lenient parser is a security bug.
Git is neither on that wire nor reachable by a visitor: it runs only when an
operator's own branch moves. Reimplementing the pack protocol would buy no
independence — the repository is GitHub's either way — while costing the exact
correctness the rest of the protocol work is for. The cost is stated honestly:
`git` must be installed on the server, and a missing one is reported in the
service's own output rather than guessed at.

**The repository URL is validated as untrusted input,** because it arrives over
the control API. `git`'s `ext::` transport runs its argument as a command, and a
URL beginning with `-` reaches `git` as an option, so the transports are an
allow-list: `https://`, `http://`, `ssh://`, `git://`, and `user@host:owner/repo`.
Private repositories authenticate with the daemon user's own SSH key; no
credential is stored in the catalogue, because a secret in a file the daemon
rewrites and the console displays is a secret that leaks.

**Not built:** a webhook receiver, and an OAuth device flow for repositories the
daemon's key does not already reach.

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

## The console is a real program, not a web page in a wrapper

There is no browser and no HTML. `selfhost-console` is a native binary that
opens a window, rasterises every pixel in it, and reads input from the platform
directly. Two crates, split by what they are about:

| crate | what | `unsafe` | tests |
|---|---|---|---|
| `crates/rui` | The interface library: elements, style, layout, the rasteriser, the TrueType engine, text, animation, and the platform windows | confined to `shell/platform/` | 263 |
| `crates/console` | The application: the client, the poller, and the views | **forbidden** | 91 |

`rui` is not a selfhost component. It is a general interface library that this
console happens to be the first program written in — it has no dependencies at
all, knows nothing about services or daemons, and is documented on its own terms
in [`crates/rui/README.md`](../crates/rui/README.md). It now lives in its own
repository as well, at <https://github.com/RockyWearsAHat/rui>, which is where
it is developed and where other projects take it from; this workspace still
builds it from `crates/rui` by path. What follows here is what the *console*
does with it, and why.

Everything above the window is pure: it turns a font's bytes and a stream of
events into a buffer of pixels. That is what makes a graphical program testable —
layout, hit testing, scrolling, text editing, and every element are asserted
against with no display attached, the same way `selfhost-http` parses bytes
without owning a socket. `App::render` draws a whole frame with no window
anywhere, through exactly the code path a window uses;
`cargo run -p rui --example gallery -- .` writes one out as a PNG.

### The interface is described, not drawn

A view is a function from the console's state to a description of what should be
on screen, and the console's state is a handle on the shared `Snapshot` and the
state of the install form — nothing else. The rail is:

```rust
style::plate((
    section("SERVICES", Some(snapshot.services.len().to_string())),
    list,
    button("+  ADD SERVICE").on_click(|console: &mut Console| console.form_mut().open_blank()),
))
.w(Length::Fraction(RAIL_SHARE))
.min_w(RAIL_MIN)
.max_w(RAIL_MAX)
```

Two things follow from that shape, and both are the reason for it.

**Nothing caches what the daemon said.** The description is rebuilt from the
snapshot every frame, so a service that has just died cannot still be drawn as
running by a widget that was not told. The alternative — a retained tree of
widget objects — needs every change in the data mirrored into it, and every bug
in that mirroring is an interface stating something untrue.

**What a control does is testable without a window.** A handler is an ordinary
`Fn(&mut Console)`, so a test builds the row of lifecycle buttons, takes the one
it means, and calls it:

```rust
let start = actions("mongod", &ServiceState::Stopped, true).child(0).unwrap();
(start.click_action().unwrap())(&mut console);
assert_eq!(console.snapshot().commands.front(), Some(&Command::Start("mongod".into())));
```

That used to require a canvas, a fake input state, and a frame drawn at a size
chosen so the button landed under a synthetic click.

### The platform layer is four methods

A backend opens a window, says how big it is, hands over the events it received,
and copies a buffer of pixels onto the screen. Nothing else. Anything a backend *could* decide for itself — what a click
means, where a widget is — is decided above it, identically everywhere.

| platform | window and input | blit |
|---|---|---|
| macOS | AppKit, reading `NSEvent`s off the queue | `CGImage` into a `CALayer` |
| Windows | Win32, reading messages off the queue | `StretchDIBits` |
| Linux | Xlib | `XPutImage` |

None of them defines a class or installs a callback that reaches state it does
not own. On macOS that means no `NSView` subclass built at run time; on Windows
the window procedure is three lines, and exists only because two messages must
be *answered* rather than observed.

The pixel format is the same on all three: `0xAARRGGBB` words, which read as
blue, green, red, unused in memory — exactly what Core Graphics, a Win32
`BI_RGB` bitmap, and an X11 `TrueColor` visual each want. Presenting a frame is
a copy and never a conversion.

### When the platform takes the loop away

A window system may run a loop of its own that does not return until the person
lets go of the mouse. macOS resizes a window that way: the mouse-down on the
window's edge is handed to `sendEvent:`, and that call does not return until the
mouse comes up. Everything above it — the frame loop, the console, the toolkit —
is stopped inside it for the whole gesture.

A program that only draws from its own loop therefore draws *nothing* while it
is being resized. The compositor stretches the last frame to each new size, so
the window smears, the text goes soft, and the interface snaps into place only
once the drag ends. That is what "resizing is laggy" was.

The way back in is a **run-loop observer**. It is registered once, for the
common modes — which include the event-tracking mode a live resize runs in — so
it fires on each turn of AppKit's nested loop as well as of ours, and draws a
frame from in there. Three things make that safe rather than clever:

- **It is gated on `inLiveResize`.** The observer fires on every turn of every
  loop, including the wait `pump` does itself; without the gate each idle wait
  would draw a second frame from inside the call that was only collecting
  events.
- **The window's mutable state lives in `Cell`s.** A frame drawn from inside
  `pump` has no `&mut self` to be had, and manufacturing one from a raw pointer
  would be two live `&mut`s to the same window. AppKit refuses to be touched off
  the main thread anyway, so a cell is exactly as much sharing as this needs.
- **The pointers the observer follows are set per pump and cleared after it.**
  Neither can be set once: the window is returned by value from `open`, so its
  address then is not its address later, and the closure belongs to one call.

`Backend::pump` therefore takes a `redraw` argument, and backends with no such
loop — X11 delivers a resize as an ordinary `ConfigureNotify` — never call it.

The plumbing is unit-tested, because every part of it is a C signature that
compiles whether or not it is right: a wrong activity flag registers for
nothing, a wrong mode registers for a loop that never runs, and both failures
are silent. The test registers an observer exactly as the window does and
asserts that it fires. What it cannot reach is `inLiveResize`, which needs a
hand on a mouse.

Three smaller things were making the same gesture cost more than it should:

- Every frame was **copied twice** — once to compare against the frame on
  screen, once into the `CFData` handed to Core Graphics. At Retina 980 by 680 a
  surface is ten megabytes. The comparison is now against a second canvas that
  is *swapped* with the drawn one, so recognising an unchanged frame costs a
  comparison and never a copy.
- `Canvas::resize` **replaced its allocation** rather than re-lengthening it. A
  window dragged by its corner resizes on every frame of the gesture, so that
  was a fresh ten-megabyte mapping sixty times a second.
- The layer was **not marked opaque**, so the compositor blended every pixel of
  the window against what was behind it. A canvas has no alpha — the bitmap
  format ignores that byte — so saying so is free.

### Text is rasterised here, not by the platform

An earlier revision of this document planned to delegate text to Core Text,
DirectWrite, and Xft. That is reversed: `crates/rui/src/font` parses the SFNT
container, the character map, and TrueType outlines, and fills them with an
analytic scanline rasteriser.

The reason is what the alternative cost. Three separate bodies of
foreign-function code, a link-time dependency on Linux, a text path that cannot
be tested without a window, and glyphs that come out differently on every
operating system. Owning it makes the console render identically everywhere and
testable with no display at all — the same trade the rest of this project makes
about protocols.

What it gives up is real and worth stating: **no complex-script shaping** (one
character becomes one glyph, so Arabic and Devanagari will not render
correctly), no ligatures, and no hinting. Latin, Greek, Cyrillic, numerals, and
punctuation are correct, and are **kerned** — the pair adjustments in a face's
`kern` table or its `GPOS` `kern` feature are read and applied, because that is
a table lookup rather than the reordering engine shaping would need. Where text
is *cut* — a caret, a wrapped line, an ellipsis — the unit is a grapheme
cluster under a documented subset of UAX #29, so a letter is never separated
from its accent; `crates/rui/src/text/grapheme.rs` states what that subset
covers and what it does not. These are limits of the font engine and not of the
toolkit — `Font::parse` takes bytes, so a deployment needing more is a question
of which file gets loaded.

The face itself is **not shipped**. A font is several hundred kilobytes of
someone else's licensed work and every desktop already has good ones, so the
console loads the platform's own — SF on macOS, Segoe UI on Windows, DejaVu or
Liberation on Linux — with a fallback list behind each.

### The corner, and the costume it used to wear

`Canvas` draws every shape from a signed distance field, and that field takes a
`Corner`: `Square`, `Round(size)`, or `Cut(size)`. A cut corner is the
intersection of the rectangle with the diagonal half-planes that slice its
corners away, and the distance to an intersection of convex regions is the
greater of the distances to each — so a cut costs an add and a multiply where a
round costs a square root, and neither is a path.

Everything framed takes `Theme::corner()`, and that one word is the console's
character. It used to be `Cut`, on an argument that reads well and was wrong: a
rounded corner is the corner of a card, a card is a piece of paper, and this
console reports on a machine rather than showing paper — so the corner should be
the chamfer of a panel bolted into a rack.

**What that produced was a costume.** The chamfer was never alone. It arrived
with a cyan accent on a blue-black ground, a graph-paper grid ruled across the
window, a halo behind every panel, button, tab, and status dot, corner brackets
around the log, a segmented gauge for the meter, and the title, tabs, headings
and figures all set in the monospaced face and tracked open. Each of those had
its own defensible paragraph. Together they stopped reading as *this program is
about a machine* and started reading as *this program is pretending to be from a
film* — which is the one thing a tool somebody opens every day must not look
like.

So `Theme::corners` became a radius, the grid went, the halos went, the brackets
went, the gauge became a bar, and `rui`'s own accent is a blue. That is still
what the *library* is, and the rule behind it still holds for anything the
operator presses: **there is no credit for disagreeing with the platform about
what a button looks like.**

The lesson is worth keeping, because the failure was not any one of those
decisions. It was that each was justified in isolation, against the thing it
replaced, and nothing ever asked what all of them looked like at once. The
sample frame is the answer to that: `cargo run -p rui --example gallery -- .`
draws every element to an image in both appearances, and the console's own
`reference_frames` test writes the whole window the same way — as it opens, at
the smallest size the backend allows, with the form open, with nothing
connected, with a link still being made, and with a failure announced. A
decision about appearance is not made until it has been looked at there.

### And then it was made an instrument on purpose

The console is now a lit HUD again: a near-black navy ground scribed with a
faint graticule, one electric cyan, chamfered plates marked at their corners by
brackets, a ring gauge for how much of the machine is up, and a sweep that goes
round while a connection is being made. Read against the section above that looks like the costume coming back, so
what makes this the *other* thing has to be said plainly. Three rules, and they
are the whole difference:

- **The platform still owns what you press.** `Theme::corners` is left as the
  library's `Round`, so every button, field and segmented control in the window
  is the desktop's shape. What is cut is what the console *reports on* — the
  plates, the rail's rows, the lamps, the log's well — and each of those is
  named with an explicit `Radius::Cut` rather than by changing the one word that
  would chamfer the controls too.
- **Glow is a fact, not a filter.** A halo appears on a lit lamp, on the chosen
  row, on a gauge's swept arc, and on the sweep itself. Nothing else has one.
  The costume's halo was behind *every* panel, button, tab and dot, which is
  what made it a filter over the window and told the reader nothing.
- **Two hues at rest.** Cyan and steel. Amber and red appear only with a cause —
  a countdown, a service that has stalled — and healthy is deliberately a
  cyan-tinted steel rather than a green, so a rail of working services stays
  quiet and the one that is not can be seen.

The graticule deserves its own sentence, because the costume had a grid and it
went. That one was ruled across the window, behind everything; this one is
painted on the *ground*, through the `App::ground` seam, and the plates are
opaque — so it exists only in the chassis around and between them, at a
twentieth of the accent, and cannot sit behind a single word. The margins used
to be the one part of the window that read as nothing; now they read as the
surface the instruments are bolted to.

Motion obeys the same test. There are exactly two loops in the program: the
sweep, which is drawn only while the link is being made or the tunnel is
opening, and the pulse under a lamp that wants attention. A frame that asks for
a loop asks for another frame, so a window with nothing outstanding still idles
— which is the mechanical version of *motion means state that is in flux*.

### Where the chamfer went instead

The argument above is about `Theme::corner()`, which is what every *framed* thing
takes when it asks the theme for its shape: a panel, a button, a field, a tag.
The console leaves it a radius on purpose.

That is a choice and not a limitation, because the seam exists: `App::theme`
takes a *function* of the appearance, `Theme::with_corners` swaps the shape and
`Theme::with_palette` swaps the colours, and everything below reads whatever
comes back — and `App::ground` hands over the bare window the same way, so an
application can paint the surface its interface sits on without the library
growing an opinion about graticules. `crates/console/src/view/style.rs` is
where the console spends both — on the palette and the ground, and on nothing
else. Changing `corners` there would be one word,
and it would chamfer every control in the window, which is exactly the line the
list below draws.

What the console also owns is the marks it draws with its own painter, in the
same file. The line it draws is what a mark is *for*:

- **Anything the operator presses keeps the desktop's shape.** A button, a
  field and a segmented control are things every program on the machine also
  has.
- **Anything the console *reports on* is cut.** The plates, the rail's rows, the
  lamp beside a service, the wedge against the chosen row, the flag down a line
  of standard error and down a banner, the mark in the masthead, the well the
  log is written in. None of these is a control, none has an equivalent in the
  desktop's own vocabulary, and every one exists to state a fact about a
  machine. A chamfer on those is not a costume, because there is nothing
  underneath it pretending to be something else. A row is on this side of the
  line even though it can be chosen: it is a readout, and being selectable does
  not make it a button.

The corner brackets are the same argument at the corners themselves — four short
strokes where each plate's chamfer ends, drawn as a `layer` so they take no room
from what they frame and cannot change what fits inside it.

One thing had to be *looked at* before it could be settled, and the swatch is
why the lamp is the shape it is. **A chamfer has to be seen to mean anything,
and at eight or ten units square it is not seen.** Cut a tenth off each corner
of a ten-unit square, antialias it at the size a screen actually draws it, and
what comes out is a circle; cut it half and what comes out is a diamond, which
reads as a warning sign whatever colour it is in. So the lamp is a *slot* — five
by fourteen, two units off each corner — because a tall shape has edges long
enough to carry the cut. It is most obviously a chamfer when it is **unlit**,
which is the state that most needed telling apart.

That last part is the second thing the lamp does. It is filled when the service
has something to assert and left as an outline when it does not, so the state is
said twice by two different means — a hue and a shape — and a reader who
receives no colour at all still sees which services are running.

### What the interface is made of

Three marks above a flat fill, each drawn by the scan that was already there:

- **A panel is lifted, not outlined.** `Canvas::shadow` reads the same distance
  field from *outside* the shape, so a shadow scans the band it occupies and
  never the area it surrounds — the trade that already made a one-pixel outline
  cheap. It is cast in `Palette::shadow`, offset slightly downward, and that
  offset is the whole difference between a shadow and a glow: light comes from
  above, so there is more shadow below the panel than above it.
- **Surfaces shade downward, barely.** A panel is filled from `surface` at its
  top edge to `surface_deep` at its bottom, with a hairline of `sheen` inside
  the top edge. A vertical gradient is the one direction that costs nothing — a
  row of it is a single colour, so the bulk span that writes a panel's interior
  still writes one word repeatedly and the mix happens once per row. A
  horizontal or angled gradient would be a mix *per pixel* and is deliberately
  not offered. A test asserts the shift stays under six percent: past that it
  stops reading as material and starts reading as a texture.
- **The accent is one hue, and it is the only saturated colour in the chrome.**
  It fills the primary button, underlines the chosen tab, outlines the selected
  row, and rings whatever has the keyboard. Nothing else. It is a hue none of
  the four status colours is near, so the primary action can never be mistaken
  for a health signal, and a test asserts the distance. It is a blue in `rui`'s
  own palette and an electric cyan in the console's, which is the seam being
  spent on the one thing a program's own character is actually made of.

A panel is separated from the window by **value** as well as by its outline, and
a test asserts that too. The dark palette used to hold its surfaces within a
value or two of the background on the theory that a cut edge was doing the
separating; what that actually produced was panels you could only find by
looking for their outlines.

### Ruled, not boxed

The window holds exactly **four framed surfaces** — the masthead strip, the
readout bank, the rail of services, and the detail pane — and everything inside
them is separated by ruling instead of by more outlines. That is a correction
that survived every redesign. An earlier revision put four rounded cards of
counts inside a rounded page inside a window, which is three frames drawn around
every fact, and the result read as a diagram of an interface rather than as one.

A **section rule** is the console's `style::section_rule`: a small-capital label,
a hairline running from it to the far edge with a short tick standing on its end,
and an optional aside set at the right. It does a box's job — saying where a
block ends — for a fiftieth of the ink, and it does the job a floating label
cannot, which is to state how far down the block extends rather than leaving the
eye to guess. `SERVICES`, `DEFINITION`, `OUTPUT`, and `POLICY` are each
introduced this way, and so is the window's own title bar, where the rule is what
stops a wide window reading as a mark at one edge and an address at the other
with nothing between them. The tick is what separates a rule from a border: a
hairline that runs out at the pane's edge reads as the top of a box nobody
finished, and the same line stopped by an upright reads as a measurement.

The rules are hairlines in `Palette::border` — the same line every panel is
outlined in, which in the console's palette is the accent at about a third of its
opacity. That was once a mistake and is now the point: dimming the accent toward
a grey border tinted every rule faintly cyan, which over a page of them read as
the interface being *lit* rather than ruled, and a HUD is exactly the interface
that means it.

**A state is a lamp and a word, and the console draws no tags at all.** `tag` is
still in `rui` and is still a tint of the status's hue with the word in the hue
itself — it has been a capsule, then a cut bracket with a bar down its leading
edge, and now a fill — but the console reached the end of that argument and
walked out of it. A tag is a capsule drawn around one word; the word at the top
of the window is `CONNECTED` on nearly every frame the console will ever draw,
and the word at the end of most rows is `RUNNING`. Chrome around those lit the
window green to announce that nothing was wrong.

So the same mark is made in all three places — the masthead, the chosen
service's title line, and every row of the rail — and it is a lamp beside a bare
word. **The word is quiet unless it needs attention.** `Status::Ok` and
`Status::Idle` are set in `Tone::Muted`; only `Warn` and `Bad` get their own hue,
and the lamp carries the state the rest of the time. A rail where every healthy
row is lit green cannot say when one is not, which is the same argument that
deleted the lit bracket, applied to the thing that replaced it.

The bank obeys a stricter version of the same rule: **exactly one of its figures
can raise its voice, and it is `ATTENTION`.** A ratio is not a verdict — a
service the operator stopped on purpose would turn `RUNNING` amber and leave it
amber all day — and a restart is something that already happened and that the
supervisor already handled. A colour spent on either is a colour the reader
learns to look past, which is the colour `ATTENTION` needs to still be worth
something.

**The bank leads with a sentence.** Its first cell is `CONDITION`: one line, in
words, saying what the whole installation amounts to — *Everything is running*,
*backups needs attention*, *The daemon is not answering*. It is the only text in
the window about the machine rather than about one service, and it is what turns
four numbers into a report. The numbers stay because a sentence cannot say `2/4`;
the sentence stays because four numbers do not say whether that is fine. It
names the service when exactly one wants looking at, because "one service needs
attention" makes the operator go and find which. `SERVICES` left the bank to
make room: `RUNNING 2/4` already states the total, and the rail's own heading
states it again beside the list it belongs to.

`tabs` sizes each tab to its own label and lays them from the left. Dividing
the row equally is the obvious thing and is wrong at any width worth having:
three words spread across a wide window sit a hand's breadth apart, which reads
as three unrelated headings rather than as one control, and the underline under
the chosen one ends up a bar four times the length of the word it points at. The
rule still runs the full width, because what it separates is the row from the
page, not the tabs from each other.

### Small capitals, and why the type engine grew a tracking field

The **fixed-width face is reserved for text the machine produced**: the log, a
program path, an address, a gutter number, and whatever is typed into a field —
because everything typed into a field here is read back verbatim by the machine,
and it is that face which makes `l` and `1`, or `rn` and `m`, tell each other
apart in a path someone has to check. A test asserts the split.

Everything the *interface* says about itself — the window's title, the tabs, the
section labels, the state beside each row, the figures in the readout bank — is set in
the proportional face. It used to be the other way round, on the argument that a
service's name in a proportional face at fifteen pixels reads as an
application's name in a title bar, which is the loudest available signal that
what follows is a document rather than a readout. That is true of the title
alone. Applied to the title *and* the tabs *and* the headings *and* the figures
it stopped saying "readout" and started saying "terminal", and a monospaced
window with a cyan accent is a screenshot from a film.

Capitals at ten pixels in a face spaced for lower case pack into a block, so
`TextStyle` carries a `tracking` field. **Only small capitals use it** —
`Theme::heading` and `Theme::state` — and a test asserts that everything else,
mixed case included, is set solid. `Theme::heading` opens up furthest because a
heading sits alone on its rule and can afford the room; `Theme::state` opens the
same capitals up less, because a state sits at the end of a line whose other
half is a service's *name*, and every unit spent tracking it is a unit taken off
the part that tells one row from another. The title and the figures used to be
tracked as well, which is what made them read as a title sequence.

Tracking is added inside `Fonts::advance_of`, the one place measuring, fitting,
wrapping, and drawing already go through, so a tracked run can never be fitted
to one width and drawn at another. It is asserted against a real face by
`rui::shell::fonts`, which is what loads one — the library ships no font, so a
width test with none loaded would pass on an empty advance and prove nothing.

Two things the small capitals bought beyond the look. The state beside a service
in the rail used to be a capsule, and on a narrow rail that capsule's chrome was
taking the room the *name* needed — so the name, which is the only thing telling
the rows apart, was the part being truncated. And the definition now reads as a
specification rather than as a conversation, which is what it is.

### The layout answers to what is being read

Three rules decide who gets the space, and each replaced something that was
sized by a number somebody picked:

- **The rail is a share of the window**, between 190 and 300 units and never
  more than half of what there is. It was a fixed 292 — a quarter of a large
  window and *over half* of the smallest one the backend allows, so the detail
  pane was squeezed hardest exactly when there was least to spare.
- **The output is promised its height and the definition is what gives way.**
  Both want the same space and only one of them changes: a specification is read
  once and is the same next time, while the log is why the console is open. So
  the log states a minimum height and the definition is left sized to its
  content — and the layout takes room back off whatever is sized to its content
  before it touches anything that asked for a height. The definition therefore
  shrinks and scrolls, in that order, without either block computing what fits.
  Sized the other way round — which is what each block taking what it needed
  amounted to — six rows of facts pushed the output entirely off the bottom of
  the smallest window.

  This used to be arithmetic: a `facts_height` function that subtracted the
  log's promise, floored the remainder to whole rows, and dropped the block
  heading-and-all when even one row would not fit. All of it is now two words in
  the description — `min_h` on the log, `.scroll()` on the definition — because
  the rule it was implementing is a *layout* rule and belongs to the layout.

The output carries a gutter of **sequence numbers**, which are the daemon's own
count — the thing that says how much was lost when `missed` is not zero, and the
thing two people reading the same log can point at. A line from standard error
gets a bar and a tint as well as a colour, because a hue alone is exactly what a
colour-blind reader does not receive.

### Motion, and where the clock comes from

Hovers fade, the selected row's bar grows out of the edge, and the tab indicator
slides between tabs rather than reappearing under a different one. That last is
not decoration: the movement is what says two tabs are one control in two
states, and a tile that simply reappeared elsewhere leaves the eye to find it.

`rui` reads no clock. `Memory::begin_frame` is *told* how long the last
frame took, and `Memory::ease` steps a value by `1 - e^(-dt/seconds)` — so motion is
identical whether a frame took four milliseconds or forty, and a test can step
the clock by a fixed amount and assert where a value got to. A fixed per-frame
increment would tie the speed of the interface to the speed of the machine.

Two details matter and are asserted:

- **A value seen for the first time starts at its target.** Otherwise opening the
  window plays a burst of animation, and a row scrolled into view fades in as
  though it had just changed.
- **Easing settles exactly.** Exponential approach never truly arrives, so a
  value within a thousandth snaps and stops asking for frames. Without that the
  console would redraw for ever after a single hover.

The loop then has two speeds. While `Memory::is_animating`, it waits 8 ms; once
everything has settled it goes back to `App::idle_timeout`, and a console nobody
is touching costs what it always did. Nothing in `rui::shell` knows *what* is
animating, and nothing above it knows there is a loop.

What the console has and does *not* animate is worth stating, because it is a
limit rather than a taste. Every animation in the window is a hover easing on
`Metrics::motion`, and a mark the console draws itself reads `Visual::lit` — the
same eased value every built-in control animates on — so a hand-drawn mark and a
button settle on one curve. A count that ran up to its new number, or a row that
settled into place, would need `Memory::ease` for a value of the console's own,
and `Painter` carries no `Memory`. It is left undone rather than faked with a
frame counter; see the note at the top of `view/style.rs`.

### What the console means, for anything that cannot see it

`rui` makes the tree of elements *be* the accessibility tree, so the console
writes almost nothing to get this: a button is named by the words in it, and a
row of a lamp, a service's name and its state is named after what it shows.
Three things did have to be said, and each is a fact the layout alone could not
carry:

- **The rail is a `Role::List` of `Role::ListItem`s.** Containment is where a
  row's position in a set of four comes from, so a screen reader says "3 of 4"
  without anybody counting. Before this the rows were clickable `Group`s, which
  is a control nobody has named — and `audit` said so.
- **A chosen row states `.selected(true)`.** Never inferred from the fill: a
  selected row and a hovered row can be drawn the same way in a theme somebody
  writes next year, and a colour was never a semantic.
- **The two controls with no words of their own are labelled.** The cross that
  dismisses a notice is `Dismiss`, and the minus beside each argument is
  `Remove argument 2` — otherwise a screen reader reads "multiplication sign",
  and every remove button is called the same thing.

None of that is a promise. `every_screen_is_reachable_named_and_ordered` drives
each screen the console can be on — watching a service, not yet connected,
announcing a failure, with the form open, and at the smallest window the backend
allows — through a real frame in `rui::testing::Harness` and runs
`assert_accessible` and `assert_tab_order` over it. It fails the build the moment
a clickable thing has no role, an interactive thing has no name, or a list item
turns up outside a list.

### What a frame costs

Measured on an M-series Mac, in a release build, drawing the whole console —
masthead, readout bank, rail, and detail pane, with a definition and a scrolling log
in it — at a Retina backing scale of two, into a canvas that already exists,
with a warmed glyph cache. Averaged over 200 frames by `reference_frames`, which
prints exactly this table:

| window | pixels | draw the whole interface | describe it |
|---|---|---|---|
| 560 × 420 | 0.9 M | **1.6 ms** | 13 µs |
| 980 × 680 | 2.7 M | **2.9 ms** | 13 µs |
| 1180 × 760 | 3.6 M | **3.4 ms** | 13 µs |

That is the budget that matters: an animating frame has 8 ms, and drawing one
takes rather under half of it.

The second column is the one worth dwelling on. Building the *entire*
description from the snapshot — every element, every style, every boxed handler,
allocated afresh — costs thirteen microseconds, which is **0.4% of the frame**. The
declarative model is therefore not paid for in frames; it is free, and what a
frame costs is what it always was: rasterising glyphs and filling spans. That is
also why the number does not move with the window size, while the drawing does.

The frame is dearer than the 1.9 ms this document quoted for the immediate-mode
revision, and it is worth saying why rather than quietly replacing the number.
Almost none of it is the rewrite: it is that the same window now fits half again
as many log lines, that each line draws its own row rather than two runs of
text, and that a line from standard error fills a tinted rectangle behind it. A
log line is a run of fixed-width glyphs, which is the most expensive thing on
screen, and there is simply more interface in the same window.

A frame that comes out identical to the last one is not sent at all, which is
most of them when nothing is moving: the only thing changing on an idle console
is the second counting up in a service's uptime.

That is not a dirty-region scheme. Nothing decides *which part* of the window to
repaint, because a system that works that out can work it out wrongly, and the
symptom is a stale pixel still showing a service as running after it has died.

## State

**Built, and verified against a running daemon.** `selfhost daemon` supervises
the services; `selfhost-console` shows them, follows their output, and starts,
stops, restarts, installs, and uninstalls them.

Verified by running it: the window opens in the console's own palette under
either desktop appearance, polls a live daemon twice a second, and renders four
services in four different states with their definitions and their captured
output.

**The appearance and the motion are verified headlessly, not by eye in a running
window.** This happens two ways, and they check different things.

*Without any font loaded.* `Console::update` is drawn to a buffer at the smallest
size the backend allows and at the ordinary one, with the form open and closed,
with a notice and without, and against a snapshot from before the daemon has
answered. No font is the point: every string measures to nothing, so every
rectangle comes out at its minimum and anything that only fits because a label
happened to be short fails here rather than on somebody's screen. That is what
caught the one defect the earlier style pass turned up — at 560 by 420 the
lifecycle row's fixed button width ran Restart off the right of the detail pane
and drew Uninstall on top of it. That arithmetic is gone: the buttons ask to
grow and state a maximum, so four of them share a narrow row instead of keeping
a width that does not fit.

*With the real faces, written out as an image.*

```sh
SELFHOST_FRAME_DIR=/tmp/frames \
  cargo test -p selfhost-console --release reference_frames -- --nocapture
```

`reference_frames` draws every screen the console can be on — watching a
service, the install form, the smallest window the backend allows, nothing
connected, a failure announced, and a link still being made — at the real
backing scale and through the real layout, to six PNGs, and then prints what a
frame costs at three window sizes. It is how the *look* is judged on a machine
that is not the target, which the font-less tests by construction cannot do. It
skips itself, saying so, unless `SELFHOST_FRAME_DIR` names somewhere to write and
a font is installed.

It writes one appearance rather than two. The console supplies its own palette
and draws the same instrument under a light desktop and a dark one — a display
does not turn white because the room's lights came on — so a second pass would
have written the same picture beside itself under a name claiming it was
different. The room that freed pays for the states that were missing.

A log drawn this way is already at its end on the *first* frame, which it did
not used to be. A scrolling area does not know how tall its content is until it
has laid it out, so pinning to the end was a position set from the previous
frame's measurement — and an image drawn from nothing showed a part-scrolled log
nobody sitting in front of the console ever sees. `.follow()` decides it inside
the layout pass that measures the content, so the end it goes to is this frame's
end.

What neither can check is how the motion *feels*, which needs the window.
Opening it on a Mac is the last step nobody has done since the change.

**A drawing change is not on screen until `scripts/macos-app.sh install` has
run.** The application in `/Applications` holds a copy of the binary, so
rebuilding `target/release` does not change what the Dock launches, and a
console left open goes on running the build it started from — an interface pass
can be finished, tested, and still look untouched to the person it was for. The
script quits the running console, force-closing one that will not go, replaces
the bundle, and reopens it if it was open. Finish any session that touched
`crates/rui` or `crates/console` with it.

**Compile-verified only.** The Windows and X11 backends type-check for
`x86_64-pc-windows-gnu` and `x86_64-unknown-linux-gnu` but have never been run —
everything so far has been built and tested on a Mac. They are the first thing
to exercise when the Windows machine arrives.

**The SSH transport and Git deployment are built, and verified live.** The
console opened a tunnel as a managed child, showed a live daemon's services
through it, and reported a refused key as *tunnel down* with the command that
fixes it — not as a missing daemon. A service installed through the control API
with a branch to watch cloned that branch from GitHub, ran its build step,
started, and printed the checked-out file; a second commit stopped it, updated
the working copy, and started it again on the new commit.

**Not built.** Views for sites and certificates. The console shows services,
which is what the control API serves; the sites-and-certificates view waits on
an API that reports them. There is no view for a Git watch either: a watched
service reports every deployment into its own output, which the console already
tails, but the branch and interval are only editable in `data/services.toml` or
over the API.
