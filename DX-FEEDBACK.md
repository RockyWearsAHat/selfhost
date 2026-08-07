# dx feedback — agent field report

Session: Self-Host / rui console UI pass, 2026-08-06. Agent: Claude Fable 5 (Claude Code).
Workload: index a 2-crate-heavy Rust workspace, run a build/test/render loop against a GUI
console, ship layout-engine + view changes, document everything.

## Bug reports (copyable)

### 1. dx_run sandbox blocks all network — cargo fails with a misleading error
```
Block: cargo test -p rui --release
Observed: "error: failed to get `tokio` as a dependency of package `selfhost-admin`"
Root cause (after probing): "Could not resolve host: index.crates.io" — no DNS/network
inside the runner. The surfaced cargo error looks like a project defect, not a sandbox
restriction.
Expected: either allow opt-in network, or surface "network unavailable in dx_run sandbox"
so the agent doesn't debug the project.
```

### 2. dx_run redirects $HOME to a synthetic dir — toolchain state vanishes
```
Observed: HOME=/Users/<user>/.cache/dx-run/bash/<hash>
Effect: cargo loses ~/.cargo (registry cache, config); git would lose ~/.gitconfig;
anything keyed off $HOME silently misbehaves. Workaround (partial): export CARGO_HOME
explicitly — still fails on write, see #3.
```

### 3. dx_run has no write access anywhere — not the workspace, not even /tmp
```
Probe: touch /tmp/dx-probe            -> "Operation not permitted"
       touch <workspace>/.dx-probe    -> denied
       touch <workspace>/target/probe -> denied
Effect: for a compiled language, "runnable documentation" is impossible — no build, no
test, no artifact. The lab document I designed around runnable blocks had to be demoted
to copy-paste snippets + one read-only status block. This is the single biggest cap on
dx's value in a Rust/Go/C++ repo.
Expected: a writable scratch dir at minimum; ideally opt-in workspace/target write.
```

### 4. Runner reports success when the command failed
```
Observed: results[].status = "ok", exit = 0, allSucceeded = true — while the block's
output was a cargo hard error (the failure was swallowed by a `| grep | head` pipeline).
Bash semantics, but the runner's "allSucceeded" label actively misleads; consider
pipefail by default or flagging blocks whose stderr contains a compiler/tool error.
```

### 5. No image/figure block
```
This project judges UI by rendered PNG frames. dx docs cannot embed or reference images
for display, so the core look-at-it loop lives outside dx entirely. An ::image src= block
(like ::code src=) would make dx the actual review surface for GUI work.
```

## What worked well

- `dx_index` scaffold → improve flow: honest, fast orientation; refuses to clobber.
- Block-addressed editing (`dx_outline` / `dx_source ids=true` / `dx_edit` one block by
  id) is excellent — precise, cheap, no diff wrangling.
- `::code src=` blocks that render the file's current text (never a stale copy) are the
  right primitive for durable indexes.
- Plain-text canonical format: other tools read the docs with zero friction.
- Findings-ledger pattern (a hand-maintained bulleted list in the lab doc) is a genuinely
  good place to persist per-session defect state.

## Ratings (this session, honest)

| Dimension | Score | Why |
|---|---|---|
| Helpfulness | 6/10 | Great as durable structured memory/index; the runnable-doc promise failed entirely for a compiled project (sandbox #1–#3) |
| Efficiency improvement | 4/10 | This session dx *cost* tokens (writing 4 docs, debugging the sandbox) and returned no execution value; the payoff is deferred to future sessions reading the index instead of re-exploring |
| General usability | 7/10 | Clean, well-designed tool API; sandbox behavior undocumented and misleading (#1, #4) |

**Work delta this session:** roughly **−5%** (doc-writing + sandbox debugging overhead vs.
just using shell + editor). **Projected future-session delta: +20–30%** — a cold agent
reading `index.dx`, `selfhost.dx`, `crates/rui/rui.dx`, and `console-lab.dx` skips nearly
all of the ~15 orientation reads this session needed. The claimed 100× speedup is not
realistic for this repo class until dx_run can execute builds (#3); the actual 100×-shaped
win this session came from parallel subagent orchestration + a fast native test/render
loop, with dx as the durable notebook beside it.

---

## Addendum — follow-up session, 2026-08-06 (later)

Bug #3 is **wrong as stated** (or the sandbox changed): dx_run DOES grant writes, via
`writes=` on the block, with one undocumented law — the grant must stay **inside the
document's own folder, relative, walking downward**. The error only says so if you probe
an absolute path; a relative miss surfaces as a bare "Operation not permitted". Recipe
that makes a full cargo build/test/render loop work in-document, discovered by probing:

- Doc lives at the repo root, block grants `writes=target`.
- `export CARGO_HOME=/Users/<user>/.cargo` + `--offline` (fixes #1/#2 for cargo).
- Absolute output dirs (`$PWD/target/frames`) — a test's cwd is its crate.
- `reads=` = comma-separated **files** only; no directories, no globs. It drives
  mechanical staleness: edit a listed file, the block re-runs on the next read/run.
- Tests that spawn processes (ssh tunnel) still fail sandbox-only; `--skip` them.

With that, `console-lab.dx` became genuinely self-verifying: 498 tests + 6 reference
PNGs re-run themselves when the view/layout files change, and the staleness mechanism
caught a real regression the same hour it was introduced (a wrap that clipped the
bank's countdown clock showed up in the auto-rerun frame). Revised ratings:

| Dimension | Score | Why |
|---|---|---|
| Helpfulness | 8/10 | The runnable-doc promise now holds for a compiled project; findings ledger + live verdicts are a real harness, not a notebook |
| Efficiency improvement | 7/10 | Orientation this session ≈ 4 reads (dx_list → outline → 2 sections) vs ~15 cold; the verify loop is one dx_run instead of shell + re-derivation |
| General usability | 7/10 | API stays excellent; the `writes=`/`reads=` laws are undocumented and cost ~6 probe cycles to reverse-engineer — document them and this is a 9 |

Remaining asks, in value order: document the sandbox laws (#1/#2/#3 addendum), allow
directory/glob `reads=`, an `::image src=` block (#5 — the PNG loop still ends outside
dx), and pipefail-or-flag on swallowed failures (#4, still true).

---

## Addendum 2 — UI-improvement session, 2026-08-07

Workload: ship three console features (Edit control, WILL RUN readback, rail restart
counts) through the dx harness end to end.

What changed since the last report:

- **`reads=` now takes folders.** `reads=crates/rui/src,crates/console/src` covers every
  file under them. That closes the biggest ask from the addendum: the lab's verdicts now
  stale mechanically on *any* view/layout edit. Verified live twice this session — both
  re-runs after code edits were triggered by the staleness engine alone (`executed: 2`,
  no force, no manual invalidation).
- **The harness caught two real defects the same hour they were written.** (1) A fifth
  lifecycle button cut every label at 560×420 — visible in the auto-regenerated narrow
  frame; the fix moved Edit onto the DEFINITION rule. (2) Filled argument fields had no
  accessible name — the audit tripped only on the new install-edit screen the session
  added. Neither would have been caught by "it compiles + tests pass" alone; both were
  caught by the doc's own run blocks. That is the runnable-doc promise actually paying.
- **`dx_run review=true` earns its place**: the stored doc is an opaque `~ dx1 <hash>`
  pointer on disk, so review is the only way to see a block's grants — and it showed the
  old blocks had no `reads=` at all, which memory had misrecorded as already wired.

Still true / still missing:

- No `::image` block: the frame PNGs are still read outside dx (Claude's Read tool on
  `target/frames/*.png`). The look-at-it half of a GUI loop lives beside the doc, not in it.
- The `.dx` file on disk is now an opaque pointer, so plain grep/cat no longer read it —
  the "any tool can read it" property from the first report is gone; dx_source is the
  only reader. Worth flagging as a regression in interop.
- Swallowed-failure risk (#4) unchanged (grep pipelines), though this session the
  failing test *did* surface because `cargo test` itself exits non-zero past the pipe.

| Dimension | Score | Why |
|---|---|---|
| Helpfulness | 9/10 | The harness found two real defects itself this session; folder `reads=` makes the verdicts trustworthy with zero upkeep |
| Efficiency improvement | 8/10 | Orientation was 3 calls (memory → outline → source); every verify cycle was one dx_run; the only overhead left is reading PNGs outside dx |
| General usability | 8/10 | Folder reads documented in the tool text now; remaining friction: opaque on-disk format, no image block, attrs editable only via full dx_write |

**Work delta this session: +25–30%** — the loop (edit → dx_run → read frames → ledger)
replaced hand-run builds, and the two caught defects would each have cost a debugging
round later. The deferred payoff claimed in the first report arrived.

---

## 2026-08-07 (later) — the gallery revision: one read is the whole verdict

The harness was revised so `console-lab.dx` alone closes the GUI loop:

- **`::image` blocks exist and work** — the previous section's "no image block" claim
  was wrong; `::image id=… src=target/frames/web/console.png` renders the frame in the
  page, and a `dx_read` of the gallery section returns every screen as pixels. The
  look-at-it half of the loop now lives *inside* the document.
- **8 MB embed limit per image**, discovered the honest way: the 2× reference frames are
  10.5 MB and render as an error paragraph. Fix worth recording: don't resample —
  `sips` cannot write its /var/folders temp inside the dx sandbox (errno 13) — render
  the frame again at scale 1.0 from the same test (`reference_frames` now writes
  `target/frames/web/*.png`). A true 1× rasterisation beats a downsampled 2× anyway.
- **The loop this enabled, measured**: edit source → `dx_run` (tests re-run because
  `reads=crates` staled them) → `dx_read` gallery → judge → ledger. Three UI passes ran
  this session (raised button faces; red-alarm floor; field_group alignment); the
  harness caught one real regression mid-pass — removing the state word's floor
  collapsed it to 0 px, failing the new rail test before any frame was drawn — and the
  narrow frame then showed the second-order defect (amber-whole cut `backups` to `b…`)
  that decided the final rule.
- **Token economics of the gallery**: a 1× frame page-image read costs roughly what the
  2× PNG cost via the Read tool, but the doc read carries tests + seven screens + ledger
  in one call, and text sections (source, outline, search hits) stay text-priced. The
  expensive thing — looking at pixels — is now spent only on request, per block.

| Dimension | Score | Why |
|---|---|---|
| Helpfulness | 9/10 | Caught a layout collapse and a priority inversion inside one session; the embedded gallery removed the last out-of-doc step |
| Efficiency improvement | 9/10 | Orientation to first meaningful edit: 4 calls. Each verify cycle: one dx_run + one section read. Frames no longer read one file at a time |
| General usability | 8/10 | `::image` under-documented (found by trying); 8 MB limit surfaced only at render; attrs still editable only via full dx_write; on-disk opaque pointer remains |


---

## 2026-08-07 (postscript) — the correction: dx as record vs dx as medium

The operator pressed on the 10-100x question and caught the flaw in how I'd framed —
and used — dx all session. Every suggestion I made (delta reads, fact layers, perceptual
verdicts) optimized *recording work* and *replaying work*. But the target is different:
**the same output for 1/100th the tokens requires the document to be where the work
happens, not where it gets written down afterward.**

### What I actually did, audited against that standard

I ran the whole UI review *in conversation context*: frame judgments, candidate defects,
the arguments for and against each fix — all of it held in my head-of-the-moment, then
distilled into the ledger at the end. The context window did the working-memory job and
the document got the minutes. Consequences:

- Every fact I established cost tokens *again* each time I circled back to it in-context
  (re-reads, re-derivations, restatements to the user).
- An interruption at minute 40 would have lost the review; resuming = re-paying most of it.
- The operator could not watch the review happen; only the summary arrived.
- A second agent could not have joined; the state was in my context, not in the world.

### The inversion that gets to 100x

Context is a cache. The document is the memory. The workflow that follows:

1. **Think by writing.** A hypothesis, a frame judgment, a dead end — written into a
   working section *the moment it forms*, in one or two lines. Reading your own note back
   later costs ~50 tokens; re-deriving it costs thousands; holding it in context costs it
   over and over as the window churns.
2. **The document carries the program counter.** A live worklist block — found / fixing /
   verified — updated in place. Session bootstrap is reading that one section, not
   re-orienting. Sessions stop being the unit of work; the task is, and it outlives any
   context window, any compaction, any crash.
3. **The conversation goes thin.** Steady state per iteration: read the worklist line,
   read the one section under edit, run the verdict block, write the result back. The
   context never needs to hold the project — only the current move. That is the flat
   cost-per-output curve: independent of project size *and* of how many sessions the
   task spans.
4. **Everyone reads the same surface.** Operator watches the review land finding by
   finding; a second agent picks up an unclaimed worklist line. The document being the
   medium is what makes the work shareable at all.

### What dx needs so this is the path of least resistance

- **Small writes for small thoughts.** dx_edit replaces a whole block; appending one
  finding means resending the ledger. Wanted: `append` to a list block, `check` on an
  item, `insert after id`. A two-line thought must cost two lines.
- **A `::now` convention** (or just a blessed section name): worklist + open questions +
  last verdict, small by construction, the designated bootstrap read. Everything else in
  the doc is archive priced at zero until asked for.
- **Scratch that promotes.** Working notes want to be cheap and disposable, then
  *promoted* into the durable ledger/docs when they harden — not copied by hand.
- **The earlier list still stands, one tier down**: text-first frame description (the
  accessibility tree answers "does it truncate?" for 2% of an image read), delta reads
  after edits, golden-frame verdicts in text, symbol-level source sections, and a facts
  layer with fingerprints. Those cut the cost of each *move*; the inversion cuts the
  number of times any move is paid for.

### The economics, said once

Today: cost-per-output ≈ (re-establish context) + (work) + (record), and the first term
grows with the project and repeats every session. Scratchbook-first: cost-per-output ≈
(marginal read) + (marginal write), flat. The 100x is not a feature — it is the sum of
never paying for the same understanding twice *within* a session (write-as-you-think),
*across* sessions (the worklist is the state), or *across agents* (the document is the
medium). dx already has the hard parts — fingerprints, staleness, live verdicts. What's
missing is mostly cheap-write ergonomics and the convention that the first tool call of
a turn is a read of the working section, and the last is a write to it.
