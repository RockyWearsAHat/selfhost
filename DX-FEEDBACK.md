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
