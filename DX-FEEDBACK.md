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
