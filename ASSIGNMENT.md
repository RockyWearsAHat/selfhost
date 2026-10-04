# Self-Host Insight: see the machine, fix it before it breaks
Version 3 · Last amended 2026-10-04

> **This assignment is the source of truth for this project.** Read it in full before any work.
> Where code, docs or notes conflict with it, the assignment wins: bring the code into line.
> If a request or your own judgment conflicts with it, stop, tell the user which section
> conflicts (quote it) and ask whether to amend it. Never edit this file or work around it
> without the user's approval.

## 1. Overview
Self-Host runs on ALEX-DESKTOP (Windows, 192.168.1.8), the owner's everyday PC and the **only DNS server for the whole house**. House internet drops intermittently and all anyone sees is "DNS failed", never why. Make Self-Host tell the owner and any controlling agent, continuously and truthfully, what the machine and every service is doing, early enough to fix problems before anyone feels them, while costing so little that the PC's own load never takes it down. End state: the outage cause is found and fixed, both consoles show machine health clearly, and an agent over MCP can prove everything is running correctly.

## 2. The Assignment

**2.1 Measure first.** Before changing anything, record a baseline on ALEX-DESKTOP for every selfhost process (CPU, resident memory, threads, handles, wakeups/s, disk I/O; idle and under load) and DNS latency and failure rate from a LAN client. Every later claim is compared against it.

**2.2 Maximal efficiency is a goal, not a ceiling.** Drive every selfhost process's footprint as close to zero as possible. No change may raise it above baseline without the owner's sign-off. Monitoring samples cheaply, stores compactly and never polls in a hot loop. Idle means idle.

**2.3 DNS that always resolves.** The LAN resolver (`selfhost lan-dns`, `crates/net/dns`) forwards every query uncached, unbounded, with a 5 s timeout and no failure counting. Give it a TTL-respecting cache, bounded in-flight work, two or more upstreams with fast failover, and near-zero cost, so it stays correct while the PC games. The router's public secondary DNS is a safety net that should never be used. Count and timestamp every query outcome (answered, cached, upstream slow, upstream failed, dropped) so a failure always shows its cause. Keep the `lan-dns --lan-ip`/`--bind` contract byte-stable.

**2.4 Full machine insight, recorded.** Keep a compact on-box history of CPU, memory, disk space and I/O, network throughput and errors, top processes per resource, per-upstream DNS latency and failures, service flaps, and the Windows events that matter (crashes, resource exhaustion, adapter resets). Derive trend warnings (memory climbing, disk filling, DNS latency rising, a service flapping) before they become failures. Warnings are **logged only** to one event timeline: no notifications and no new automatic actions.

**2.5 Native console first, web at parity.** The native RUI console (`crates/ui/console`) is the owner's main access point. Give it a Health overview answering "is anything wrong, what, since when, why" at a glance, with live machine charts, the DNS panel, the event timeline and drill-down. Every on-screen item has a stable visible name so the owner can point at it in a screenshot. Bring the web console (`sites/console`) to the same screens. Both clean: consistent layout, no dead controls, no raw dumps where a sentence serves.

**2.6 Agents see what the owner sees.** Everything a console shows is readable over MCP: health, metrics history, DNS stats, timeline, audit, processes, plus one "what is wrong right now" call returning current problems with evidence. Fix the `selfhost mcp --host admin.rockywearsahat.com` startup hang (no reply to `initialize`; hung instances lived for days). The MCP parity test covers the new routes.

**2.7 Clean, proven code.** Build green, all tests pass, helpers lint clean on touched code. Every claim is a dx gate with a recorded verdict in `index.dx` or a lab. Replaced code is deleted in the same change (rule 7). Kill the orphaned dx-run relays and hung MCP processes on the Mac, and stop tests leaking them.

**2.8 Milestones.** (M1) build green and baseline recorded; (M2) DNS hardened and telemetered, outage cause identified from real data; (M3) metrics, timeline and warnings over the admin API; (M4) MCP tools and hang fix; (M5) native Health screens; (M6) web parity; (M7) Windows proof and deploy.

## 3. Constraints
- `CLAUDE.md`, `index.dx` §3 rules 1–10, and `docs/SECURITY.md` before networked code: loopback binds, no new public surface.
- Work through dx (`dx_search`/`dx_source` to read, `dx_run` gates to prove).
- Rust, no heavyweight new dependencies; native UI in RUI.
- Branch `insight/monitor-ui-dns`, off `redesign/round-2`.
- Rule 10: runs healthy on ALEX-DESKTOP from a side folder before `main`. Only the lead agent authorizes the merge (= deploy); worker agents never deploy or touch the live install.
- Numbers come from run output, never agent prose; report MET/NOT MET with evidence location.
- **The house internet must never drop, not even for a second** (owner, 2026-10-03). DNS outages take down every device, the TV and the agents themselves. During development, nothing on ALEX-DESKTOP is restarted, stopped or rebound; side-folder runs never bind :53. Any change that touches the live DNS path ships only through a zero-drop handoff: the new resolver binds and proves it answers real queries before the old one exits, with automatic rollback if the proof fails. One exception, approved by the owner: the single first move of :53 from the old daemon to `selfhost lan-dns`, whose socket Windows will not let a second server share (measured cost: one query, about 210 ms). Old code and processes are deleted only after the replacement is proven live.

## 4. Non-Goals
- No paging, email or push alerts; no automatic remediation beyond what exists.
- No outside monitoring stack (Prometheus, Grafana, SaaS) or cloud dependency.
- No identity/VPN/Grant rework; no features outside monitoring, DNS, UI, MCP.
- No "fixing" the outage by permanently pointing the house at public DNS.
- No cosmetic screens that add no insight.

## 5. Deliverables
Hardened, telemetered LAN DNS; on-box metrics, history and timeline with admin API routes; MCP tools and the "what's wrong now" call; native and web Health screens; a dx lab with baseline and after footprint and the outage root cause with evidence; the branch merged to `main` after the Windows proof.

## 6. Grading
1. Can the owner see why a past DNS failure happened (upstream, latency, machine load then), not just that it did?
2. Is every selfhost process's measured footprint at or below baseline, and DNS p99 stable under heavy PC load, per recorded runs?
3. Can an MCP-only agent state the machine's condition and every current problem with evidence, matching the console?
4. Does the native Health overview make a developing problem obvious at a glance, with web at parity?
5. Do build, tests, lint, MCP parity and the Windows proof pass as recorded dx verdicts?
6. Was the outage cause identified from data and fixed, not assumed?

Zero marks: synthetic or hardcoded chart data, gates that check nothing, monitoring costing more than it saves, a screen with no MCP equivalent.

## 7. Done State
The branch is merged and live on ALEX-DESKTOP, `index.dx` gates are green, and the lab shows before and after footprint, DNS numbers and the outage cause marked MET. The native console and MCP show the same health, history and timeline.

**Central question:** Can the owner and any agent see, before anyone feels it, exactly what is going wrong on this machine and why, while Self-Host itself costs almost nothing to run?

## Amendments
- v1 (2026-10-03): initial assignment.
- v2 (2026-10-03): owner added the never-drop-the-internet constraint (§3).
- v3 (2026-10-04): owner approved a one-time exception in §3 for the first move of :53 off the old daemon.
