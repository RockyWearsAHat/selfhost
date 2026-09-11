# Incident: ai.rockywearsahat.com multi-hour outage — checkout divergence

2026-09-08. Diagnosis only; no further live changes made as part of this writeup.

## Root cause

selfhost's own service registry has an entry named `ai-studio` (visible via
`services_list`/`services_show`) whose spec says: cwd `checkouts/ai-studio`
(→ `C:\Users\Alex\Self-Host\checkouts\ai-studio`), program the system
`python.exe`, port 8300, git remote `git@github.com:RockyWearsAHat/ai-studio.git`
(SSH), `autoUpdate: true`. Its live status is **`gave-up`, exited code 1** — it
has never successfully served traffic in its current form.

The site that is actually live at `ai.rockywearsahat.com` is bound by a plain
Windows **Scheduled Task** named `ai-studio` (`State: Running`), created entirely
outside selfhost, whose action is
`powershell -File D:\SARA\ai-studio-wrapper.ps1`. That wrapper loops forever
running `D:\SARA\ai-studio\gateway\venv\Scripts\python.exe -m uvicorn
gateway.app:app --host 127.0.0.1 --port 8300`. `D:\SARA\ai-studio`'s HEAD is
still `0bf22b5`, the repo's very first commit — nobody has run `git pull`
there since it was created; the health-check fix landed there only by hand
(`git status` shows `gateway/app.py` modified, uncommitted — the tar+scp
stopgap).

`C:\Users\Alex\Self-Host\checkouts\ai-studio` (the path selfhost's registry
*and* all deploy docs describe) is 3 commits ahead (`f1d2941`), correctly
tracking `origin/main`, and is **not what's running**.

A third path, `D:\AIStudio\...`, appears in
`~/Desktop/AI/deploy/selfhost-service.json` and nowhere else — it does not
exist on the box at all. That file is a stale draft from an earlier,
apparently abandoned plan to register the service under yet another layout;
it was never reconciled with the registry entry that actually got created
(which uses `checkouts/ai-studio`, not `D:\AIStudio`).

**Why this happened, mechanically:** the box hosts two independent process
supervisors that both believe they own "ai-studio" — selfhost's own service
manager, and a hand-made Scheduled Task that predates it (part of a separate,
larger "SARA" agent-factory project living under `D:\SARA`, which also owns
`sara-engine`, `sara-gateway`, `sara-myeditor`, `factory-pull`, `dx-build` —
all in selfhost's registry, all pointed at `D:/SARA/...` paths). When
ai-studio was later "adopted" into selfhost's registry, it was pointed at the
`checkouts/ai-studio` convention every other service uses, but nobody
retired the original Scheduled Task, and nobody noticed the two never
collided on port 8300 because selfhost's copy has *never once started
successfully* (SSH deploy key on the box is unauthorized — "Repository not
found" — so even a fresh checkout there can't pull; the global
`credential.helper` also points at a deleted temp file, so HTTPS fallback
fails too: `git ls-remote` from `checkouts/ai-studio` fails with "could not
read Username for 'https://github.com'"). selfhost's own dashboard has
therefore shown this service as **broken** for a long time, which is
technically true of *its own* checkout — while the box has been quietly
served the whole time by a checkout selfhost has no record of at all. Log
lines like "branch is reachable again" were network-reachability checks,
not proof the configured auth could actually pull.

## Same pattern elsewhere on the box?

Yes, structurally. `sara-gateway` (`services_show`) is also `gave-up`,
exited code 1, cwd `D:/SARA/Desktop/factory/gateway` — same shape (registry
believes it owns a path/process, current status says it doesn't actually
run), one level removed from the ai-studio situation, in the *same* SARA
tree. `sara-engine` is in `backoff` with 87 restarts. Both were not
diagnosed further here (out of scope: "no further live fixes"), but they are
worth the same drift check before anyone assumes selfhost's dashboard state
reflects what's live for the SARA services either. `forge`, `mayr`,
`reports`, `sara-myeditor`, `factory-pull`, `dx-build` are all reporting
`running` with a real `pid` — those are lower-risk (a live PID is much
stronger evidence than a git remote URL), but none of them have been
cross-checked against an independent Scheduled-Task/service inventory the
way ai-studio was here. Recommend the same spot-check pass before trusting
selfhost's registry as ground truth for any of them.

## Is the SSH-tunnel requirement discoverable enough?

CLAUDE.md references `docs/SECURITY.md` once, generically ("Before writing
or shipping such code you MUST consult... the guidebook"), framed entirely
around *writing new networked code* — not about *how to reach an existing
box to deploy to it*. Nothing in CLAUDE.md, in the AI-studio repo, or in
`~/Desktop/AI/deploy/*.md` says "SSH to any Self-Host box always goes
through the 8444 Secure-VPN tunnel, never port 22 directly." The actual rule
(SSH-02) is on line 259 of a ~1100-line document, correct and detailed once
found, but an agent working a deploy task in a *different* repo
(ai-studio) has no reason to open `Self-Host/docs/SECURITY.md` at all unless
it already suspects a firewall rule exists. This is exactly what happened:
multiple agents burned cycles on direct `ssh -p 22 ...@192.168.1.8` before
anyone thought to check.

**Recommendation:** add one line to CLAUDE.md's existing security paragraph,
not a new section:

> Remote SSH to any Self-Host-managed box is never direct — it always goes
> through the Secure-VPN tunnel on port 8444 → loopback 22 (see
> `docs/SECURITY.md` §SSH-02). Direct `ssh host:22` will time out by design;
> that is not a bug to fix.

That sentence needs to be true wherever an agent starts a deploy task, which
argues for it living in `~/Desktop/AI/ai-studio/README.md` and
`~/Desktop/AI/deploy/README.md` too, not only in Self-Host's own CLAUDE.md —
an agent working the ai-studio repo may never open this repo's CLAUDE.md at
all.

## Prioritized recommendations

1. **Retire or merge `D:\SARA\ai-studio`.** It is the one actually live but
   cannot be updated by git (stale HEAD, uncommitted manual patch). Either
   point the Scheduled Task at `checkouts/ai-studio` and delete the
   Scheduled Task once selfhost's own supervisor can run it end to end, or
   formally adopt `D:\SARA\ai-studio` as the canonical path and update
   selfhost's registry + all docs to say so. Whichever direction is chosen,
   there must be exactly one filesystem path per service afterward — right
   now there are three candidate paths in play (`checkouts/ai-studio`,
   `D:\SARA\ai-studio`, `D:\AIStudio\...`) and only one of them is real.
2. **Fix git auth on the box before relying on `autoUpdate: true` for
   anything.** Both the SSH deploy key and the HTTPS credential helper are
   broken; `autoUpdate` silently no-ops instead of failing loudly, which is
   how this went unnoticed. Worth making a failed auto-pull surface as a
   service-health condition (selfhost already tracks `gave-up`/`backoff`;
   a stalled `git.enabled` repo that hasn't advanced HEAD in N intervals
   should get the same visibility).
3. **Add drift detection to `services_show`/`services_list`.** For any
   service with a `git` block, compare the registry's configured
   path+remote+HEAD against what a live `netstat`/`Get-NetTCPConnection` on
   the configured port shows is actually bound, and flag a mismatch. This
   is the concrete fix for "selfhost's own tooling couldn't have caught the
   divergence" — right now `services_show` only reports its own belief, with
   no cross-check against the OS-level Scheduled Task layer, which is where
   the truth actually lived.
4. **Delete or correct the stale docs.** `~/Desktop/AI/deploy/selfhost-service.json`,
   `README.md`, `DEPLOYMENT_STATUS.md` all describe a `D:\AIStudio\...` layout
   that was never provisioned and a webhook endpoint
   (`/api/webhook/git`) that returns EOF because it doesn't exist in
   selfhost. Either implement that endpoint or delete these docs — as
   written they actively mislead the next agent into debugging a path and a
   route that were never real.
5. **Add the one-line SSH-tunnel pointer to CLAUDE.md and to the ai-studio
   repo's own docs**, per above — cheap, and would have saved most of this
   incident's wasted cycles by itself.
