# Design comps — build specs

Every comp is a static HTML file in this folder, phone width unless stated,
linking `theatre.css` (the shipped stylesheet + design-kit extensions) with a
relative `<link rel="stylesheet" href="theatre.css">`. Comps use the page's own
class vocabulary — `.plate .device .title-rule .doing .deck .slider .actions
.grouprow .keypad .palette .chip .effects .scope .setmark .lamp .stateword
.section-rule .bank .alert` — and invent no new CSS unless the spec says so
(then: add it to the comp in a `<style>` block with a comment, flagged in your
report, so the director can fold it into theatre.css). No JavaScript. No
external requests of any kind. Reference comp: `phone-player.html` — read it
first; match its density, tone, and markup patterns exactly.

Doctrine, non-negotiable: true-black ground, grey hairline structure, square
corners everywhere except the platter, the sweep ring, and the reticle; amber
and red only for faults; machine text (numbers, hex, kelvin, identifiers) in
`.mono`, human words never. Healthy is quiet. Selected/pressed state via
`aria-pressed="true"`. Sentences end with periods. Device names are content,
set in the interface face.

## The house (real, from the census — use these names verbatim)

| room | device | kind | notes |
|---|---|---|---|
| Kitchen | Kitchen | speaker | Sonos One, the deck's coordinator |
| Kitchen | Move | speaker | Sonos Move, battery 100%, groups with Kitchen |
| Living Room | Couch Left | light | WiZ RGB, on, 70%, teal #2FB3A5 |
| Living Room | Couch Right | light | WiZ RGB, on, 70%, teal #2FB3A5 |
| Living Room | Living Room TV | television | Fire TV 4K, apps + keys |
| Bedroom | Bedside | light | WiZ RGB, converging to off |
| Bedroom | Bedroom TV | television | Fire TV (Vega), apps only |
| Office | Desk | light | WiZ RGB, off |
| Unplaced | Brother HL-3040CN | fixture | printer; shown, not driven |

## The palette (the only choice chips ever shown)

Colour chips, left to right, selected = teal:
CRIMSON #E03A3F · EMBER #FF7A2F · GOLD #FFB46B · MOSS #7FAE62 ·
TEAL #2FB3A5 · SKY #4F9FE0 · VIOLET #8F6FE8 · ROSE #E26FAE · `+` (add chip)

Temp chips (ink `#0a0b0d` on their own tint):
CANDLE 2200K #FF9329 · WARM 2700K #FFB46B · NEUTRAL 4000K #FFDCB8 · DAY 5500K #F5EFE6

Effects chips (small buttons, words only): FIREPLACE · OCEAN · FOREST ·
SUNSET · PARTY · FOCUS · RELAX · NIGHT — the running one is pressed.

## Steadfastness marks (server state is the truth)

- Applying: `<span class="setmark"><span class="lamp pending"></span><span class="micro">SET 0% — APPLYING</span></span>`
- Holdout (device still dissenting after patience): same with class `setmark holdout`, text `SET OFF — DEVICE SAYS ON, RETRYING`.
- An unreachable device keeps its controls at the server's set values, dimmed
  plate (`device gone`), note: `Not answering. Set state applies when it does.`

## Comps

### phone-house.html — the whole page, 390px
Masthead (HOME wordmark, DEVICE CONTROL, rule, `#214` gen in mono, ok lamp,
stateword OK). Bank plate: condition `Music in the kitchen; three lights on.`
evidence DEVICES 9 · ACTIVE 4 · UNREACHABLE 0. Then the LIGHTS deck (see
phone-lights, compact: scope row ALL pressed + count `4`, ON/OFF pair, BRIGHT
slider 70, palette row, effects row). Then rooms in census order: Kitchen
(playing deck plate, exactly as reference, plus Move follower), Living Room
(two light plates compact: title-rule, doing sentence, ON/OFF, BRIGHT slider,
swatchline; TV plate compact: `Showing Netflix.`, STOP + REMOTE disclosure
closed), Bedroom (Bedside light with applying setmark; Bedroom TV idle
`Nothing running.` with launch inline-form), Office (Desk off), and an
UNPLACED section with the printer as a quiet fixture row (name, kind, note
`Shown because it is here; nothing to drive.`). Long page is fine.

### phone-lights.html — group light control, 390px
Top: LIGHTS deck plate, full: section title-rule `LIGHTS`, scope row
`ALL (4)` pressed · `LIVING ROOM (2)` · `BEDROOM (1)` · `OFFICE (1)`;
ON / OFF pair; BRIGHT slider 70; palette (TEAL pressed); temp chips; effects
row (none pressed); caption under: `Commands land on every light in the
scope. Each bulb still answers alone below.` Then the four individual plates:
Couch Left (on, teal swatchline, 70), Couch Right (same), Bedside (setmark
applying), Desk (off, controls at set values). One plate shows the palette
expanded on a single bulb to prove single-light colour.

### phone-tv.html — televisions, 390px
Living Room TV: `Showing Netflix.`, actions STOP · REMOTE (disclosure open):
keypad grid (gap ▲ gap / ◀ OK ▶ / gap ▼ gap) + keyrow BACK · HOME · MENU,
launch inline-form (`APP` fieldlabel, input placeholder `netflix`, LAUNCH
btn). Bedroom TV: `Nothing running.`, launch form only, note: `Remote keys
need nothing on this set — DIAL only. More arrives if a driver ever can.`
(exact wording matters: no operator asks).

### phone-states.html — honesty board, 390px
Four plates + two strips, top to bottom: (1) refusal alert bar `The hub
refused: volume must be 0–100.` with dismiss ×; (2) Bedside applying
setmark; (3) Move as `device gone` — dimmed, `Not answering. Set state
applies when it does.`, volume slider still at set 25; (4) a cloud-only bulb
row: title-rule `Porch`, kind LIGHT, idle lamp, note `Cloud-only, no local
protocol. Shown so nothing is silently missing.`, no controls; (5) stale
masthead strip: warn lamp + STALE, caption `Commands wait; the page will not
pretend.`; (6) holdout setmark example on a light plate.

### phone-empty.html — nothing yet, 390px
Connecting masthead (sweep ring visible, stateword CONNECTING warn), then the
reticle centered with caption `No devices found on this network yet. The
house is being swept; anything that answers appears here by itself.`

### desktop-house.html — the laptop view, 1280px
Same content as phone-house, but the rooms grid shows its columns (three to
four across), bank evidence inline beside the sentence, LIGHTS deck as a
wide strip under the bank with palette, effects and scope in one compact strip (a second wrapped line is fine). Prove the
grid: rooms side by side, `align-items:start` visible (rooms of different
heights top-aligned).

### color-system.html — the choices, legend board, 720px
A plate per row: (1) the eight colour chips large (with name + hex in mono
micro under each); (2) temp chips with kelvin; (3) effects with a five-word
description each in muted caption; (4) the three setmark states with their
exact wording; (5) lamp legend: ok / warn / bad / idle / pending with one
line each on when they appear. This board is the design's legend, not a page.

## The material pass (2026-08-19, second round) — black glass and phosphor

Three materials, already in theatre.css; comps opt in with classes:

- **`.readout`** on machine numbers ONLY (slider values, clocks, kelvin, hex,
  the generation counter, bank evidence numbers): phosphor glow. Prose never
  glows.
- **`.lit` + inline `--glow:#RRGGBB`** on a light plate whose bulb is ON: the
  plate emits its bulb's colour from the top edge, faintly. The LIGHTS deck
  plate is lit with the scope's colour. Off/converging bulbs are not lit.
- **The deck's top row**: `<div class="toprow">` wraps the `.nowplaying` block
  and a `.vus` pair:
  `<div class="vus"><span class="vu"><span class="needle" style="--vu:-4deg"></span><span class="vu-tag">L</span></span><span class="vu"><span class="needle" style="--vu:16deg"></span><span class="vu-tag">R</span></span></div>`
  Playing: needles angled as above. Paused/idle: omit the style so they rest.
