"use strict";
/*
 * HOME — the house panel.
 *
 * One page showing every device the hub can see, grouped by the room it stands
 * in, and driving each one by the capabilities it advertises rather than by the
 * brand on its case. A device that says "transport" gets transport controls
 * whether it is a Sonos, a soundbar or something nobody has written a driver
 * for yet; a device that advertises nothing is shown and not driven. That rule
 * is the whole architecture of this file, and it is why there is no mention of
 * a vendor anywhere below it.
 *
 * Everything on this page is hostile text. A device's name, its note, and the
 * title of whatever it is playing were written by a stranger's firmware and
 * arrive over the network unexamined, so every one of them reaches the DOM
 * through `textContent` and this file contains no `innerHTML` at all. The
 * page's CSP is `default-src 'none'`, which means there is no route from a
 * device name to a script even if one of these rules were broken.
 *
 * Layout of this file:
 *   1. Pure functions: durations and clocks, the sentence a device's state
 *      deserves, the sorting of devices into rooms, and the arithmetic that
 *      stops a poll from stealing the slider out of somebody's hand. No DOM,
 *      no fetch, no clock of their own — every one of them is told the time.
 *   2. Self-tests: `node app.js` runs them and exits non-zero on failure.
 *   3. The application: state, polling, rendering. Browser only.
 */

/* ── 1. Pure logic ───────────────────────────────────────────────────── */

/** Whether a value is a number worth showing.
 *
 *  The wire is explicit that a reading a device does not have is `null` —
 *  `brightness` on a bulb that is off, `battery_pct` on a mains speaker — and a
 *  dashboard that renders those as `0` states something false about the device.
 *  Everything numeric on this page goes through here first, and `null` back
 *  means "say nothing", never "say zero". */
function finiteNumber(value) {
  if (typeof value !== "number" && typeof value !== "string") return null;
  if (typeof value === "string" && value.trim() === "") return null;
  const n = Number(value);
  return Number.isFinite(n) ? n : null;
}

/** Seconds in the largest two units that say something: "6d 4h", never
 *  "534240s". */
function duration(seconds) {
  const n = Math.max(0, Math.floor(Number(seconds) || 0));
  const MINUTE = 60, HOUR = 3600, DAY = 86400;
  if (n < MINUTE) return `${n}s`;
  if (n < HOUR) return `${Math.floor(n / MINUTE)}m ${n % MINUTE}s`;
  if (n < DAY) return `${Math.floor(n / HOUR)}h ${Math.floor((n % HOUR) / MINUTE)}m`;
  return `${Math.floor(n / DAY)}d ${Math.floor((n % DAY) / HOUR)}h`;
}

/** A position in a track, as a clock rather than as a count of seconds.
 *
 *  Deliberately not `duration()`. "3m 12s" is the right shape for an uptime,
 *  which is read once; a position beside a progress bar is read against the
 *  total next to it, and two clocks subtract at a glance where two prose
 *  durations do not. The hour only appears once there is one, because a
 *  three-minute song reading "0:03:12" is three characters of nothing. */
function clockText(seconds) {
  const n = finiteNumber(seconds);
  if (n === null || n < 0) return "—";
  const whole = Math.floor(n);
  const secs = whole % 60;
  const mins = Math.floor(whole / 60) % 60;
  const hours = Math.floor(whole / 3600);
  const pad = (v) => String(v).padStart(2, "0");
  return hours > 0 ? `${hours}:${pad(mins)}:${pad(secs)}` : `${mins}:${pad(secs)}`;
}

/** A number held between two bounds, as an integer. */
function clampInt(value, low, high) {
  const n = finiteNumber(value);
  if (n === null) return low;
  return Math.min(high, Math.max(low, Math.round(n)));
}

/** The masthead's word for the link.
 *
 *  A fresh loss wears no age, because a page that says "unreachable · 1s" the
 *  instant a poll is late is a page that cries wolf on every hiccup; past a
 *  minute and a half the age is the reading that matters, since "unreachable"
 *  alone cannot tell an outage from a page left open overnight. */
function linkWord(link, sinceSecs) {
  if (link === "connecting") return "CONNECTING";
  if (link === "connected") return "CONNECTED";
  return sinceSecs > 90 ? `UNREACHABLE · ${duration(sinceSecs)}` : "UNREACHABLE";
}

/** Whether a device id may be put in a request path.
 *
 *  Ids come from the hub and look like `sonos:rincon_7828…` — a colon is
 *  ordinary here, so the grammar cannot be the console's `[A-Za-z0-9._-]`. What
 *  is refused instead is what could change the *shape* of a request: an empty
 *  id, an absurd one, and any control character, which a header-splitting
 *  attempt would need. Everything else is encoded rather than judged, by
 *  `commandPath`, which is the only place an id is ever pasted into a URL. */
function usableId(id) {
  if (typeof id !== "string") return false;
  if (id.length === 0 || id.length > 200) return false;
  // Tested by code point rather than by a character class, because a control
  // character written literally into a regular expression is invisible in
  // every editor that will ever open this file — including the one that would
  // quietly delete it.
  for (let i = 0; i < id.length; i += 1) {
    const code = id.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) return false;
  }
  return true;
}

/** The one place a device id becomes a URL.
 *
 *  `encodeURIComponent` and not template interpolation: an id containing a
 *  slash would otherwise address a different route entirely, and an id
 *  containing `?` would turn the rest of it into a query string. One encoder,
 *  called once, is the only shape of this that cannot drift. */
function commandPath(id) {
  return `/api/home/devices/${encodeURIComponent(id)}/command`;
}

/** Whether a device advertises a capability. Everything this page draws is
 *  decided by this function and never by `kind` or `driver`. */
function has(device, capability) {
  return !!device && Array.isArray(device.capabilities) && device.capabilities.indexOf(capability) !== -1;
}

/** What kind of thing this is, as the small-capital label beside its name.
 *  An unfamiliar kind is shown as the hub spelled it rather than as "OTHER":
 *  a newer hub knowing a word this build does not is not an error. */
function kindWord(kind) {
  const word = typeof kind === "string" ? kind.trim() : "";
  return word ? word.toUpperCase() : "DEVICE";
}

/** Whether a device is making sound right now. */
function isPlaying(device) {
  return !!device && device.reachable === true
    && !!device.state && device.state.transport === "playing";
}

/** Whether a device is switched on right now. */
function isPoweredOn(device) {
  return !!device && device.reachable === true
    && !!device.state && device.state.power === "on";
}

/** The lamp and the word for one device.
 *
 *  Almost everything here is `idle`, and that is the design rather than an
 *  oversight. The lamp's *fill* is the device's own switch — a speaker that is
 *  playing and a lamp that is lit fill their slot, and everything merely
 *  waiting leaves it an empty outline — so the state is said twice, by a value
 *  and by a shape, and a reader who receives no colour still sees which half of
 *  the house is doing something.
 *
 *  Nothing here returns `warn` or `bad`, deliberately. Amber and red are the
 *  only saturated colours this page can show and neither appears without a
 *  cause; a television being off is not a cause, and a wall of amber for
 *  devices behaving exactly as asked is what makes a genuine alarm invisible.
 *  An unreachable device is `idle` for the same reason it is not red: it is
 *  usually asleep, and the plate says so in words underneath. */
function deviceStatus(device) {
  if (!device || device.reachable !== true) return { status: "idle", word: "UNREACHABLE" };
  const s = device.state || {};
  if (!Array.isArray(device.capabilities) || device.capabilities.length === 0) {
    return { status: "idle", word: "PRESENT" };
  }
  if (has(device, "transport")) {
    switch (s.transport) {
      case "playing": return { status: "ok", word: s.muted ? "PLAYING · MUTED" : "PLAYING" };
      case "paused": return { status: "idle", word: "PAUSED" };
      case "buffering": return { status: "idle", word: "BUFFERING" };
      case "stopped": return { status: "idle", word: "STOPPED" };
      default: return { status: "idle", word: "IDLE" };
    }
  }
  if (has(device, "power")) {
    if (s.power === "on") return { status: "ok", word: "ON" };
    if (s.power === "off") return { status: "idle", word: "OFF" };
    return { status: "idle", word: "UNKNOWN" };
  }
  return { status: "idle", word: "PRESENT" };
}

/** What this device is doing, in one sentence.
 *
 *  One sentence and not a row of tags, because the question somebody walks up
 *  to this page with is "what is the kitchen doing" and the answer to that is
 *  prose. The numbers are all repeated as dials underneath for anybody reading
 *  properly; this line is for the glance. */
/** Whether to offer pairing: an application surface with no keys.
 *
 *  A Fire TV that nobody has paired advertises `apps` and `power` — it can be
 *  turned on and told to launch things — and gains `keys` and `transport` only
 *  once somebody has read a PIN off its own screen. So "can launch, cannot
 *  press" is exactly the shape of an unpaired television, and it is the only
 *  shape worth putting a PAIR button on: offering it to a paired set would put
 *  a PIN on a screen for nothing, and offering it to a speaker would be
 *  nonsense. A device that drives nothing at all is not offered it either. */
function offersPairing(device) {
  return has(device, "apps") && !has(device, "keys");
}

function deviceSentence(device) {
  if (!device || device.reachable !== true) return "The hub cannot reach it.";
  const s = device.state || {};
  if (!Array.isArray(device.capabilities) || device.capabilities.length === 0) {
    return "Reporting only — there is nothing here to drive.";
  }
  if (has(device, "transport")) {
    const volume = finiteNumber(s.volume);
    const at = volume === null ? "" : ` at volume ${Math.round(volume)}`;
    switch (s.transport) {
      case "playing":
        // Muted outranks the number: a speaker playing silently at volume 40
        // is a question, and "at volume 40" is the wrong half of the answer.
        if (s.muted) return "Playing, muted.";
        return s.source ? `Playing ${String(s.source)}${at}.` : `Playing${at}.`;
      case "paused": return "Paused.";
      case "buffering": return "Buffering.";
      case "stopped": return "Stopped.";
      default: return s.muted ? "Idle, muted." : "Idle.";
    }
  }
  if (has(device, "power")) {
    if (s.power === "off") return "Off.";
    if (s.power !== "on") return "It has not said whether it is on.";
    const settings = [];
    const brightness = finiteNumber(s.brightness);
    if (brightness !== null) settings.push(`${Math.round(brightness)}% brightness`);
    const temp = finiteNumber(s.color_temp);
    if (temp !== null) settings.push(`${Math.round(temp)}K`);
    let sentence = "On";
    if (settings.length > 0) sentence += ` at ${settings.join(" and ")}`;
    if (s.app) sentence += `, showing ${String(s.app)}`;
    return `${sentence}.`;
  }
  return "Nothing to report.";
}

/** Why an unreachable device is unreachable, in the hub's own words.
 *
 *  The note is the only thing on a dimmed plate worth reading, so it is shown
 *  as a sentence rather than as a bare fragment, and a hub that offered no
 *  reason is made to say so — an empty line under "cannot reach it" reads as a
 *  page that failed to load the reason rather than as one that was never
 *  given. Terminal punctuation the note already carries is left alone. */
function noteSentence(device) {
  if (!device || device.reachable === true) return "";
  const note = typeof device.note === "string" ? device.note.trim() : "";
  if (!note) return "The hub gave no reason.";
  return /[.!?]$/.test(note) ? note : `${note}.`;
}

/** A list of names as English rather than as an array: "a, b and c". */
function listWords(items) {
  if (items.length === 0) return "";
  if (items.length === 1) return items[0];
  return `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

/** Whether this device is part of a group of more than one. */
function isGrouped(device) {
  const group = device && device.state && Array.isArray(device.state.group) ? device.state.group : [];
  return group.filter((id) => typeof id === "string" && id.length > 0).length > 1;
}

/** Which group a speaker is in, by the *names* of its members.
 *
 *  Named and not counted: "grouped with 2 others" makes somebody open every
 *  other plate to find out which two. A member whose id this page has never
 *  seen is shown as its id — inventing a name for it would be worse than the
 *  ugly truth, and an id here means the group survived a device leaving the
 *  hub's inventory, which is worth seeing. */
function groupSentence(device, names) {
  if (!isGrouped(device)) return "";
  const s = device.state || {};
  const group = s.group.filter((id) => typeof id === "string" && id.length > 0);
  const nameOf = (id) => (names && names.get(id)) || id;
  if (!s.coordinator || s.coordinator === device.id) {
    const others = group.filter((id) => id !== device.id).map(nameOf);
    return others.length === 0 ? "" : `Leading ${listWords(others)}.`;
  }
  return `Following ${nameOf(s.coordinator)}.`;
}

/** The speakers this one could be told to join.
 *
 *  Filtered by the `group` capability rather than by `kind`, so a device that
 *  can be grouped and is not called a speaker is offered, and a speaker whose
 *  driver cannot group is not offered and then refused. A device already in
 *  this group is left out because joining it is a no-op the hub would have to
 *  answer with an error. */
function joinCandidates(devices, device) {
  const mine = new Set(device && device.state && Array.isArray(device.state.group) ? device.state.group : []);
  return devices
    .filter((other) => other.id !== device.id && other.reachable === true
      && has(other, "group") && !mine.has(other.id))
    .map((other) => ({ id: other.id, name: String(other.name || other.id) }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/** Devices sorted into the rooms they stand in.
 *
 *  A room is a fact the hub reports per device, not a list it serves, so the
 *  grouping happens here. Two decisions worth stating. A device with no room is
 *  not dropped and not silently filed under the first room — it goes to
 *  UNPLACED, at the end, because a device nobody has placed is a configuration
 *  job and belongs where jobs go. And the ordering is by code point rather than
 *  by locale: this page is read on a phone, a laptop and a wall tablet that may
 *  disagree about collation, and a dashboard whose rooms are in a different
 *  order on each of them is one you have to read rather than recognise. */
function roomsOf(devices) {
  const byName = (a, b) => {
    const an = String(a.name || a.id), bn = String(b.name || b.id);
    if (an !== bn) return an < bn ? -1 : 1;
    return String(a.id) < String(b.id) ? -1 : 1;
  };
  const groups = new Map();
  for (const device of devices) {
    const room = typeof device.room === "string" ? device.room.trim() : "";
    let group = groups.get(room);
    if (!group) {
      group = { key: room, label: room ? room.toUpperCase() : "UNPLACED", devices: [] };
      groups.set(room, group);
    }
    group.devices.push(device);
  }
  const placed = [];
  for (const group of groups.values()) if (group.key !== "") placed.push(group);
  placed.sort((a, b) => (a.label < b.label ? -1 : a.label > b.label ? 1 : 0));
  const unplaced = groups.get("");
  if (unplaced) placed.push(unplaced);
  for (const group of placed) group.devices.sort(byName);
  return placed;
}

/** Every room a device on the page currently stands in, sorted and without
 *  repeats — offered as suggestions on the room field so that labelling a
 *  second lamp into "Kitchen" is a pick, not a retype liable to land as
 *  "kitchen" and split the room in two on the page. Code-point order, for the
 *  same reason `roomsOf` sorts that way. */
function knownRooms(devices) {
  const seen = new Set();
  for (const device of devices) {
    const room = typeof device.room === "string" ? device.room.trim() : "";
    if (room) seen.add(room);
  }
  return Array.from(seen).sort();
}

/** What the whole house amounts to, in one line.
 *
 *  The order of the tests is the priority order of the reader's attention: the
 *  link outranks everything, because a page that cannot reach the hub knows
 *  nothing at all and must not report a stale house as a live one; a device
 *  that is not answering outranks whatever the rest are doing, and is named
 *  when there is exactly one, because "1 device is not answering" sends
 *  somebody hunting for which. */
function condition(link, devices) {
  if (link === "connecting") return "Reaching the house";
  if (link === "lost") return "The house is not answering";
  const total = devices.length;
  if (total === 0) return "No devices found";
  const gone = devices.filter((device) => device.reachable !== true);
  if (gone.length === 1) return `${String(gone[0].name || gone[0].id)} is not answering`;
  if (gone.length > 1) return `${gone.length} devices are not answering`;
  const playing = devices.filter(isPlaying).length;
  const on = devices.filter(isPoweredOn).length;
  if (playing === 0 && on === 0) return "The house is quiet";
  const parts = [];
  if (playing > 0) parts.push(`${playing} playing`);
  if (on > 0) parts.push(`${on} on`);
  return parts.join(" and ");
}

/** How far through a track a speaker is, as 0…1, or null when the hub has not
 *  said. A bar drawn at zero for an unknown position is a bar claiming the
 *  track just started. */
function progressFraction(position, durationSecs) {
  const total = finiteNumber(durationSecs);
  const at = finiteNumber(position);
  if (total === null || total <= 0 || at === null) return null;
  return Math.min(1, Math.max(0, at / total));
}

/** A percentage, or an em dash when there is no number to show. */
function percentText(value) {
  const n = finiteNumber(value);
  return n === null ? "—" : `${Math.round(n)}%`;
}

/** A battery as one dial reading, or "" when the device has no battery.
 *  Charging is stated because a battery at 9% on the charger and one at 9% in
 *  a cupboard are different problems, and only one of them is yours. */
function batteryText(state) {
  const pct = finiteNumber(state && state.battery_pct);
  if (pct === null) return "";
  const shown = `${Math.round(pct)}%`;
  return state && state.battery_charging ? `${shown} CHG` : shown;
}

/** Whether a battery is the one thing on this plate that is actually wrong.
 *
 *  This colours the battery dial and nothing else. Escalating the device's own
 *  lamp was tried and rejected: a speaker playing perfectly on a low battery
 *  would then wear the same amber as a device in trouble, and the reader would
 *  learn that amber on this page means "look closer at something, somewhere". */
function batteryLow(state) {
  const pct = finiteNumber(state && state.battery_pct);
  return pct !== null && pct < 15 && !(state && state.battery_charging);
}

/** A colour the hub reported, normalised, or null if it is not one.
 *  Also the validator for what may be typed into the colour field — one
 *  function for both, so a value this page will draw is exactly the set of
 *  values it will send. */
function usableHex(text) {
  const cleaned = String(text === null || text === undefined ? "" : text).trim().replace(/^#/, "").toUpperCase();
  return /^[0-9A-F]{6}$/.test(cleaned) ? cleaned : null;
}

/** Which way an arrow key means to move a slider, as a multiple of the step.
 *  Returns null for every key that is not one, so the handler can get out of
 *  the way of Tab, Home, End and everything else the platform owns. */
function arrowStep(key) {
  const steps = { ArrowLeft: -1, ArrowDown: -1, ArrowRight: 1, ArrowUp: 1, PageDown: -2, PageUp: 2 };
  return Object.prototype.hasOwnProperty.call(steps, key) ? steps[key] : null;
}

/**
 * WHICH NUMBER A SLIDER MUST SHOW THIS FRAME — the single most common bug in a
 * dashboard like this one, solved here rather than in the render function.
 *
 * The bug has two halves and they need two different answers.
 *
 * The first: a poll lands while a hand is on the control. The page redraws, the
 * render writes `input.value` from what the hub last said, and the thumb jumps
 * out from under the finger — every second, for as long as the drag lasts. So
 * while `hold.holding` is set, the person owns the control outright and the
 * reported number is not written at all. That is the easy half.
 *
 * The second is the half that gets missed. The finger comes up, the command is
 * sent, and a poll answers *before the device has acted on it* — carrying the
 * old volume, because the speaker has not ramped yet. The thumb snaps back to
 * where it was, sits there for a poll or two, then jumps forward to where the
 * person put it. It looks exactly like the control fighting them, and it is
 * worse than the first bug because it happens after they have let go and are no
 * longer explaining it to themselves as lag. So a released control keeps an
 * *echo window*: the chosen value stands until the hub reports that value back
 * — which is the acknowledgement, and closes the window immediately — or until
 * the deadline passes, which is what stops a command the hub silently dropped
 * from freezing the reading for ever.
 *
 * `keep` is false the moment the hold has done its work, and the caller forgets
 * it then, so a device nobody is touching costs no bookkeeping at all.
 *
 * The clock is a parameter and never `Date.now()` inside, so the deadline is
 * testable without waiting four seconds.
 */
function sliderValue(reported, hold, now) {
  if (!hold) return { value: reported, keep: false };
  if (hold.holding) return { value: hold.value, keep: true };
  if (now >= hold.until) return { value: reported, keep: false };
  if (reported === hold.value) return { value: reported, keep: false };
  return { value: hold.value, keep: true };
}

/** What a refused command says on screen.
 *
 *  The hub answers a refusal with a sentence, and that sentence is shown
 *  verbatim: it is the only party that knows why, and rewording it here would
 *  be this page inventing a diagnosis. The fallbacks are for the replies that
 *  carry no sentence, and each names what actually happened rather than
 *  "something went wrong". */
function refusalText(status, body) {
  const said = body && typeof body.error === "string" ? body.error.trim() : "";
  if (said) return said;
  if (status === 0) return "The house did not answer.";
  if (status === 404) return "The hub no longer knows that device.";
  return `The hub refused that (${status}).`;
}

/* ── 2. Self-tests: `node app.js` ───────────────────────────────────── */

if (typeof document === "undefined") {
  let failures = 0;
  const check = (label, got, want) => {
    const a = JSON.stringify(got), b = JSON.stringify(want);
    if (a !== b) { failures += 1; console.error(`FAIL ${label}: got ${a}, want ${b}`); }
  };

  check("a number is a number", finiteNumber(9), 9);
  check("a numeric string is a number", finiteNumber("41"), 41);
  check("null is not a zero", finiteNumber(null), null);
  check("an empty string is not a zero", finiteNumber("  "), null);
  check("a boolean is not a one", finiteNumber(true), null);
  check("infinity is not a reading", finiteNumber(Infinity), null);

  check("duration seconds", duration(45), "45s");
  check("duration minutes", duration(75), "1m 15s");
  check("duration days", duration(534240), "6d 4h");

  check("a position is a clock", clockText(41), "0:41");
  check("three minutes twelve", clockText(192), "3:12");
  check("an hour is only shown when there is one", clockText(3723), "1:02:03");
  check("no position is an em dash", clockText(null), "—");
  check("a negative position is an em dash", clockText(-1), "—");

  check("clamping holds the ceiling", clampInt(140, 0, 100), 100);
  check("clamping holds the floor", clampInt(-8, 0, 100), 0);
  check("clamping rounds", clampInt(41.6, 0, 100), 42);
  check("clamping a non-number falls to the floor", clampInt(null, 0, 100), 0);

  check("link word while connecting", linkWord("connecting", 0), "CONNECTING");
  check("link word connected", linkWord("connected", 500), "CONNECTED");
  check("a fresh loss has no age", linkWord("lost", 1), "UNREACHABLE");
  check("an old loss wears its age", linkWord("lost", 95), "UNREACHABLE · 1m 35s");

  check("an ordinary id passes", usableId("sonos:rincon_7828B4C1E01400"), true);
  check("a slash is not refused, it is encoded", usableId("hue/light/3"), true);
  check("an empty id is refused", usableId(""), false);
  check("a non-string id is refused", usableId(null), false);
  check("a control character is refused", usableId("a\nb"), false);
  check("an absurd id is refused", usableId("x".repeat(201)), false);
  // The whole point of the encoder: an id with a slash in it must not be able
  // to address a route this page never meant to call.
  check("a slash cannot escape the route", commandPath("a/b"), "/api/home/devices/a%2Fb/command");
  check("a colon survives encoding readably", commandPath("sonos:x"), "/api/home/devices/sonos%3Ax/command");

  const speaker = {
    id: "sonos:kitchen", name: "Kitchen", room: "Kitchen", kind: "speaker",
    reachable: true, capabilities: ["transport", "volume", "mute", "group"],
    state: { transport: "playing", volume: 9, muted: false, source: "radio",
      title: "Sonata", artist: "Someone", duration_secs: 192, position_secs: 41,
      coordinator: "sonos:kitchen", group: ["sonos:kitchen"] },
  };
  const bulb = {
    id: "hue:hall", name: "Hall", room: "Hall", kind: "light", reachable: true,
    capabilities: ["power", "brightness", "color_temp"],
    state: { power: "on", brightness: 60, color_temp: 2700 },
  };
  const gone = {
    id: "tp:heater", name: "Heater", room: "Study", kind: "plug", reachable: false,
    capabilities: ["power"], note: "no reply since 19:02", state: { power: "on" },
  };
  const dumb = { id: "x:sensor", name: "Porch", kind: "fixture", reachable: true, capabilities: [], state: {} };

  check("a capability is what decides", [has(speaker, "transport"), has(speaker, "keys")], [true, false]);
  check("a device with no capability list drives nothing", has({ id: "a" }, "power"), false);
  check("an unpaired television is offered the remote",
    offersPairing({ id: "dial:a", capabilities: ["apps", "power"] }), true);
  check("a paired television is not asked to pair again",
    offersPairing({ id: "dial:a", capabilities: ["apps", "power", "keys", "transport"] }), false);
  check("a speaker is never offered pairing", offersPairing(speaker), false);
  check("a device that drives nothing is not offered pairing", offersPairing(dumb), false);

  check("a kind is a label", kindWord("television"), "TELEVISION");
  check("an unknown kind is shown as written", kindWord("kettle"), "KETTLE");
  check("no kind is still a word", kindWord(null), "DEVICE");

  check("playing is the one lit lamp", deviceStatus(speaker), { status: "ok", word: "PLAYING" });
  check("muted is said in the word, not in colour",
    deviceStatus({ ...speaker, state: { ...speaker.state, muted: true } }),
    { status: "ok", word: "PLAYING · MUTED" });
  check("paused is quiet", deviceStatus({ ...speaker, state: { transport: "paused" } }),
    { status: "idle", word: "PAUSED" });
  check("a lit bulb fills its slot", deviceStatus(bulb), { status: "ok", word: "ON" });
  check("an unlit bulb is an empty slot",
    deviceStatus({ ...bulb, state: { power: "off" } }), { status: "idle", word: "OFF" });
  // The doctrine, asserted: nothing that is merely off, paused or asleep may
  // raise its voice, or a genuine alarm has nowhere to be seen from.
  check("an unreachable device does not shout", deviceStatus(gone), { status: "idle", word: "UNREACHABLE" });
  check("a device with nothing to drive is present, not broken",
    deviceStatus(dumb), { status: "idle", word: "PRESENT" });
  check("no lamp on this page is ever amber or red",
    [speaker, bulb, gone, dumb, { ...speaker, state: { transport: "buffering" } },
      { ...bulb, state: { power: "what" } }]
      .map((d) => deviceStatus(d).status)
      .filter((s) => s === "warn" || s === "bad"),
    []);

  check("a playing speaker says what and how loud", deviceSentence(speaker), "Playing radio at volume 9.");
  check("muted outranks the volume",
    deviceSentence({ ...speaker, state: { ...speaker.state, muted: true } }), "Playing, muted.");
  check("a source nobody named is left out",
    deviceSentence({ ...speaker, state: { transport: "playing", volume: 4 } }), "Playing at volume 4.");
  check("a paused speaker is one word", deviceSentence({ ...speaker, state: { transport: "paused" } }), "Paused.");
  check("an unknown transport is idle, not blank",
    deviceSentence({ ...speaker, state: {} }), "Idle.");
  check("a bulb states its settings", deviceSentence(bulb), "On at 60% brightness and 2700K.");
  check("a bulb with one setting does not say 'and'",
    deviceSentence({ ...bulb, state: { power: "on", brightness: 60 } }), "On at 60% brightness.");
  check("a television names its app",
    deviceSentence({ id: "t", reachable: true, capabilities: ["power", "apps"], state: { power: "on", app: "netflix" } }),
    "On, showing netflix.");
  check("an off plug is one word", deviceSentence({ ...gone, reachable: true, state: { power: "off" } }), "Off.");
  check("a device that never said is not guessed at",
    deviceSentence({ id: "t", reachable: true, capabilities: ["power"], state: {} }),
    "It has not said whether it is on.");
  check("an unreachable device's sentence is about the hub", deviceSentence(gone), "The hub cannot reach it.");
  check("nothing to drive is said plainly",
    deviceSentence(dumb), "Reporting only — there is nothing here to drive.");
  // A bulb reporting brightness 0 is at zero, not unknown, and the two must not
  // render the same.
  check("zero brightness is a reading, not an absence",
    deviceSentence({ ...bulb, state: { power: "on", brightness: 0, color_temp: null } }),
    "On at 0% brightness.");

  check("a reachable device has no note", noteSentence(speaker), "");
  check("a note becomes a sentence", noteSentence(gone), "no reply since 19:02.");
  check("a note that is already a sentence is left alone",
    noteSentence({ ...gone, note: "It has been unplugged." }), "It has been unplugged.");
  check("a silent hub is made to say so", noteSentence({ ...gone, note: null }), "The hub gave no reason.");

  check("one name is a name", listWords(["Kitchen"]), "Kitchen");
  check("two names take 'and'", listWords(["Kitchen", "Patio"]), "Kitchen and Patio");
  check("three names take a comma and an 'and'",
    listWords(["Kitchen", "Patio", "Study"]), "Kitchen, Patio and Study");

  const names = new Map([["sonos:kitchen", "Kitchen"], ["sonos:patio", "Patio"]]);
  const leader = { ...speaker, state: { ...speaker.state, group: ["sonos:kitchen", "sonos:patio"] } };
  const member = {
    id: "sonos:patio", name: "Patio", reachable: true, capabilities: ["transport", "group"],
    state: { transport: "playing", coordinator: "sonos:kitchen", group: ["sonos:kitchen", "sonos:patio"] },
  };
  check("a group of one is not a group", isGrouped(speaker), false);
  check("a group of two is", isGrouped(leader), true);
  check("a coordinator names who follows it", groupSentence(leader, names), "Leading Patio.");
  /** Guards the reading a person actually needs: a speaker that is only
   *  echoing another one must say which, or the volume slider on the wrong
   *  plate is the one they reach for. */
  check("a grouped member reports its coordinator", groupSentence(member, names), "Following Kitchen.");
  check("an ungrouped speaker says nothing about groups", groupSentence(speaker, names), "");
  check("a member this page has never seen is shown as its id",
    groupSentence({ ...member, state: { ...member.state, coordinator: "sonos:ghost" } }, names),
    "Following sonos:ghost.");

  const fleet = [speaker, member, bulb, gone,
    { id: "sonos:study", name: "Study", reachable: false, capabilities: ["transport", "group"], state: {} }];
  check("a join picker offers the other groupables",
    joinCandidates(fleet, speaker).map((c) => c.name), ["Patio"]);
  /** A speaker that is not answering cannot be joined to anything, and
   *  offering it produces a refusal the person had no way to predict. */
  check("an unreachable speaker is not offered",
    joinCandidates(fleet, speaker).some((c) => c.id === "sonos:study"), false);
  check("a device already in the group is not offered again",
    joinCandidates(fleet, leader).map((c) => c.name), []);
  check("a member is not offered the speaker it is already following",
    joinCandidates(fleet, member).map((c) => c.name), []);

  const placed = roomsOf([
    { id: "b", name: "Two", room: "Study" },
    { id: "a", name: "One", room: "Kitchen" },
    { id: "c", name: "Three", room: null },
    { id: "d", name: "Four", room: "  " },
    { id: "e", name: "Alpha", room: "Study" },
  ]);
  check("rooms are ordered and unplaced comes last",
    placed.map((g) => g.label), ["KITCHEN", "STUDY", "UNPLACED"]);
  // Membership rather than order: a room of whitespace and a room of null are
  // the same absence, and both land in UNPLACED.
  check("a room without a name is not a room named ' '",
    placed[2].devices.map((d) => d.id).sort(), ["c", "d"]);
  check("devices inside a room are ordered by name",
    placed[1].devices.map((d) => d.name), ["Alpha", "Two"]);
  check("an empty house has no rooms", roomsOf([]), []);

  check("known rooms are sorted and deduplicated",
    knownRooms([{ room: "Study" }, { room: "Kitchen" }, { room: "Study" }]), ["Kitchen", "Study"]);
  check("blank and absent rooms suggest nothing",
    knownRooms([{ room: null }, { room: "  " }, { room: undefined }]), []);
  check("an empty house suggests no rooms", knownRooms([]), []);

  check("condition while connecting outranks everything",
    condition("connecting", [speaker]), "Reaching the house");
  check("condition lost outranks the devices", condition("lost", [speaker]), "The house is not answering");
  check("condition on an empty house", condition("connected", []), "No devices found");
  check("condition names the one that is missing", condition("connected", [speaker, gone]), "Heater is not answering");
  check("condition counts several missing",
    condition("connected", [gone, { ...gone, id: "z", name: "Other" }]), "2 devices are not answering");
  check("a quiet house says so",
    condition("connected", [{ ...speaker, state: { transport: "paused" } }, { ...bulb, state: { power: "off" } }]),
    "The house is quiet");
  check("a busy house counts both kinds", condition("connected", [speaker, member, bulb]), "2 playing and 1 on");
  check("only one kind is counted when only one is happening",
    condition("connected", [bulb]), "1 on");

  check("a position is a fraction", progressFraction(41, 192), 41 / 192);
  check("an unknown duration is not a bar at zero", progressFraction(41, null), null);
  check("a live stream with no duration draws no bar", progressFraction(600, 0), null);
  check("a position past the end is held at the end", progressFraction(400, 192), 1);
  check("a negative position is held at the start", progressFraction(-5, 192), 0);

  check("a percentage rounds", percentText(59.6), "60%");
  check("no percentage is an em dash", percentText(null), "—");

  check("a battery reads as a percentage", batteryText({ battery_pct: 100 }), "100%");
  check("a charging battery says so", batteryText({ battery_pct: 41, battery_charging: true }), "41% CHG");
  check("a mains device has no battery reading", batteryText({}), "");
  check("a flat battery is the one thing worth colouring", batteryLow({ battery_pct: 9 }), true);
  check("a flat battery on the charger is somebody else's problem",
    batteryLow({ battery_pct: 9, battery_charging: true }), false);
  check("a healthy battery is quiet", batteryLow({ battery_pct: 80 }), false);
  check("no battery is not a flat battery", batteryLow({}), false);

  check("a hex colour normalises", usableHex("#ff8800"), "FF8800");
  check("a bare hex colour passes", usableHex("FF8800"), "FF8800");
  check("a short colour is refused", usableHex("F80"), null);
  check("a named colour is refused", usableHex("orange"), null);
  check("nothing is not a colour", usableHex(null), null);

  check("left and down step down", [arrowStep("ArrowLeft"), arrowStep("ArrowDown")], [-1, -1]);
  check("right and up step up", [arrowStep("ArrowRight"), arrowStep("ArrowUp")], [1, 1]);
  check("page keys step further", [arrowStep("PageDown"), arrowStep("PageUp")], [-2, 2]);
  check("tab belongs to the platform", arrowStep("Tab"), null);
  check("a key named like an object property is still not an arrow", arrowStep("constructor"), null);

  // The slider's whole argument, asserted. Each of these was a real symptom
  // before it was a test.
  check("with no hold the reported value wins", sliderValue(9, null, 1000), { value: 9, keep: false });
  check("a hand on the control owns it",
    sliderValue(9, { holding: true, value: 30, until: 0 }, 1000), { value: 30, keep: true });
  check("a released control keeps its value until the hub agrees",
    sliderValue(9, { holding: false, value: 30, until: 5000 }, 1000), { value: 30, keep: true });
  check("the hub agreeing closes the window at once",
    sliderValue(30, { holding: false, value: 30, until: 5000 }, 1000), { value: 30, keep: false });
  check("a command the hub dropped does not freeze the reading for ever",
    sliderValue(9, { holding: false, value: 30, until: 5000 }, 5000), { value: 9, keep: false });
  check("a hand outlasts its own deadline",
    sliderValue(9, { holding: true, value: 30, until: 1 }, 99999), { value: 30, keep: true });

  check("a refusal is shown in the hub's own words",
    refusalText(400, { error: "that speaker is grouped and cannot be told directly" }),
    "that speaker is grouped and cannot be told directly");
  check("a refusal with no sentence still says what happened",
    refusalText(500, null), "The hub refused that (500).");
  check("a missing device is named as one", refusalText(404, {}), "The hub no longer knows that device.");
  check("a network failure is not a status code", refusalText(0, null), "The house did not answer.");

  if (failures > 0) { process.exitCode = 1; console.error(`${failures} failure(s)`); }
  else console.log("all self-tests passed");
} else {
  boot();
}

/* ── 3. The application ─────────────────────────────────────────────── */

/** Wires the page up and starts the poll. */
function boot() {

  /* How often the hub is asked, in ms.
   *
   * A second while somebody is looking, because this page's whole job is to be
   * right *now* — a light somebody switched at the wall must appear here before
   * they have walked into the next room, and a poll slower than that makes the
   * page feel like it is guessing. Fifteen seconds when the tab is hidden,
   * because a phone left on a table with this page open would otherwise spend
   * its battery asking a question nobody is reading the answer to; the poll on
   * becoming visible again is immediate, so the slow rate is never what the
   * reader sees. */
  const POLL_LIVE = 1000;
  const POLL_HIDDEN = 15000;

  /* How long a released slider keeps the number the person chose while it
   * waits for the hub to echo it back. Four seconds is a device that ramps its
   * volume plus the poll that discovers it did; past that the page believes the
   * hub over its own memory, because a command that was silently dropped must
   * not leave a reading lying for ever. */
  const ECHO_MS = 4000;
  /* How long the arrow keys are allowed to accumulate before one step command
   * is sent. A held arrow repeats at the operating system's key rate — thirty a
   * second on a Mac — and one POST per repeat is a flood the hub answers by
   * falling behind. One request carrying the summed delta is the same
   * instruction, once. */
  const STEP_MS = 120;
  /* What one arrow press is worth. Five is a step somebody notices without
   * having to press it ten times to cross the range. */
  const VOLUME_STEP = 5;

  /** Everything the page knows. The DOM is a function of this and nothing else. */
  const state = {
    link: "connecting",      // "connecting" | "connected" | "lost"
    generation: null,        // the hub's counter; unchanged means nothing to redraw
    devices: [],
    notice: null,            // the last refusal, until it is dismissed
  };

  const $ = (id) => document.getElementById(id);

  /* Poll bookkeeping: one loop, and an immediate re-poll after any command. */
  let pollTimer = null;
  let inFlight = false;
  let pollAgain = false;
  /* When the hub last answered, for the masthead's age-of-loss reading. */
  let lastContact = 0;

  /* Plates and room blocks by key, updated in place from then on.
   *
   * This is the rule the rest of the render depends on: a plate is built once
   * and never rebuilt. Rebuilding restarts every lamp animation on it, drops
   * the focus somebody was about to press Enter on, and destroys the very
   * slider element they are holding — which no amount of care in `sliderValue`
   * can survive, because the node it was reasoning about is gone. Controls a
   * device does not justify are hidden rather than absent, so a plate's shape
   * is a set of attributes and never a rebuild. */
  const plates = new Map();
  const roomBlocks = new Map();

  /* Live slider holds, keyed by device and command. See `sliderValue`. */
  const holds = new Map();
  /* Accumulating arrow-key steps, keyed the same way. */
  const steps = new Map();

  /* ── transport ────────────────────────────────────────────────────── */

  /** One request to the house API. Throws only on network failure; every
   *  refusal comes back as a status and a body for the caller to read. */
  async function api(path, options = {}) {
    const method = options.method || "GET";
    const headers = { "Accept": "application/json" };
    let body;
    if (options.body !== undefined) {
      headers["Content-Type"] = "application/json";
      body = JSON.stringify(options.body);
    }
    const response = await fetch(path, { method, headers, body, credentials: "same-origin" });
    let payload = null;
    try { payload = await response.json(); } catch { /* an empty body is fine */ }
    return { status: response.status, body: payload };
  }

  /** Sends one command and polls immediately afterwards.
   *
   *  There is no success notice, deliberately. A command that worked proves it
   *  by changing the reading it was aimed at, one poll later, and a page that
   *  announced every volume nudge would be a page whose notices nobody reads —
   *  which is exactly the page you want to be shouting on the day a command is
   *  refused. Only refusals speak. */
  async function send(id, body) {
    if (!usableId(id)) return;
    let reply;
    try { reply = await api(commandPath(id), { method: "POST", body }); }
    catch { showNotice(refusalText(0, null)); return; }
    if (reply.status < 200 || reply.status >= 300) showNotice(refusalText(reply.status, reply.body));
    poll();
  }

  /* ── the poll ─────────────────────────────────────────────────────── */

  function schedule(delay) {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(poll, delay);
  }

  /** One poll. Called on a timer, and directly for an immediate re-poll after
   *  any command; overlapping calls queue one more rather than racing, so a
   *  burst of commands cannot open a burst of connections whose replies arrive
   *  out of order and render an older house over a newer one. */
  async function poll() {
    if (inFlight) { pollAgain = true; return; }
    inFlight = true;
    try {
      await refresh();
    } finally {
      inFlight = false;
      const delay = pollAgain ? 0 : (document.hidden ? POLL_HIDDEN : POLL_LIVE);
      pollAgain = false;
      schedule(delay);
    }
  }

  /** The poll body: one snapshot of the whole house.
   *
   *  The `generation` is the hub's promise that nothing has changed, and an
   *  unchanged one skips the entire render. That is not a micro-optimisation:
   *  the render writes into every plate on the page, and the less often it runs
   *  the fewer chances it has to take a control away from a hand. The one
   *  exception is a live slider hold — those settle on a clock rather than on a
   *  change, so while one is outstanding the render has to keep running for it
   *  to be able to close. */
  async function refresh() {
    let reply;
    try { reply = await api("/api/home"); }
    catch { state.link = "lost"; render(); return; }
    if (reply.status !== 200 || !reply.body) { state.link = "lost"; render(); return; }

    const wasConnected = state.link === "connected";
    state.link = "connected";
    lastContact = Date.now();

    const generation = finiteNumber(reply.body.generation);
    if (wasConnected && generation !== null && generation === state.generation && holds.size === 0) return;

    state.generation = generation;
    // A device the page cannot address is a device it must not draw controls
    // for: every button on a plate ends up in a URL built from this id.
    state.devices = Array.isArray(reply.body.devices)
      ? reply.body.devices.filter((device) => device && usableId(device.id))
      : [];
    render();
  }

  /* ── rendering ────────────────────────────────────────────────────── */

  /** A flat, idempotent sequence. Every function below may be called at any
   *  time, in any order, any number of times, and leaves the page saying the
   *  same thing — which is what makes "render after anything" a safe rule
   *  rather than a source of half-drawn states. */
  function render() {
    renderMasthead();
    renderBank();
    renderRooms();
    renderNotice();
  }

  function setLamp(lamp, status) {
    lamp.className = `lamp ${status}`;
  }

  function setStateWord(word, status, text) {
    word.className = status === "warn" || status === "bad" ? `stateword ${status}` : "stateword";
    word.textContent = text;
  }

  function renderMasthead() {
    const faces = {
      connecting: { status: "warn", reaching: true },
      connected: { status: "ok", reaching: false },
      lost: { status: "bad", reaching: false },
    };
    const face = faces[state.link] || faces.connecting;
    const sinceSecs = lastContact ? Math.floor((Date.now() - lastContact) / 1000) : 0;
    // The sweep and the lamp are the same instrument in two states, so exactly
    // one of them is ever on the page: a spinner beside a lit lamp reads as two
    // contradictory answers to one question.
    $("link-sweep").hidden = !face.reaching;
    $("link-lamp").hidden = face.reaching;
    setLamp($("link-lamp"), face.status);
    setStateWord($("link-word"), face.status, linkWord(state.link, sinceSecs));
    $("gen").textContent = state.generation === null ? "" : `GEN ${state.generation}`;
  }

  function renderBank() {
    $("condition").textContent = condition(state.link, state.devices);
    const total = state.devices.length;
    $("evidence").hidden = total === 0;
    if (total === 0) return;
    const gone = state.devices.filter((device) => device.reachable !== true).length;
    const active = state.devices.filter((device) => isPlaying(device) || isPoweredOn(device)).length;
    $("ev-devices").textContent = String(total);
    $("ev-active").textContent = String(active);
    const goneEl = $("ev-gone");
    goneEl.textContent = String(gone);
    goneEl.className = gone > 0 ? "mono bad-ink" : "mono";
  }

  function renderNotice() {
    const notice = $("notice");
    notice.hidden = !state.notice;
    if (state.notice) $("notice-text").textContent = state.notice;
  }

  function showNotice(text) {
    state.notice = text;
    renderNotice();
  }

  /* ── the rooms ────────────────────────────────────────────────────── */

  /** Every room, and the plates standing in it.
   *
   *  Rooms and plates are both moved only when their order actually changed.
   *  Re-inserting a node restarts its lamp's animation, and on the ordinary
   *  poll — which is every second, for hours — nothing has moved at all. */
  function renderRooms() {
    const rooms = $("rooms");
    const groups = roomsOf(state.devices);
    const names = new Map(state.devices.map((device) => [device.id, String(device.name || device.id)]));

    $("empty").hidden = state.devices.length > 0;
    $("empty-text").textContent = state.link === "connected"
      ? "The hub is reporting no devices."
      : "Waiting for the hub.";

    const seenRooms = new Set();
    const seenDevices = new Set();
    let cursor = rooms.firstElementChild;

    for (const group of groups) {
      seenRooms.add(group.key);
      let block = roomBlocks.get(group.key);
      if (!block) { block = buildRoom(); roomBlocks.set(group.key, block); }
      if (block.el === cursor) cursor = cursor.nextElementSibling;
      else rooms.insertBefore(block.el, cursor);
      block.heading.textContent = group.label;
      block.count.textContent = String(group.devices.length);

      let deviceCursor = block.grid.firstElementChild;
      for (const device of group.devices) {
        seenDevices.add(device.id);
        let plate = plates.get(device.id);
        if (!plate) { plate = buildPlate(device.id); plates.set(device.id, plate); }
        if (plate.el === deviceCursor) deviceCursor = deviceCursor.nextElementSibling;
        else block.grid.insertBefore(plate.el, deviceCursor);
        updatePlate(plate, device, names);
      }
    }

    for (const [key, block] of roomBlocks) {
      if (!seenRooms.has(key)) { block.el.remove(); roomBlocks.delete(key); }
    }
    for (const [id, plate] of plates) {
      if (!seenDevices.has(id)) { plate.el.remove(); plates.delete(id); }
    }
  }

  /** One room: a section rule with its label, its count, and the grid under
   *  it. A rule rather than an outline — the tick on its end says how far the
   *  room extends, which is the job a box does, for a fiftieth of the ink and
   *  without drawing a second frame around plates that already have one. */
  function buildRoom() {
    const el = document.createElement("section");
    el.className = "room";
    const rule = document.createElement("div");
    rule.className = "section-rule";
    const heading = document.createElement("h2");
    const line = document.createElement("span");
    line.className = "rule";
    const count = document.createElement("span");
    count.className = "mono micro";
    rule.append(heading, line, count);
    const grid = document.createElement("div");
    grid.className = "roomdevices";
    el.append(rule, grid);
    return { el, heading, count, grid };
  }

  /* ── one device's plate ───────────────────────────────────────────── */

  /** A labelled reading in the plate's dial bar. */
  function buildDial(label) {
    const el = document.createElement("span");
    el.className = "dial";
    el.hidden = true;
    const caption = document.createElement("span");
    caption.className = "fieldlabel";
    caption.textContent = label;
    const value = document.createElement("span");
    value.className = "mono";
    el.append(caption, value);
    return { el, value };
  }

  /** A button that carries one command, read at the moment it is pressed.
   *
   *  The handler looks the device up again rather than closing over the object
   *  it was built from. That object is a snapshot from some poll minutes ago,
   *  and a Mute button that toggles the mute state as it was when the page
   *  loaded is a button that does the opposite of what it says on it. */
  function buildButton(label, className) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = className || "btn";
    button.textContent = label;
    button.hidden = true;
    return button;
  }

  /** A slider, and the whole of its conflict with the poll.
   *
   *  Four events, doing four different jobs:
   *
   *  `input` fires continuously through a drag and marks the control held, so
   *  the render stops writing to it. Nothing is sent — a drag across the range
   *  would otherwise be forty commands.
   *
   *  `change` fires once, on release, and is what sends the absolute value. It
   *  also opens the echo window that keeps the chosen number on screen until
   *  the hub has caught up.
   *
   *  `pointercancel` and `blur` end the hold, and so does the window's own
   *  `pointerup` — registered once for the page, further down. A pointer
   *  released outside the control never sends one to it, and a hold that is
   *  never released is a slider that stops updating for the rest of the
   *  session.
   *
   *  `keydown` is the arrow keys, and they are the reason `volume_step` exists
   *  on the wire: a step is a *relative* instruction, so two people nudging one
   *  speaker from two phones both get what they asked for, where two absolute
   *  values would mean the second one silently undoes the first. The default is
   *  prevented so the native change cannot also fire an absolute value behind
   *  the relative one, and the presses are accumulated into a single request. */
  function buildSlider(id, options) {
    const row = document.createElement("div");
    row.className = "slider";
    row.hidden = true;
    const label = document.createElement("span");
    label.className = "fieldlabel";
    label.textContent = options.label;
    const input = document.createElement("input");
    input.type = "range";
    input.min = "0";
    input.max = String(options.max);
    input.step = "1";
    input.setAttribute("aria-label", options.aria);
    const value = document.createElement("span");
    value.className = "value mono";
    row.append(label, input, value);

    // The command leads the key, and no command name has a space in it, so
    // the separator is unambiguous however strange an id turns out to be.
    const key = `${options.command} ${id}`;
    const slider = { row, input, value, key, unit: options.unit, max: options.max };

    const showHeld = (held) => {
      input.value = String(held);
      value.textContent = `${held}${options.unit}`;
    };
    const release = () => {
      const held = holds.get(key);
      if (held) held.holding = false;
    };

    input.addEventListener("pointerdown", () => { holdFor(key, input.value, options.max).holding = true; });
    input.addEventListener("pointercancel", release);
    input.addEventListener("blur", release);

    input.addEventListener("input", () => {
      const held = holdFor(key, input.value, options.max);
      held.holding = true;
      held.value = clampInt(input.value, 0, options.max);
      held.until = Date.now() + ECHO_MS;
      value.textContent = `${held.value}${options.unit}`;
    });

    input.addEventListener("change", () => {
      const held = holdFor(key, input.value, options.max);
      held.holding = false;
      held.value = clampInt(input.value, 0, options.max);
      held.until = Date.now() + ECHO_MS;
      send(id, { command: options.command, value: held.value });
    });

    if (options.stepCommand) {
      input.addEventListener("keydown", (event) => {
        const step = arrowStep(event.key);
        if (step === null) return;
        event.preventDefault();
        const delta = step * VOLUME_STEP;
        const held = holdFor(key, input.value, options.max);
        held.holding = false;
        held.value = clampInt(held.value + delta, 0, options.max);
        held.until = Date.now() + ECHO_MS;
        showHeld(held.value);

        const pending = steps.get(key) || { delta: 0, timer: null };
        pending.delta += delta;
        clearTimeout(pending.timer);
        pending.timer = setTimeout(() => {
          steps.delete(key);
          send(id, { command: options.stepCommand, delta: pending.delta });
        }, STEP_MS);
        steps.set(key, pending);
      });
    }

    return slider;
  }

  /** The hold record for a control, refreshed from what is on screen once its
   *  echo window has closed — so a stale hold can never resurrect an old value
   *  the next time somebody touches the control. */
  function holdFor(key, current, max) {
    let held = holds.get(key);
    if (!held || (!held.holding && Date.now() >= held.until)) {
      held = { holding: false, value: clampInt(current, 0, max), until: 0 };
      holds.set(key, held);
    }
    return held;
  }

  /** Writes a slider's number without ever taking it out of a hand. */
  function updateSlider(slider, capable, reported, locked) {
    slider.row.hidden = !capable;
    if (!capable) { holds.delete(slider.key); return; }
    if (reported === null) {
      // The capability exists and the value does not — a bulb that is off
      // reports no brightness. A slider parked at zero would be a claim.
      slider.input.disabled = true;
      slider.value.textContent = "—";
      holds.delete(slider.key);
      return;
    }
    slider.input.disabled = locked;
    const { value, keep } = sliderValue(Math.round(reported), holds.get(slider.key) || null, Date.now());
    if (!keep) holds.delete(slider.key);
    const shown = String(clampInt(value, 0, slider.max));
    if (slider.input.value !== shown) slider.input.value = shown;
    slider.value.textContent = `${shown}${slider.unit}`;
  }

  /** The device this id currently names, or null. Every handler reads the
   *  house through here at the moment it fires. */
  function deviceById(id) {
    return state.devices.find((device) => device.id === id) || null;
  }

  /** One plate, built once. Every control it could ever need is built here and
   *  hidden; `updatePlate` decides which of them this device's capabilities
   *  justify. */
  function buildPlate(id) {
    const el = document.createElement("section");
    el.className = "plate device";

    const head = document.createElement("div");
    head.className = "title-rule";
    const name = document.createElement("h3");
    name.className = "title";
    const rule = document.createElement("span");
    rule.className = "rule";
    const kind = document.createElement("span");
    kind.className = "fieldlabel kind";
    const lamp = document.createElement("span");
    lamp.className = "lamp idle";
    const word = document.createElement("span");
    word.className = "stateword";
    head.append(name, rule, kind, lamp, word);

    /* Labelling. Every known device may be renamed and placed in a room —
       this is a decision about the page, not a command to the device, so it
       is offered whether or not the device is reachable and whatever its
       capabilities are: a lamp asleep in a box still deserves a name before
       it comes back. It stands outside `controls` for exactly that reason —
       `controls` disappears for a device with nothing to drive, and labelling
       is not one of the things capabilities gate. */
    const labelRow = document.createElement("div");
    labelRow.className = "inline-form";
    const labelText = document.createElement("span");
    labelText.className = "fieldlabel";
    labelText.textContent = "LABEL";
    const nameInput = document.createElement("input");
    nameInput.className = "mono";
    nameInput.autocomplete = "off";
    nameInput.spellcheck = false;
    nameInput.placeholder = "name";
    nameInput.maxLength = 80;
    nameInput.setAttribute("aria-label", "Rename this device");
    const roomInput = document.createElement("input");
    roomInput.className = "mono";
    roomInput.autocomplete = "off";
    roomInput.spellcheck = false;
    roomInput.placeholder = "room";
    roomInput.maxLength = 80;
    roomInput.setAttribute("aria-label", "The room this device stands in");
    const roomList = document.createElement("datalist");
    roomList.id = `roomlist-${id.replace(/[^A-Za-z0-9_-]/g, "_")}`;
    roomInput.setAttribute("list", roomList.id);
    const labelGo = buildButton("SAVE", "btn small");
    labelRow.append(labelText, nameInput, roomInput, labelGo, roomList);

    const doing = document.createElement("p");
    doing.className = "doing";
    const note = document.createElement("p");
    note.className = "note warn-ink";
    note.hidden = true;

    // What is playing. The title and the artist are somebody's words, so they
    // are set in the interface face; the clock beside the bar is a machine
    // reading and is not.
    const nowplaying = document.createElement("div");
    nowplaying.className = "nowplaying";
    nowplaying.hidden = true;
    const track = document.createElement("span");
    track.className = "track";
    const artist = document.createElement("span");
    artist.className = "artist";
    nowplaying.append(track, artist);

    const progress = document.createElement("div");
    progress.className = "progress";
    progress.hidden = true;
    const bar = document.createElement("span");
    bar.className = "bar";
    const fill = document.createElement("span");
    fill.className = "fill";
    bar.append(fill);
    const clock = document.createElement("span");
    clock.className = "clock mono";
    progress.append(bar, clock);

    const readings = document.createElement("div");
    readings.className = "readings";
    readings.hidden = true;
    const source = buildDial("SOURCE");
    const app = buildDial("APP");
    const battery = buildDial("BATTERY");
    // color_temp is advertised as a capability and the command set names no
    // verb for it, so it is a reading and not a control. A knob that produced a
    // 4xx every time it was turned would be worse than no knob.
    const temp = buildDial("TEMPERATURE");
    const colour = buildDial("COLOUR");
    const swatchline = document.createElement("span");
    swatchline.className = "swatchline";
    const swatch = document.createElement("span");
    swatch.className = "swatch";
    swatchline.append(swatch, colour.value);
    colour.el.append(swatchline);
    readings.append(source.el, app.el, battery.el, temp.el, colour.el);

    const controls = document.createElement("div");
    controls.className = "controls";

    const actions = document.createElement("div");
    actions.className = "actions";
    actions.hidden = true;
    const transport = buildButton("PLAY", "btn primary");
    const mute = buildButton("MUTE", "btn");
    mute.setAttribute("aria-pressed", "false");
    const power = buildButton("TURN ON", "btn primary");
    actions.append(transport, mute, power);

    const volume = buildSlider(id, {
      label: "VOLUME", aria: "Volume", command: "volume", stepCommand: "volume_step",
      max: 100, unit: "",
    });
    const brightness = buildSlider(id, {
      label: "BRIGHTNESS", aria: "Brightness", command: "brightness", stepCommand: null,
      max: 100, unit: "%",
    });

    const groupRow = document.createElement("div");
    groupRow.className = "grouprow";
    groupRow.hidden = true;
    const groupText = document.createElement("span");
    groupText.className = "caption";
    const joinPick = document.createElement("select");
    joinPick.setAttribute("aria-label", "Speaker to join");
    const join = buildButton("JOIN", "btn small");
    const leave = buildButton("LEAVE", "btn small");
    groupRow.append(groupText, joinPick, join, leave);

    const keypad = document.createElement("div");
    keypad.className = "keypad";
    keypad.hidden = true;
    const keyrow = document.createElement("div");
    keyrow.className = "keyrow";
    keyrow.hidden = true;
    const keyButton = (glyph, keyName, aria, className) => {
      const button = document.createElement("button");
      button.type = "button";
      button.className = className || "btn small";
      button.textContent = glyph;
      button.setAttribute("aria-label", aria);
      button.addEventListener("click", () => send(id, { command: "key", name: keyName }));
      return button;
    };
    const gap = () => {
      const cell = document.createElement("span");
      cell.className = "gap";
      return cell;
    };
    keypad.append(
      gap(), keyButton("▲", "up", "Up"), gap(),
      keyButton("◀", "left", "Left"),
      keyButton("OK", "select", "Select", "btn small ok"),
      keyButton("▶", "right", "Right"),
      gap(), keyButton("▼", "down", "Down"), gap(),
    );
    keyrow.append(keyButton("BACK", "back", "Back"), keyButton("HOME", "home", "Home"));

    const appRow = document.createElement("div");
    appRow.className = "inline-form";
    appRow.hidden = true;
    const appLabel = document.createElement("span");
    appLabel.className = "fieldlabel";
    appLabel.textContent = "LAUNCH";
    const appInput = document.createElement("input");
    appInput.className = "mono";
    appInput.autocomplete = "off";
    appInput.spellcheck = false;
    appInput.placeholder = "app identifier";
    appInput.setAttribute("aria-label", "Application to launch");
    const appGo = buildButton("GO", "btn small");
    appGo.hidden = false;
    appRow.append(appLabel, appInput, appGo);

    /* Pairing. A Fire TV gives its d-pad, transport and sleep only to a client
       that has been handed a PIN off the television's own screen, so an
       unpaired set can be turned on and have applications launched and nothing
       more. This row is the only control on the page that asks a person to
       look at a different screen, which is why it says so in words instead of
       just offering a button. */
    const pairRow = document.createElement("div");
    pairRow.className = "inline-form";
    pairRow.hidden = true;
    const pairLabel = document.createElement("span");
    pairLabel.className = "fieldlabel";
    pairLabel.textContent = "REMOTE";
    const pairText = document.createElement("span");
    pairText.className = "micro";
    pairText.textContent = "Not paired — no keys.";
    const pairStart = buildButton("PAIR", "btn small");
    const pairInput = document.createElement("input");
    pairInput.className = "mono";
    pairInput.autocomplete = "off";
    pairInput.spellcheck = false;
    pairInput.placeholder = "PIN";
    pairInput.maxLength = 8;
    pairInput.hidden = true;
    pairInput.setAttribute("aria-label", "The PIN shown on the television");
    const pairGo = buildButton("CONFIRM", "btn small");
    pairGo.hidden = true;
    pairRow.append(pairLabel, pairText, pairStart, pairInput, pairGo);

    const colourRow = document.createElement("div");
    colourRow.className = "inline-form";
    colourRow.hidden = true;
    const colourLabel = document.createElement("span");
    colourLabel.className = "fieldlabel";
    colourLabel.textContent = "COLOUR";
    const colourInput = document.createElement("input");
    colourInput.className = "mono";
    colourInput.autocomplete = "off";
    colourInput.spellcheck = false;
    colourInput.placeholder = "FF8800";
    colourInput.maxLength = 7;
    colourInput.setAttribute("aria-label", "Colour, as six hexadecimal digits");
    const colourGo = buildButton("SET", "btn small");
    colourGo.hidden = false;
    colourRow.append(colourLabel, colourInput, colourGo);

    controls.append(actions, volume.row, brightness.row, groupRow, keypad, keyrow, appRow, pairRow, colourRow);

    const address = document.createElement("p");
    address.className = "address mono micro";
    address.hidden = true;

    el.append(head, labelRow, doing, note, nowplaying, progress, readings, controls, address);

    /* Handlers. Every one of them reads the device again through
       `deviceById` — see `buildButton`. */
    transport.addEventListener("click", () => {
      const device = deviceById(id);
      if (!device) return;
      const playing = device.state && device.state.transport === "playing";
      send(id, { command: playing ? "pause" : "play" });
    });
    mute.addEventListener("click", () => {
      const device = deviceById(id);
      if (!device) return;
      send(id, { command: "mute", value: !(device.state && device.state.muted) });
    });
    power.addEventListener("click", () => {
      const device = deviceById(id);
      if (!device) return;
      send(id, { command: "power", value: !(device.state && device.state.power === "on") });
    });
    join.addEventListener("click", () => {
      if (joinPick.value) send(id, { command: "join", target: joinPick.value });
    });
    leave.addEventListener("click", () => send(id, { command: "leave" }));
    appGo.addEventListener("click", () => {
      const wanted = appInput.value.trim();
      if (!wanted) { appInput.focus(); return; }
      send(id, { command: "launch", app: wanted });
    });
    /* Pairing is two presses with a person walking to a television in
       between, so the row keeps its own small state: PAIR asks for the PIN to
       be drawn, and the field it reveals stays revealed until a confirm lands
       or the device turns out to be paired after all. Nothing here is
       remembered across a reload, because a PIN does not outlive one either. */
    pairStart.addEventListener("click", () => {
      pairText.textContent = "Look at the television — a PIN should appear.";
      pairInput.hidden = false;
      pairGo.hidden = false;
      pairInput.focus();
      send(id, { command: "pair" });
    });
    pairGo.addEventListener("click", () => {
      const pin = pairInput.value.trim();
      if (!pin) { pairInput.focus(); return; }
      pairInput.value = "";
      send(id, { command: "pair_confirm", value: pin });
    });

    colourGo.addEventListener("click", () => {
      const wanted = usableHex(colourInput.value);
      // Refused here rather than by the hub: a round trip to be told that
      // "orange" is not a colour is a round trip that teaches nothing the field
      // could not have said instantly.
      colourInput.classList.toggle("bad", wanted === null);
      if (wanted === null) { colourInput.focus(); return; }
      colourInput.value = wanted;
      send(id, { command: "color", value: wanted });
    });

    /* SAVE sends only the field that actually changed — a rename and a room
       are two independent registry words, and a person who only touched the
       room field should not also re-send a name that was never edited. An
       emptied field is a real answer, not a no-op: it is how a custom name or
       a room assignment is cleared back to the default, so it is compared
       against the device's current value and not skipped for being blank. */
    labelGo.addEventListener("click", () => {
      const device = deviceById(id);
      if (!device) return;
      const wantedName = nameInput.value.trim();
      const currentName = String(device.name || "");
      if (wantedName !== currentName) send(id, { command: "rename", value: wantedName });
      const wantedRoom = roomInput.value.trim();
      const currentRoom = typeof device.room === "string" ? device.room.trim() : "";
      if (wantedRoom !== currentRoom) send(id, { command: "room", value: wantedRoom });
    });

    return {
      el, name, kind, lamp, word, doing, note, nowplaying, track, artist,
      progress, fill, clock, readings, source, app, battery, temp, colour, swatch,
      controls, actions, transport, mute, power, volume, brightness,
      groupRow, groupText, joinPick, join, leave, keypad, keyrow,
      appRow, appInput, appGo, pairRow, pairText, pairStart, pairInput, pairGo,
      colourRow, colourInput, colourGo, address,
      labelRow, nameInput, roomInput, roomList, labelGo,
      joinDrawn: "", roomsDrawn: "",
    };
  }

  /** Everything one plate says, written from one device. Idempotent, and
   *  called on every render for every visible device. */
  function updatePlate(plate, device, names) {
    const s = device.state || {};
    const reachable = device.reachable === true;
    /* An unreachable device keeps every control it has, disabled. Removing
       them would make the plate change shape as a device comes and goes, which
       moves the button under a finger that was already reaching for it; leaving
       them live would send commands into the dark and answer with a refusal the
       person did not earn. */
    const locked = !reachable;

    plate.el.classList.toggle("gone", !reachable);
    plate.el.setAttribute("aria-label", String(device.name || device.id));
    plate.name.textContent = String(device.name || device.id);
    plate.kind.textContent = kindWord(device.kind);
    const { status, word } = deviceStatus(device);
    setLamp(plate.lamp, status);
    setStateWord(plate.word, status, word);
    plate.doing.textContent = deviceSentence(device);

    const note = noteSentence(device);
    plate.note.hidden = note === "";
    plate.note.textContent = note;

    const address = typeof device.address === "string" ? device.address.trim() : "";
    plate.address.hidden = address === "";
    plate.address.textContent = address;

    /* The label fields. Renaming works whether or not the device is reachable
       — see `hub.rs`'s reasoning, "renaming an unreachable lamp is legitimate"
       — so neither field nor SAVE is disabled by `locked`. Each field is left
       alone while a hand is in it: overwriting what somebody is mid-typing
       with the server's last word is the same bug the slider hold exists to
       prevent, in a plainer control. */
    if (document.activeElement !== plate.nameInput) {
      plate.nameInput.value = String(device.name || "");
    }
    if (document.activeElement !== plate.roomInput) {
      plate.roomInput.value = typeof device.room === "string" ? device.room.trim() : "";
    }
    const rooms = knownRooms(state.devices);
    const roomsKey = JSON.stringify(rooms);
    if (roomsKey !== plate.roomsDrawn) {
      plate.roomsDrawn = roomsKey;
      plate.roomList.textContent = "";
      for (const room of rooms) {
        const option = document.createElement("option");
        option.value = room;
        plate.roomList.append(option);
      }
    }

    /* What is playing, and how far through it is. Both are hidden rather than
       blanked when there is nothing to say: an empty line where a title was is
       a plate that looks like it failed to load one. */
    const title = has(device, "transport") && typeof s.title === "string" ? s.title.trim() : "";
    plate.nowplaying.hidden = title === "";
    if (title !== "") {
      plate.track.textContent = title;
      const by = typeof s.artist === "string" ? s.artist.trim() : "";
      plate.artist.hidden = by === "";
      plate.artist.textContent = by;
    }
    const fraction = has(device, "transport") ? progressFraction(s.position_secs, s.duration_secs) : null;
    plate.progress.hidden = fraction === null;
    if (fraction !== null) {
      plate.fill.style.width = `${(fraction * 100).toFixed(1)}%`;
      plate.clock.textContent = `${clockText(s.position_secs)} / ${clockText(s.duration_secs)}`;
    }

    /* The dials. Each one appears only when the device has that reading, and
       the bar itself disappears when none of them do — an empty machined bar
       is furniture reporting nothing. */
    const sourceText = typeof s.source === "string" ? s.source.trim() : "";
    plate.source.el.hidden = sourceText === "";
    plate.source.value.textContent = sourceText;

    const appText = typeof s.app === "string" ? s.app.trim() : "";
    plate.app.el.hidden = appText === "";
    plate.app.value.textContent = appText;

    const batteryReading = batteryText(s);
    plate.battery.el.hidden = batteryReading === "";
    plate.battery.value.textContent = batteryReading;
    plate.battery.value.className = batteryLow(s) ? "mono bad-ink" : "mono";

    const tempReading = finiteNumber(s.color_temp);
    plate.temp.el.hidden = tempReading === null;
    plate.temp.value.textContent = tempReading === null ? "" : `${Math.round(tempReading)}K`;

    const hex = usableHex(s.color);
    plate.colour.el.hidden = hex === null;
    if (hex !== null) {
      plate.colour.value.textContent = hex;
      plate.swatch.style.background = `#${hex}`;
    }
    plate.readings.hidden = [plate.source, plate.app, plate.battery, plate.temp, plate.colour]
      .every((dial) => dial.el.hidden);

    /* The controls this device's capabilities justify, and nothing else. */
    const canTransport = has(device, "transport");
    plate.transport.hidden = !canTransport;
    plate.transport.disabled = locked;
    plate.transport.textContent = s.transport === "playing" ? "PAUSE" : "PLAY";

    const canMute = has(device, "mute");
    plate.mute.hidden = !canMute;
    plate.mute.disabled = locked;
    plate.mute.setAttribute("aria-pressed", s.muted ? "true" : "false");

    const canPower = has(device, "power");
    plate.power.hidden = !canPower;
    plate.power.disabled = locked;
    plate.power.textContent = s.power === "on" ? "TURN OFF" : "TURN ON";
    plate.actions.hidden = !canTransport && !canMute && !canPower;

    updateSlider(plate.volume, has(device, "volume"), finiteNumber(s.volume), locked);
    updateSlider(plate.brightness, has(device, "brightness"), finiteNumber(s.brightness), locked);

    /* Grouping. A grouped speaker is offered Leave and nothing else, because
       joining a second group from inside one is a question the wire has no way
       to ask; an ungrouped one is offered the others by name. */
    const canGroup = has(device, "group");
    plate.groupRow.hidden = !canGroup;
    if (canGroup) {
      const grouped = isGrouped(device);
      plate.groupText.textContent = grouped ? groupSentence(device, names) : "Not in a group.";
      plate.leave.hidden = !grouped;
      plate.leave.disabled = locked;
      plate.join.hidden = grouped;
      plate.joinPick.hidden = grouped;
      if (!grouped) fillJoin(plate, joinCandidates(state.devices, device), locked);
    }

    const canKeys = has(device, "keys");
    plate.keypad.hidden = !canKeys;
    plate.keyrow.hidden = !canKeys;
    for (const button of [...plate.keypad.children, ...plate.keyrow.children]) {
      if (button.tagName === "BUTTON") button.disabled = locked;
    }

    const canApps = has(device, "apps");
    plate.appRow.hidden = !canApps;
    plate.appInput.disabled = locked;
    plate.appGo.disabled = locked;

    /* The pairing offer, shown only where it means something: a set that can
       launch applications but takes no keys is a Fire TV nobody has paired.
       Once the keys arrive the row disappears rather than lingering as a
       button that would put a PIN on a screen for no reason. */
    const canPair = offersPairing(device);
    plate.pairRow.hidden = !canPair;
    plate.pairStart.disabled = locked;
    plate.pairGo.disabled = locked;
    if (!canPair) {
      plate.pairInput.hidden = true;
      plate.pairGo.hidden = true;
      plate.pairText.textContent = "Not paired — no keys.";
    }

    const canColour = has(device, "color");
    plate.colourRow.hidden = !canColour;
    plate.colourInput.disabled = locked;
    plate.colourGo.disabled = locked;

    /* A device that advertises nothing gets no control block at all. An empty
       one is invisible but not weightless — it still takes a row of the
       plate's gap, and the plate comes out taller than the sentence in it,
       which is how a grid of tidy plates acquires one that looks broken. */
    plate.controls.hidden = [...plate.controls.children].every((child) => child.hidden);
  }

  /** The join picker's options.
   *
   *  Rebuilt only when the set of candidates actually changed, and the chosen
   *  one is put back afterwards. A `<select>` whose options are replaced every
   *  second closes itself the instant somebody opens it, and loses whatever
   *  they had highlighted — the same class of bug as the slider, in the one
   *  control where it is not obvious because the list looks identical. */
  function fillJoin(plate, candidates, locked) {
    const drawn = JSON.stringify(candidates);
    if (drawn !== plate.joinDrawn) {
      plate.joinDrawn = drawn;
      const chosen = plate.joinPick.value;
      plate.joinPick.textContent = "";
      for (const candidate of candidates) {
        const option = document.createElement("option");
        option.value = candidate.id;
        option.textContent = candidate.name;
        plate.joinPick.append(option);
      }
      if (candidates.some((candidate) => candidate.id === chosen)) plate.joinPick.value = chosen;
    }
    const none = candidates.length === 0;
    plate.joinPick.disabled = locked || none;
    plate.join.disabled = locked || none;
  }

  /* ── going ────────────────────────────────────────────────────────── */

  $("notice-dismiss").addEventListener("click", () => { state.notice = null; renderNotice(); });

  /* One release for every slider on the page. A pointer let go anywhere means
     no pointer is down on any control, and registering this once rather than
     once per slider is what stops a device that comes and goes from leaving a
     listener behind on the window every time its plate is rebuilt. */
  window.addEventListener("pointerup", () => {
    for (const held of holds.values()) held.holding = false;
  });

  /* A tab coming back to the front polls at once rather than waiting out the
     slow interval it was hidden on. Somebody who has just switched to this tab
     is looking at it, and a fifteen-second-old house is exactly what they came
     to check. */
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) poll();
    else schedule(POLL_HIDDEN);
  });

  render();
  poll();
}
