"use strict";
/*
 * SELFHOST web admin console.
 *
 * Feature parity with the native console (crates/console), served only over
 * the WireGuard tunnel and reverse-proxied to the loopback admin API at
 * /api/*. Still written as hostile-network code: every server-sourced string
 * reaches the page through textContent (never innerHTML), service names are
 * validated before they appear in a request path, and every mutating fetch
 * carries the X-Selfhost-Console header the API requires against CSRF.
 *
 * Two of those rules earn their keep in the FILES plate more than anywhere
 * else on this page, because a directory listing is the only screen whose text
 * a stranger chooses: the rule is stated in full above `urlPath`, and it is
 * worth reading before touching that plate.
 *
 * Layout of this file:
 *   1.  Pure functions ported from the native console (present, condition,
 *       duration, name checks, form parsing). No DOM.
 *   1b. Files: the share and path grammars, sizes, sorting, and the words a
 *       refusal carries. Mirrors of `crates/identity`'s token grammar and
 *       `crates/storage`'s path encoder, deliberately identical rather than
 *       approximated.
 *   1c. The desktop, inbound: the message codec, the session states and the
 *       readings. A total parser, mirroring `crates/desk`'s in both behaviour
 *       and wording — the two consoles share no code, so the sentences live in
 *       one place.
 *   1d. The desktop, outbound: the key table, the input encoders, the four
 *       input modes and the words a refusal carries. Every conversion a
 *       keystroke or a pointer goes through is a pure function here, because a
 *       wrong scroll sign or a mis-scaled pointer is invisible from this end
 *       and looks like the far machine misbehaving.
 *   1e. The audit trail as prose: a record's fields read as sentences, because
 *       a column of `keydown:0x04` is a trail nobody audits.
 *   2.  Self-tests: `node app.js` runs them and exits non-zero on failure.
 *   3.  The application: state, polling, rendering. Browser only.
 */

/* ── 1. Pure logic, ported from crates/console/src/view and poller ──── */

/** How a wire status object should read: lamp colour, whether Start is
 *  offered, and the one-line summary. Port of view/mod.rs `present()`. */
function present(s) {
  switch (s.state) {
    case "running":
      return { status: "ok", startable: false, summary: `pid ${s.pid} · up ${duration(s.uptimeSecs)}` };
    case "starting":
      return { status: "warn", startable: false, summary: "starting" };
    case "stopping":
      return { status: "warn", startable: false, summary: "stopping" };
    case "stopped":
      return { status: "idle", startable: true, summary: "not running" };
    case "disabled":
      return { status: "idle", startable: false, summary: "disabled; start requests are refused" };
    case "exited":
      return {
        status: "idle",
        startable: true,
        summary: s.code === 0 ? "exited cleanly"
          : (s.code === null || s.code === undefined) ? "killed by a signal"
          : `exited with code ${s.code}`,
      };
    case "backoff":
      return { status: "warn", startable: false, summary: `attempt ${s.attempt} · retrying in ${duration(s.retryInSecs)}` };
    case "gave-up":
      return { status: "bad", startable: true, summary: `gave up after ${s.attempts} attempts · ${s.reason}` };
    case "unstartable":
      return { status: "bad", startable: true, summary: String(s.reason || "cannot start") };
    default:
      return { status: "idle", startable: false, summary: String(s.state || "unknown") };
  }
}

/** The state's word, in the rail's small capitals. Port of ServiceState::label. */
function stateLabel(tag) {
  const words = {
    stopped: "STOPPED", disabled: "DISABLED", starting: "STARTING",
    running: "RUNNING", stopping: "STOPPING", exited: "EXITED",
    backoff: "RESTARTING", "gave-up": "GAVE UP", unstartable: "CANNOT START",
  };
  return words[tag] || String(tag || "?").toUpperCase();
}

/** Whether a process currently exists for this status. */
function isLive(s) {
  return s.state === "starting" || s.state === "running" || s.state === "stopping";
}

/** Whether the operator needs to do something about this status. */
function needsAttention(s) {
  return s.state === "gave-up" || s.state === "unstartable";
}

/** The name to show for a service: displayName, falling back to name. */
function displayName(s) {
  return s.displayName || s.name;
}

/** Seconds in the largest two units that say something: "6d 4h", never "534240s". */
function duration(seconds) {
  const n = Math.max(0, Math.floor(Number(seconds) || 0));
  const MINUTE = 60, HOUR = 3600, DAY = 86400;
  if (n < MINUTE) return `${n}s`;
  if (n < HOUR) return `${Math.floor(n / MINUTE)}m ${n % MINUTE}s`;
  if (n < DAY) return `${Math.floor(n / HOUR)}h ${Math.floor((n % HOUR) / MINUTE)}m`;
  return `${Math.floor(n / DAY)}d ${Math.floor((n % DAY) / HOUR)}h`;
}

/** What the machine amounts to, in one line. Port of view/mod.rs `condition()`. */
function condition(link, services) {
  if (link === "connecting") return "Reaching the daemon";
  if (link === "lost") return "The daemon is not answering";
  const total = services.length;
  if (total === 0) return "No services installed";
  const wanting = services.filter(needsAttention);
  if (wanting.length === 1) return `${displayName(wanting[0])} needs attention`;
  if (wanting.length > 1) return `${wanting.length} services need attention`;
  const running = services.filter(isLive).length;
  if (running === 0) return "Nothing is running";
  if (running === total) return "Everything is running";
  return `${running} of ${total} running`;
}

/** What a rail row says under the name. Only a live service wears its restart
 *  count — a troubled state's own words already account for its restarts. */
function railSummary(s) {
  const { summary } = present(s);
  const restarts = Number(s.totalRestarts) || 0;
  if (restarts === 0 || !isLive(s)) return summary;
  return restarts === 1 ? `${summary} · 1 restart` : `${summary} · ${restarts} restarts`;
}

/** Whether a service name may appear in a request path. Port of the poller's
 *  `service_path` check: names are validated, never escaped — anything else
 *  did not come from the daemon and could address a different endpoint. */
function usableName(name) {
  return typeof name === "string"
    && name.length > 0 && name.length <= 128
    && /^[A-Za-z0-9._-]+$/.test(name)
    && name !== "." && name !== "..";
}

/** The three verdicts for one firewall opening, ported from view/exposure.rs:
 *  the firewall column is fact, the router column is the honest "cannot
 *  verify", and reachability is the weakest link of the chain. */
function exposureOf(rule) {
  const firewall = rule.applied ? ["ok", "OPEN"] : ["bad", "NOT APPLIED"];
  const router = rule.scope === "lan" ? ["ok", "LAN — NO FORWARD"]
    : rule.scope === "internet" ? ["warn", "FORWARD UNVERIFIED"]
    : ["idle", "THIS MACHINE ONLY"];
  const reach = !rule.applied ? ["bad", "BLOCKED AT HOST"]
    : rule.scope === "lan" ? ["ok", "REACHABLE ON LAN"]
    : rule.scope === "internet" ? ["warn", "INTERNET UNVERIFIED"]
    : ["idle", "THIS MACHINE ONLY"];
  return { service: String(rule.tag || ""), bind: `${rule.port}/${rule.proto}`, firewall, router, reach };
}

/** ENVIRONMENT textarea → {env, bad}: one NAME=value per line; lines without
 *  a usable name are reported, never guessed at. Whitespace around the name
 *  and value is dropped — in a form it is a typing accident, not data. */
function parseEnv(text) {
  const env = {};
  const bad = [];
  for (const line of String(text).split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    const key = eq > 0 ? trimmed.slice(0, eq).trim() : "";
    if (!key) { bad.push(trimmed); continue; }
    env[key] = trimmed.slice(eq + 1).trim();
  }
  return { env, bad };
}

/** A textarea of one-item-per-line → array, blanks dropped. */
function parseLines(text) {
  return String(text).split("\n").map((line) => line.trim()).filter((line) => line.length > 0);
}

/** Which form field a 422 problem belongs beside, or null for the general
 *  list. Server fields are dotted Rust paths like "service.restart_delay_secs". */
function problemTarget(field) {
  const path = String(field).replace(/^service\./, "");
  const map = {
    "name": "f-name", "display_name": "f-display", "description": "f-desc",
    "program": "f-program", "args": "f-args", "cwd": "f-cwd", "env": "f-env",
    "node": "f-node", "start_mode": "f-startmode", "restart": "f-restart",
    "restart_delay_secs": "f-delay", "max_restarts": "f-maxrestarts",
    "stop_timeout_secs": "f-stoptimeout", "stop_command": "f-stopcmd",
    "git.repository": "f-git-repo", "git.branch": "f-git-branch",
    "git.path": "f-git-path", "git.interval_secs": "f-git-interval",
    "git.post_pull": "f-git-postpull",
  };
  return map[path] || null;
}

/** Whether a log line's text passes the reader's filter, case-insensitively.
 *  An empty filter passes everything — the sieve is only there when asked for. */
function sift(text, query) {
  if (!query) return true;
  return String(text).toLowerCase().includes(String(query).toLowerCase());
}

/** The masthead's word for the link. A loss that has lasted wears its age,
 *  so a glance says how long the daemon has been silent. */
function linkWord(link, sinceSecs) {
  if (link === "connecting") return "CONNECTING";
  if (link !== "lost") return "CONNECTED";
  return sinceSecs >= 2 ? `UNREACHABLE · ${duration(sinceSecs)}` : "UNREACHABLE";
}

/** What the empty detail pane advises, given what the console actually knows. */
function guidance(link, serviceCount) {
  if (link === "connecting") return "Waiting for the daemon.";
  if (link === "lost") return "The daemon is not answering.";
  if (serviceCount === 0) return "Nothing is installed yet. Add a service to begin.";
  return "Choose a service on the left, or add one.";
}

/** Bytes → unpadded base64url, the alphabet WebAuthn speaks on the wire. */
function bufToB64url(bytes) {
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const bits = (bytes[i] << 16) | ((bytes[i + 1] || 0) << 8) | (bytes[i + 2] || 0);
    out += B64[(bits >> 18) & 63] + B64[(bits >> 12) & 63];
    if (i + 1 < bytes.length) out += B64[(bits >> 6) & 63];
    if (i + 2 < bytes.length) out += B64[bits & 63];
  }
  return out;
}

/** Unpadded base64url → bytes, or null for any other alphabet — a value that
 *  fails here did not come from this console's own encoder or the daemon. */
function b64urlToBuf(text) {
  const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const symbols = [];
  for (const char of String(text)) {
    if (char === "=") continue;
    const value = B64.indexOf(char);
    if (value < 0) return null;
    symbols.push(value);
  }
  if (symbols.length % 4 === 1) return null;
  const out = [];
  for (let i = 0; i < symbols.length; i += 4) {
    const group = symbols.slice(i, i + 4);
    const bits = group.reduce((acc, s, at) => acc | (s << (18 - 6 * at)), 0);
    out.push((bits >> 16) & 255);
    if (group.length > 2) out.push((bits >> 8) & 255);
    if (group.length > 3) out.push(bits & 255);
  }
  return new Uint8Array(out);
}

/** Whether a credential id may appear in a request path: base64url text of a
 *  sane length, validated (never escaped) exactly as service names are. */
function usableCredentialId(id) {
  return typeof id === "string" && id.length > 0 && id.length <= 1400
    && /^[A-Za-z0-9_-]+$/.test(id);
}

/** The default label for a passkey being registered, from the user agent —
 *  the operator sees "Mac" or "iPhone" in the list, not a credential id. */
function deviceLabel(ua) {
  const text = String(ua);
  if (/iPhone/.test(text)) return "iPhone";
  if (/iPad/.test(text)) return "iPad";
  if (/Macintosh/.test(text)) return "Mac";
  if (/Windows/.test(text)) return "Windows";
  if (/Android/.test(text)) return "Android";
  return "this device";
}

/** A passkey's registration instant as its calendar day, or an honest dash. */
function passkeyDay(unix) {
  const n = Number(unix);
  if (!Number.isFinite(n) || n <= 0) return "—";
  return new Date(n * 1000).toISOString().slice(0, 10);
}

/** The masthead's word for the push stream. Four states, because "not
 *  streaming" has three genuinely different causes and an operator debugging a
 *  console needs to tell them apart: the handshake is in flight, it was live and
 *  the link went, or this daemon has no stream to offer and the page is polling
 *  instead. */
function streamWord(stream) {
  const words = { opening: "OPENING", live: "LIVE", lost: "RECONNECTING", off: "POLLING" };
  return words[stream] || "POLLING";
}

/** The stream's lamp colour. Amber while reaching, green while live, and idle —
 *  never red — when there is no stream at all: a daemon that does not offer one
 *  is not a fault, and the page still works from its poll. */
function streamLamp(stream) {
  if (stream === "live") return "ok";
  if (stream === "opening") return "warn";
  if (stream === "lost") return "bad";
  return "idle";
}

/** How long to wait before the nth reconnection attempt, in ms: half a second,
 *  doubling, capped at fifteen. The cap matters more than the curve — a console
 *  left open on a laptop that sleeps for a weekend must not come back and find
 *  its next attempt scheduled for an hour's time. */
function backoffDelay(attempt) {
  const n = Math.max(1, Math.floor(Number(attempt) || 1));
  return Math.min(15000, 500 * Math.pow(2, n - 1));
}

/** The subprotocol list a handshake offers: the versioned protocol name, and
 *  the ticket. `Sec-WebSocket-Protocol` is the one header a page may set on a
 *  handshake, which is why the credential travels in it. */
function streamProtocols(ticket) {
  return ["selfhost.events.1", `tkt.${ticket}`];
}

/** Whether a minted ticket is the shape this daemon issues: 32 bytes of hex.
 *  Validated, never escaped, exactly as service names and credential ids are —
 *  a value that fails here did not come from the daemon and has no business in
 *  a handshake header. */
function usableTicket(ticket) {
  return typeof ticket === "string" && /^[0-9a-f]{64}$/.test(ticket);
}

/** Bytes in the units a person reads, held to three significant figures so the
 *  column does not jitter. */
function byteCount(bytes) {
  const n = Math.max(0, Math.floor(Number(bytes) || 0));
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} kB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** The diagnostics plate's one-line account of the link, which is the sentence
 *  an operator reads when the console stops feeling live. */
function diagnosisLine(stream, sinceSecs) {
  if (stream === "live") {
    return sinceSecs >= 60
      ? `live · nothing has changed for ${duration(sinceSecs)}`
      : "live · the daemon pushes every change as it happens";
  }
  if (stream === "opening") return "opening the stream";
  if (stream === "lost") return "link lost, reconnecting";
  return "no stream on this daemon · polling every second instead";
}

/* ── 1b. Files: names, paths, sizes, and the words a refusal carries ──
 *
 * ┌───────────────────────────────────────────────────────────────────┐
 * │ THE RULE FOR EVERY LINE OF THE FILES PLATE, STATED ONCE:          │
 * │                                                                   │
 * │  A stored name is HOSTILE TEXT. It arrives from a disk that SMB,  │
 * │  WebDAV, a restored backup and another operating system can all   │
 * │  write to, so it may contain `%`, `&`, `"`, `<`, `#`, `?`, a      │
 * │  newline, or a right-to-left override. Two rules, no exceptions:  │
 * │                                                                   │
 * │   1. A name reaches the page through `textContent` — NEVER        │
 * │      `innerHTML`, never a template string built into markup. A    │
 * │      directory listing is the single place in this console where  │
 * │      an XSS would land, because it is the only screen whose text  │
 * │      a stranger can choose.                                       │
 * │   2. A name reaches a URL through `urlPath` — NEVER by            │
 * │      concatenation. A name containing `%` or `#` names a          │
 * │      *different file* the moment a link is built out of it, and a │
 * │      name containing `&` or `=` rewrites the query string it is   │
 * │      put in.                                                      │
 * └───────────────────────────────────────────────────────────────────┘
 */

/** Whether a lowercase token may name a share or a machine.
 *
 *  A mirror of `parse_token` in `crates/identity/src/capability.rs`, kept
 *  deliberately identical rather than approximated: this console validates ids
 *  before putting them in a request path exactly as it validates service names,
 *  and a grammar that is merely *close* to the daemon's is a grammar that
 *  eventually disagrees with it about one character. Lowercase letters and
 *  digits, with `-`, `_` and `.` allowed between them but never at either edge
 *  and never two in a row. */
function usableToken(text, limit) {
  if (typeof text !== "string" || text.length === 0) return false;
  const characters = Array.from(text);
  if (characters.length > limit) return false;
  let previousWasSeparator = false;
  for (let at = 0; at < characters.length; at += 1) {
    const character = characters[at];
    const separator = character === "-" || character === "_" || character === ".";
    const alphanumeric = /^[a-z0-9]$/.test(character);
    if (!separator && !alphanumeric) return false;
    if (at === 0 && separator) return false;
    if (separator && previousWasSeparator) return false;
    previousWasSeparator = separator;
  }
  return !previousWasSeparator;
}

/** Whether a share id may appear in a request path. */
function usableShareId(id) {
  return usableToken(id, 32);
}

/** Whether a machine's name may appear in a request path or a query. */
function usableNodeName(name) {
  return usableToken(name, 64);
}

/** A share-relative path split into its segments, dropping the empties and the
 *  `.`s that a hand-typed path collects. The share root is the empty list. */
function pathSegments(path) {
  return String(path === null || path === undefined ? "" : path)
    .split("/")
    .filter((segment) => segment.length > 0 && segment !== ".");
}

/** The plain path back from its segments: what a person reads, and what this
 *  console keeps in its own state. Never put in a URL — that is `urlPath`. */
function plainPath(segments) {
  return segments.join("/");
}

/** A plain path as it may go in a URL: every segment percent-encoded, joined
 *  with slashes, no leading or trailing slash.
 *
 *  The mirror of `RelativePath::to_url_path` (crates/storage/src/path.rs), and
 *  the **only** way this page turns a name into a link or a query value.
 *  `encodeURIComponent` escapes a superset of what the daemon's own encoder
 *  leaves alone, and the daemon percent-decodes once on the way in, so the two
 *  agree on every name either will accept. It is also what makes a name safe in
 *  a *query string*: `&`, `=` and `#` come back as escapes, so a file called
 *  `a&b=c` cannot invent a second parameter. */
function urlPath(path) {
  return pathSegments(path).map(encodeURIComponent).join("/");
}

/** A child's plain path inside a directory, or null for a name no request can
 *  ever address.
 *
 *  A separator in a stored name is not a hypothetical: `a\b.txt` is a legal
 *  filename on ext4 and APFS, and the daemon maps `\` to `/` unconditionally so
 *  that a Mac-written share cannot become traversable the day it is served from
 *  the Windows box. The cost is that such a name is unreachable, which the
 *  listing already reports; this returns null so the console cannot build a link
 *  that would silently open something else. */
function joinPath(directory, name) {
  if (typeof name !== "string" || name.length === 0) return null;
  if (name.includes("/") || name.includes("\\") || name.includes("\0")) return null;
  if (name === "." || name === "..") return null;
  return plainPath(pathSegments(directory).concat([name]));
}

/** The directory holding this path; the share root's parent is itself. */
function parentPath(path) {
  const segments = pathSegments(path);
  segments.pop();
  return plainPath(segments);
}

/** The breadcrumb trail for a directory, outermost first, as `{label, path}`
 *  pairs. The share root is not in the trail — the plate draws it as the
 *  share's own id, which is what a person calls it. Each crumb leads to a
 *  *prefix* of the path it came from, which is the property that makes the
 *  trail a navigation rather than a decoration. */
function crumbs(path) {
  const trail = [];
  let walked = [];
  for (const segment of pathSegments(path)) {
    walked = walked.concat([segment]);
    trail.push({ label: segment, path: plainPath(walked) });
  }
  return trail;
}

/** A finite number, or null for anything else.
 *
 *  The storage API answers `null` for a reading it could not take — a share on
 *  a disk that has just been unplugged still has a quota it cannot measure —
 *  and `Number(null)` is `0`, which is the lie this exists to refuse. */
function finiteNumber(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

/** Bytes in the units a person reads, up to petabytes and held to three
 *  significant figures so a column of them does not jitter.
 *
 *  Separate from `byteCount`, which stops at megabytes because it counts what a
 *  snapshot stream has carried. A file manager routinely shows a five-gigabyte
 *  upload, and "5120.0 MB" is a number nobody reads. */
function sizeText(bytes) {
  const n = finiteNumber(typeof bytes === "string" ? Number(bytes) : bytes);
  if (n === null || n < 0) return "—";
  const units = ["B", "kB", "MB", "GB", "TB", "PB"];
  let value = Math.floor(n);
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; }
  if (unit === 0) return `${value} B`;
  const rendered = value < 10 ? value.toFixed(2) : value < 100 ? value.toFixed(1) : String(Math.round(value));
  return `${rendered} ${units[unit]}`;
}

/** A transfer rate in the same units. */
function rateText(bytesPerSecond) {
  const n = finiteNumber(bytesPerSecond);
  if (n === null || n < 0) return "—";
  return `${sizeText(n)}/s`;
}

/** A Unix instant as a local calendar day and clock time, or an honest dash.
 *
 *  A listing omits `modified` entirely for a file whose timestamp predates 1970
 *  — a real thing on a restored backup — so the absent case is ordinary and
 *  gets a dash rather than 1970. */
function whenText(unix) {
  const seconds = finiteNumber(unix);
  if (seconds === null || seconds <= 0) return "—";
  const when = new Date(seconds * 1000);
  if (Number.isNaN(when.getTime())) return "—";
  const pad = (value) => String(value).padStart(2, "0");
  return `${when.getFullYear()}-${pad(when.getMonth() + 1)}-${pad(when.getDate())}`
    + ` ${pad(when.getHours())}:${pad(when.getMinutes())}`;
}

/** Directories first, then by the chosen column. The order a person expects.
 *
 *  Directories lead whatever the column, because that is what a file manager
 *  means by sorted and the alternative — a folder buried between two files
 *  because it happens to be zero bytes — reads as a bug. The name comparison is
 *  case-insensitive with a byte-order tiebreak, matching `listing::sort` on the
 *  daemon so that the console's own default agrees with the order the server
 *  already put the entries in. Pure, and given the array rather than reading
 *  one, so the sort is a table test. */
function sortEntries(entries, column, ascending) {
  const direction = ascending ? 1 : -1;
  const folded = (name) => String(name).toLowerCase();
  const byName = (a, b) => {
    const left = folded(a.name), right = folded(b.name);
    if (left < right) return -1;
    if (left > right) return 1;
    return a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  };
  return entries.slice().sort((a, b) => {
    const directoriesFirst = Number(a.kind !== "directory") - Number(b.kind !== "directory");
    if (directoriesFirst !== 0) return directoriesFirst;
    if (column === "size") {
      const difference = (finiteNumber(a.size) || 0) - (finiteNumber(b.size) || 0);
      if (difference !== 0) return difference * direction;
      return byName(a, b);
    }
    if (column === "modified") {
      const difference = (finiteNumber(a.modified) || 0) - (finiteNumber(b.modified) || 0);
      if (difference !== 0) return difference * direction;
      return byName(a, b);
    }
    return byName(a, b) * direction;
  });
}

/** The sentence to show for a refused storage request.
 *
 *  **This is why a quota refusal does not read as "error".** The storage API
 *  answers `{"error": <stable tag>, "message": <prose>}`, where the tag is what
 *  a program switches on and the prose is what a person reads — a 507 carries
 *  *"this share is limited to N bytes and already holds M; the upload needs
 *  another K"*, which tells the operator what to delete. Showing the tag would
 *  turn that into the word "out-of-room", and showing a generic sentence of our
 *  own would throw away a number only the server knows. So the prose wins,
 *  the tag is the fallback, and an invented sentence is the last resort. */
function refusalText(status, body) {
  const message = body && typeof body.message === "string" ? body.message.trim() : "";
  if (message) return message;
  const named = body && typeof body.error === "string" ? body.error.trim() : "";
  if (named) return named;
  const code = finiteNumber(status) || 0;
  if (code === 0) return "the server could not be reached";
  if (code === 401) return "not permitted";
  if (code === 404) return "there is nothing there";
  return `the server refused this (${code})`;
}

/** What a share's gauge shows: the words, the fraction to light, and the
 *  colour. A share with no quota still shows its usage against the free space
 *  on the volume, because "how much room is left" is the question either way. */
function quotaReading(share) {
  const used = finiteNumber(share && share.usedBytes);
  const quota = finiteNumber(share && share.quotaBytes);
  const available = finiteNumber(share && share.availableBytes);
  if (used === null) {
    return { text: "usage cannot be measured", fraction: null, status: "warn" };
  }
  if (quota !== null && quota > 0) {
    const fraction = Math.min(1, used / quota);
    return {
      text: `${sizeText(used)} of ${sizeText(quota)}`,
      fraction,
      status: fraction >= 0.95 ? "bad" : fraction >= 0.85 ? "warn" : "ok",
    };
  }
  if (available !== null) {
    return { text: `${sizeText(used)} used · ${sizeText(available)} free`, fraction: null, status: "ok" };
  }
  return { text: `${sizeText(used)} used`, fraction: null, status: "ok" };
}

/** What the FILES plate says when it has no shares to draw. Absence is a
 *  sentence, never an error: a deployment with no `[[shares]]` is a correct
 *  deployment, and a caller who may read the console but hold no share is a
 *  correct caller. */
function sharesNote(shares) {
  if (shares === null) return "This deployment serves no shares.";
  if (shares.length === 0) return "No share on this box is yours to open.";
  return "";
}

/** One upload row's right-hand reading: the fraction, the bytes, and the rate
 *  once there is enough of it to mean anything. */
function transferLine(sent, total, bytesPerSecond) {
  const done = Math.max(0, finiteNumber(sent) || 0);
  const size = Math.max(0, finiteNumber(total) || 0);
  if (size === 0) return sizeText(done);
  const percent = Math.min(100, Math.floor((done / size) * 100));
  const rate = finiteNumber(bytesPerSecond);
  const speed = rate !== null && rate > 0 ? ` · ${rateText(rate)}` : "";
  return `${percent}% · ${sizeText(done)} of ${sizeText(size)}${speed}`;
}

/* ── 1c. The desktop: the wire, the states, and the readings ───────── */

/** The subprotocol list a desktop handshake offers. Same shape as the events
 *  stream's, and for the same reason: `Sec-WebSocket-Protocol` is the one
 *  header a page may set on a handshake, so the ticket travels in it. */
function deskProtocols(ticket) {
  return ["selfhost.desktop.1", `tkt.${ticket}`];
}

/** The sentence a console shows for a session state.
 *
 *  A verbatim mirror of `Notice::sentence` in `crates/desk/src/state.rs`. The
 *  two consoles share no code, and the Rust file says why these words live in
 *  one place: a difference in wording between them is a difference an operator
 *  will eventually read as a difference in behaviour. Change one, change both. */
function noticeSentence(code) {
  const sentences = {
    1: "connecting to the desktop agent",
    2: "live",
    3: "rebuilding the screen source",
    4: "secure desktop — screen and input suspended",
    5: "the interactive session moved — waiting for it to come back",
    6: "no user is logged in — nothing to capture",
    7: "the operating system has not granted screen or input access",
    8: "stopped trying — see the daemon log",
    9: "disabled by desktop.disabled",
  };
  return sentences[code] || "";
}

/** The second line: what the state means for the person watching, and what — if
 *  anything — they should do about it.
 *
 *  Additive to `noticeSentence` rather than a rewording of it, so parity with
 *  the native console is kept on the sentence that matters while the web plate
 *  can still explain that a UAC prompt is a normal Tuesday and not a fault. */
function noticeHint(code) {
  const hints = {
    1: "the agent is being reached; the first frame follows",
    2: "frames are arriving as fast as the machine changes",
    3: "the capture was lost and is being rebuilt — this is ordinary after a resolution change or a driver reset",
    4: "a UAC prompt, the lock screen or the sign-in screen is in front; Windows forbids capturing it, and the picture returns on its own when it goes",
    5: "somebody signed in at the machine, or a remote-desktop session took it over; the agent follows the interactive session when it settles",
    6: "the machine is on and nobody is signed in, so there is no desktop to show — this is a state, not a fault",
    7: "grant this machine screen recording and accessibility, then restart the agent; nothing else is wrong",
    8: "the agent stopped retrying; the daemon's own log says what it last saw",
    9: "an operator put the kill switch in place; remove desktop.disabled to allow sessions again",
  };
  return hints[code] || "";
}

/** The state's word, in the rail's small capitals. */
function noticeWord(code) {
  const words = {
    1: "STARTING", 2: "LIVE", 3: "RECOVERING", 4: "SECURE DESKTOP", 5: "SESSION MOVED",
    6: "NO USER", 7: "NOT PERMITTED", 8: "GAVE UP", 9: "STOPPED",
  };
  return words[code] || "UNKNOWN";
}

/** The state's lamp colour.
 *
 *  Three of these states are **normal conditions and are not lit as faults**: a
 *  secure desktop, a moved session and a machine nobody is signed into are all
 *  the far machine behaving correctly, and an amber lamp on each of them would
 *  train the operator to ignore amber. Red is reserved for the one state
 *  nothing will fix on its own; amber is worn by the states that want a person
 *  to do something, or that are in motion. */
function noticeLamp(code) {
  if (code === 2) return "ok";
  if (code === 1 || code === 3 || code === 7) return "warn";
  if (code === 8) return "bad";
  return "idle";
}

/** Why an input event was not delivered, in the agent's own words. A mirror of
 *  `Refusal::sentence` (crates/desk/src/wire.rs) under the same parity rule as
 *  `noticeSentence`. Nothing sends input in this phase, so the only one a
 *  viewer can currently provoke is the first — and it is worth showing rather
 *  than dropping, because it is the session saying out loud that it may watch
 *  and not touch. */
function refusalSentence(code) {
  const sentences = {
    1: "this session may view but not control",
    2: "input is disabled for this deployment",
    3: "input suspended while the secure desktop is in front",
    4: "the focused window is elevated — the platform discards input",
    5: "the session is not live",
    6: "that key has no mapping on the remote platform",
  };
  return sentences[code] || "";
}

/** What a session was actually granted, from the byte the agent echoed back.
 *  Read from `Hello`, never from what the console asked for: the point of the
 *  echo is that the screen states the truth. */
function capabilityWords(bits) {
  const held = [];
  if (bits & 0x01) held.push("VIEW");
  if (bits & 0x02) held.push("CONTROL");
  if (bits & 0x04) held.push("CLIPBOARD");
  return held;
}

/** One display, labelled as a person would name it. */
function monitorLabel(monitor) {
  const scale = finiteNumber(monitor.scalePermille);
  const zoom = scale !== null && scale !== 1000 ? ` · ${Math.round(scale / 10)}%` : "";
  return `${monitor.width}×${monitor.height}${zoom}${monitor.primary ? " · primary" : ""}`;
}

/** The plate's account of the picture on screen.
 *
 *  **The frozen frame is the failure mode this whole plate is designed
 *  against**, because it is the only one that looks like success: a session
 *  whose socket died mid-frame shows a perfect desktop that is quietly minutes
 *  old, and an operator will act on it. The difficulty is that silence is
 *  *also* what a still desktop looks like — the driver sends no frame marker at
 *  all when nothing has changed, deliberately — so age alone cannot separate
 *  "nothing is happening" from "nothing is arriving". This says both: the age
 *  is always on screen, and the wording hardens as the silence outlasts any
 *  plausible stillness. */
function frameLine(notice, sinceSecs, hasPicture) {
  if (!hasPicture) return "no frame has arrived yet";
  const age = duration(Math.max(0, Math.floor(finiteNumber(sinceSecs) || 0)));
  if (notice !== 2) return `the picture is ${age} old and held while ${noticeSentence(notice)}`;
  if (sinceSecs < 5) return "the picture is current";
  if (sinceSecs < 45) return `still · nothing has changed for ${age}`;
  return `nothing has arrived for ${age} — treat this picture as stale until it moves`;
}

/** The picture's own lamp, on the same reasoning as `frameLine`. */
function frameLamp(notice, sinceSecs, hasPicture) {
  if (!hasPicture) return "idle";
  if (notice !== 2) return "idle";
  return sinceSecs >= 45 ? "warn" : "ok";
}

/** A duration in milliseconds, as a round-trip reading. */
function msText(ms) {
  const value = finiteNumber(ms);
  if (value === null || value < 0) return "—";
  if (value < 1) return "<1 ms";
  if (value < 1000) return `${Math.round(value)} ms`;
  return `${(value / 1000).toFixed(1)} s`;
}

/** What the two round-trip numbers amount to, in one line.
 *
 *  Two numbers rather than one because a slow session has two possible causes
 *  and they want opposite responses: the tunnel between the browser and this
 *  box, and the link between this box and the machine being watched. A console
 *  that reports one number leaves the operator guessing which hop to go and
 *  look at. */
function latencyLine(hopMs, endMs) {
  const hop = finiteNumber(hopMs);
  const end = finiteNumber(endMs);
  if (hop === null && end === null) return "no round trip has been measured yet";
  if (end === null) return `${msText(hop)} to this box · the far machine has not been timed`;
  if (hop === null) return `${msText(end)} end to end`;
  const far = Math.max(0, end - hop);
  return `${msText(hop)} to this box · ${msText(far)} beyond it · ${msText(end)} end to end`;
}

/** What the console says about frames the far side dropped for want of credit.
 *
 *  A credit stall is not an error and not a dropped connection: the capture
 *  loop declined to send a frame because the link had not acknowledged enough
 *  of the last one, and the damage merges into the next frame it can afford. A
 *  remote desktop must show the present, not a backlog. So this reads as an
 *  account of a starved link rather than a failure, and says nothing at all
 *  when the number is zero. */
function stallLine(stalls) {
  const count = finiteNumber(stalls);
  if (count === null || count <= 0) return "";
  const frames = count === 1 ? "one frame" : `${count} frames`;
  return `the link is starved — ${frames} dropped rather than queued, so the picture skips instead of lagging`;
}

/** Whether a sequence number follows the last one this client presented, and
 *  how many frames went missing if it does not.
 *
 *  The driver advances its sequence only on a frame it actually sent, so a gap
 *  here is not a credit stall — it is a message this console never received,
 *  which means the surface it is holding no longer matches the far screen and
 *  the next difference will be taken against a picture it does not have. The
 *  answer is a keyframe, and the count is worth showing because a link losing
 *  messages silently is exactly the fault a "working" remote desktop hides. */
function sequenceGap(previous, sequence) {
  if (previous === null || previous === undefined) return 0;
  const expected = previous + 1;
  return sequence > expected ? sequence - expected : 0;
}

/** The pixel rectangle a tile covers, clipped to the display, or null for a
 *  coordinate outside the grid.
 *
 *  The mirror of `Grid::bounds` (crates/desk/src/tiles.rs). Tiles at the right
 *  and bottom edges are **partial and carried at their clipped size**, so the
 *  payload of an edge tile is smaller than a full one; a client that assumed a
 *  square would read past the end of every screen whose size is not a multiple
 *  of the tile edge, which is most of them. A coordinate the peer chose is
 *  refused here rather than trusted — `col` and `row` arrive unvalidated by
 *  design, because only the current geometry can bound them. */
function tileBounds(edge, width, height, col, row) {
  if (!(edge > 0) || !(width > 0) || !(height > 0)) return null;
  if (!Number.isInteger(col) || !Number.isInteger(row) || col < 0 || row < 0) return null;
  const cols = Math.ceil(width / edge);
  const rows = Math.ceil(height / edge);
  if (col >= cols || row >= rows) return null;
  const x = col * edge;
  const y = row * edge;
  return { x, y, w: Math.min(edge, width - x), h: Math.min(edge, height - y) };
}

/** A tile's payload expanded to tight BGRA, or null for anything that does not
 *  decode to exactly the pixels the grid says are there.
 *
 *  Total, like its counterpart in Rust: every input, including every random
 *  byte string, produces either a buffer of the exact expected length or null.
 *  A length is never trusted — the run-length decoder checks the room left
 *  before every run rather than after — because the alternative is a client
 *  that a peer's payload can make allocate or overrun. */
function expandTile(encoding, payload, pixels) {
  if (!Number.isInteger(pixels) || pixels <= 0) return null;
  const needed = pixels * 4;
  if (encoding === 0x00) {
    return payload.length === needed ? payload : null;
  }
  if (encoding === 0x03) {
    if (payload.length !== 4) return null;
    const out = new Uint8Array(needed);
    for (let at = 0; at < needed; at += 4) {
      out[at] = payload[0]; out[at + 1] = payload[1];
      out[at + 2] = payload[2]; out[at + 3] = payload[3];
    }
    return out;
  }
  if (encoding === 0x01) {
    if (payload.length === 0 || payload.length % 5 !== 0) return null;
    const out = new Uint8Array(needed);
    let at = 0;
    for (let read = 0; read < payload.length; read += 5) {
      const count = payload[read];
      if (count === 0) return null;
      if (at + count * 4 > needed) return null;
      for (let n = 0; n < count; n += 1) {
        out[at] = payload[read + 1]; out[at + 1] = payload[read + 2];
        out[at + 2] = payload[read + 3]; out[at + 3] = payload[read + 4];
        at += 4;
      }
    }
    return at === needed ? out : null;
  }
  return null;
}

/** Tight BGRA from the wire as the RGBA a canvas takes, forced opaque.
 *
 *  Two conversions in one pass, both deliberate. The channel swap is the wire
 *  order; the alpha is a decision: a captured screen is opaque, and several
 *  capture paths — `BitBlt` on Windows most of all — leave the alpha byte at
 *  zero because nothing ever reads it. A client that honoured that byte would
 *  present a perfectly decoded, entirely invisible desktop. */
function screenPixels(bgra) {
  const out = new Uint8ClampedArray(bgra.length);
  for (let at = 0; at + 3 < bgra.length; at += 4) {
    out[at] = bgra[at + 2];
    out[at + 1] = bgra[at + 1];
    out[at + 2] = bgra[at];
    out[at + 3] = 255;
  }
  return out;
}

/** A cursor bitmap from the wire as the RGBA a canvas takes.
 *
 *  The opposite decision to `screenPixels`, for the opposite reason: a cursor's
 *  alpha is the whole point — an I-beam is mostly transparent — and it arrives
 *  **premultiplied**, which is not what `putImageData` expects. Un-multiplying
 *  is what keeps an antialiased edge from being drawn as a dark halo. Fully
 *  transparent pixels keep no colour at all, because dividing by zero there
 *  would invent one. */
function cursorPixels(bgra) {
  const out = new Uint8ClampedArray(bgra.length);
  for (let at = 0; at + 3 < bgra.length; at += 4) {
    const alpha = bgra[at + 3];
    if (alpha === 0) continue;
    out[at] = Math.round((bgra[at + 2] * 255) / alpha);
    out[at + 1] = Math.round((bgra[at + 1] * 255) / alpha);
    out[at + 2] = Math.round((bgra[at] * 255) / alpha);
    out[at + 3] = alpha;
  }
  return out;
}

/** Decodes one message from the desktop stream, or null for anything this
 *  build cannot read.
 *
 *  Total by construction, and for the same reason the Rust codec is: these
 *  bytes come from the far end of a tunnel, and a parser that throws is a plate
 *  that goes blank on a version mismatch. Every field is read through a bounds
 *  check, every peer-chosen length is compared against the room left before it
 *  is used, and trailing bytes are refused — so a message this returns is one
 *  whose encoding this build agrees with exactly, rather than one it managed to
 *  read the beginning of.
 *
 *  Only the eight kinds that travel **to** the viewer are decoded. A `Key` or a
 *  `PointerMove` arriving here would be the machine being watched trying to
 *  type into the console, and it is refused as an unknown kind. */
function deskMessage(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 1;
  const room = (n) => at + n <= bytes.length;
  const u8 = () => { if (!room(1)) return null; const v = view.getUint8(at); at += 1; return v; };
  const u16 = () => { if (!room(2)) return null; const v = view.getUint16(at); at += 2; return v; };
  const u32 = () => { if (!room(4)) return null; const v = view.getUint32(at); at += 4; return v; };
  const i32 = () => { if (!room(4)) return null; const v = view.getInt32(at); at += 4; return v; };
  // A u64 as two words. Frame sequences and shape ids are counters on a
  // machine's uptime, so the exact integers stay well inside 2^53; the high
  // word is folded in rather than dropped so that a peer sending a large one
  // produces a large number rather than a wrapped small one.
  const u64 = () => {
    const high = u32(), low = u32();
    if (high === null || low === null) return null;
    return high * 4294967296 + low;
  };
  const flag = () => { const v = u8(); return v === null ? null : v !== 0; };
  const blob = (length) => {
    if (length === null || !room(length)) return null;
    const slice = bytes.subarray(at, at + length);
    at += length;
    return slice;
  };
  const text = (length) => {
    const raw = blob(length);
    if (raw === null) return null;
    try { return new TextDecoder().decode(raw); } catch { return ""; }
  };
  const done = (value) => (value !== null && at === bytes.length ? value : null);

  switch (bytes[0]) {
    case 0x01: {
      const protocol = u16(), edge = u16(), maxFps = u8(), capabilities = u8(), count = u8();
      if (protocol === null || edge === null || maxFps === null || capabilities === null || count === null) return null;
      const monitors = [];
      for (let n = 0; n < count; n += 1) {
        const id = u8(), originX = i32(), originY = i32();
        const width = u32(), height = u32(), scalePermille = u16(), primary = flag();
        if (id === null || originX === null || originY === null || width === null
          || height === null || scalePermille === null || primary === null) return null;
        monitors.push({ id, originX, originY, width, height, scalePermille, primary });
      }
      return done({ kind: "hello", protocol, edge, maxFps, capabilities, monitors });
    }
    case 0x02: {
      const notice = u8(), length = u16();
      if (notice === null) return null;
      const detail = text(length);
      if (detail === null || !noticeSentence(notice)) return null;
      return done({ kind: "status", notice, detail });
    }
    case 0x03: {
      const monitor = u8(), sequence = u64(), width = u32(), height = u32(), keyframe = flag();
      if (monitor === null || sequence === null || width === null || height === null || keyframe === null) return null;
      return done({ kind: "frameBegin", monitor, sequence, width, height, keyframe });
    }
    case 0x04: {
      const monitor = u8(), col = u16(), row = u16(), encoding = u8(), length = u32();
      if (monitor === null || col === null || row === null || encoding === null) return null;
      const payload = blob(length);
      if (payload === null) return null;
      return done({ kind: "tile", monitor, col, row, encoding, payload });
    }
    case 0x05: {
      const sequence = u64();
      return done(sequence === null ? null : { kind: "frameEnd", sequence });
    }
    case 0x06: {
      const x = i32(), y = i32(), visible = flag();
      if (x === null || y === null || visible === null) return null;
      return done({ kind: "cursorPos", x, y, visible });
    }
    case 0x07: {
      const shape = u64(), hotspotX = u16(), hotspotY = u16(), width = u16(), height = u16(), length = u32();
      if (shape === null || hotspotX === null || hotspotY === null || width === null || height === null) return null;
      const pixels = blob(length);
      if (pixels === null || pixels.length !== width * height * 4) return null;
      if (hotspotX >= width || hotspotY >= height) return null;
      return done({ kind: "cursorShape", shape, hotspotX, hotspotY, width, height, pixels });
    }
    case 0x08: {
      const reason = u8();
      if (reason === null || !refusalSentence(reason)) return null;
      return done({ kind: "inputRefused", reason });
    }
    default:
      return null;
  }
}

/** The one message a watching viewer sends: ask for a full frame rather than a
 *  difference.
 *
 *  It is not an input event and carries no capability — the driver honours it
 *  at `VIEW` — which is what makes it usable as an end-to-end probe: the round
 *  trip from writing this byte to the keyframe that answers it is the browser
 *  to the far machine's capture and back, measured through every hop. */
function requestFullFrame(monitor) {
  return new Uint8Array([0x46, monitor & 0xff]);
}

/* ── 1d. Driving: the keyboard, the pointer, and the modes ─────────────
 *
 *  Everything below this line is the half of the protocol that travels *to* the
 *  machine, and every function in it is pure: a browser event goes in and bytes
 *  or a sentence comes out. That is not tidiness for its own sake. The input
 *  path is the one part of this console whose faults are invisible from the
 *  console — a wrong scroll sign, a modifier released in the wrong order, a
 *  pointer scaled by the wrong number all look like "the far machine is being
 *  strange" — so the whole of it is table-tested under `node app.js`, and the
 *  functions that touch the DOM contain no arithmetic worth getting wrong.
 *
 *  # Physical keys, never characters
 *
 *  The wire speaks USB HID usage page 0x07, and `KeyboardEvent.code` is
 *  *defined* in terms of those usages, so [`hidUsage`] is a rename rather than a
 *  translation. `event.key` is never consulted: it carries the character *this*
 *  keyboard's layout produced, and the far machine applies its own layout to the
 *  physical key it is told about. Sending `key` would mean a French operator's
 *  `A` arrives on an American machine as `Q`, and `Ctrl+C` sent as a character
 *  does nothing at all on either platform. */

/** Every key this console can send, as `KeyboardEvent.code` → HID usage.
 *
 *  A verbatim mirror of `KEYS` in `crates/desk/src/keys.rs`, which is the closed
 *  table of usages that have a verified mapping on **both** platforms. A code
 *  missing here is missing there — the Rust module names the two families that
 *  are absent on purpose — and this console refuses such a key locally with the
 *  agent's own sentence rather than dropping it, because a key that quietly does
 *  nothing is diagnosed by the person pressing it as a frozen machine.
 *
 *  Change one, change both: a code added here without the matching table edit in
 *  `keys.rs` is a key the far end answers with a refusal. */
const HID_USAGE = {
  KeyA: 0x04, KeyB: 0x05, KeyC: 0x06, KeyD: 0x07, KeyE: 0x08, KeyF: 0x09, KeyG: 0x0A,
  KeyH: 0x0B, KeyI: 0x0C, KeyJ: 0x0D, KeyK: 0x0E, KeyL: 0x0F, KeyM: 0x10, KeyN: 0x11,
  KeyO: 0x12, KeyP: 0x13, KeyQ: 0x14, KeyR: 0x15, KeyS: 0x16, KeyT: 0x17, KeyU: 0x18,
  KeyV: 0x19, KeyW: 0x1A, KeyX: 0x1B, KeyY: 0x1C, KeyZ: 0x1D, Digit1: 0x1E, Digit2: 0x1F,
  Digit3: 0x20, Digit4: 0x21, Digit5: 0x22, Digit6: 0x23, Digit7: 0x24, Digit8: 0x25,
  Digit9: 0x26, Digit0: 0x27, Enter: 0x28, Escape: 0x29, Backspace: 0x2A, Tab: 0x2B,
  Space: 0x2C, Minus: 0x2D, Equal: 0x2E, BracketLeft: 0x2F, BracketRight: 0x30,
  Backslash: 0x31, Semicolon: 0x33, Quote: 0x34, Backquote: 0x35, Comma: 0x36, Period: 0x37,
  Slash: 0x38, CapsLock: 0x39, F1: 0x3A, F2: 0x3B, F3: 0x3C, F4: 0x3D, F5: 0x3E, F6: 0x3F,
  F7: 0x40, F8: 0x41, F9: 0x42, F10: 0x43, F11: 0x44, F12: 0x45, PrintScreen: 0x46,
  ScrollLock: 0x47, Pause: 0x48, Insert: 0x49, Home: 0x4A, PageUp: 0x4B, Delete: 0x4C,
  End: 0x4D, PageDown: 0x4E, ArrowRight: 0x4F, ArrowLeft: 0x50, ArrowDown: 0x51,
  ArrowUp: 0x52, NumLock: 0x53, NumpadDivide: 0x54, NumpadMultiply: 0x55,
  NumpadSubtract: 0x56, NumpadAdd: 0x57, NumpadEnter: 0x58, Numpad1: 0x59, Numpad2: 0x5A,
  Numpad3: 0x5B, Numpad4: 0x5C, Numpad5: 0x5D, Numpad6: 0x5E, Numpad7: 0x5F, Numpad8: 0x60,
  Numpad9: 0x61, Numpad0: 0x62, NumpadDecimal: 0x63, IntlBackslash: 0x64, ContextMenu: 0x65,
  NumpadEqual: 0x67, F13: 0x68, F14: 0x69, F15: 0x6A, F16: 0x6B, F17: 0x6C, F18: 0x6D,
  F19: 0x6E, F20: 0x6F, Help: 0x75, NumpadComma: 0x85, ControlLeft: 0xE0, ShiftLeft: 0xE1,
  AltLeft: 0xE2, MetaLeft: 0xE3, ControlRight: 0xE4, ShiftRight: 0xE5, AltRight: 0xE6,
  MetaRight: 0xE7,
};

/** The HID usage a `KeyboardEvent.code` names, or null for a key this
 *  vocabulary does not carry.
 *
 *  `hasOwnProperty` rather than a bare lookup because `code` is a string from an
 *  event and `"constructor"` is a string: a plain member read on an object
 *  literal would answer a function for it, and this must answer null for
 *  everything that is not a key. */
function hidUsage(code) {
  if (typeof code !== "string") return null;
  return Object.prototype.hasOwnProperty.call(HID_USAGE, code) ? HID_USAGE[code] : null;
}

/** A key's name for the held-keys strip: short, unambiguous, and a person's
 *  word rather than the DOM's.
 *
 *  The strip exists to show what is held down *on the far machine*, so its
 *  names have to be readable at a glance while something is wrong — which is
 *  exactly when `ControlLeft` reads as noise and `⌃ L` reads as a stuck Control.
 *  A code with no entry keeps its own name, which is always better than a
 *  guess. */
function keyLabel(code) {
  const named = {
    ControlLeft: "⌃ L", ControlRight: "⌃ R", ShiftLeft: "⇧ L", ShiftRight: "⇧ R",
    AltLeft: "⌥ L", AltRight: "⌥ R", MetaLeft: "⌘ L", MetaRight: "⌘ R",
    Space: "SPACE", Enter: "ENTER", Escape: "ESC", Tab: "TAB", Backspace: "⌫",
    ArrowUp: "↑", ArrowDown: "↓", ArrowLeft: "←", ArrowRight: "→",
    CapsLock: "CAPS", NumLock: "NUM", ScrollLock: "SCRL", ContextMenu: "MENU",
  };
  if (Object.prototype.hasOwnProperty.call(named, code)) return named[code];
  if (/^Key[A-Z]$/.test(code)) return code.slice(3);
  if (/^Digit[0-9]$/.test(code)) return code.slice(5);
  return String(code);
}

/** The most bytes one `Text` message may carry, mirroring `MAX_TEXT_BYTES` in
 *  `crates/desk/src/wire.rs`. The decoder there refuses a longer one outright,
 *  so a paste is split rather than truncated. */
const MAX_TEXT_BYTES = 1024;

/** A key press or release: kind `0x40`, the usage as a big-endian `u16`, and a
 *  byte for the direction. */
function keyMessage(usage, down) {
  return new Uint8Array([0x40, (usage >> 8) & 0xff, usage & 0xff, down ? 1 : 0]);
}

/** Text to type on the far machine, or null for a run that will not fit.
 *
 *  A separate message from a key for the reason `wire.rs` gives: the two take
 *  different paths on both platforms, and a shortcut sent down the unicode path
 *  does nothing at all. So this carries pasted text and nothing else — every
 *  keystroke the operator makes travels as a physical key. */
function textMessage(text) {
  const bytes = new TextEncoder().encode(String(text));
  if (bytes.length === 0 || bytes.length > MAX_TEXT_BYTES) return null;
  const out = new Uint8Array(3 + bytes.length);
  out[0] = 0x41;
  out[1] = (bytes.length >> 8) & 0xff;
  out[2] = bytes.length & 0xff;
  out.set(bytes, 3);
  return out;
}

/** A paste split into pieces the wire will accept, measured in UTF-8 bytes.
 *
 *  Split at code-point boundaries rather than at bytes, because a message
 *  carrying half of a character is a message the far end's UTF-8 reader refuses
 *  — which would lose the whole paste rather than one character of it. A
 *  multi-code-point emoji can still be divided across two messages if the
 *  boundary falls inside it; that is a cosmetic wrong on a 1 kB boundary and the
 *  alternative is a limit this console cannot honour. */
function textChunks(text, limit) {
  const encoder = new TextEncoder();
  const room = Math.max(4, Math.floor(finiteNumber(limit) || 0));
  const chunks = [];
  let held = "";
  let bytes = 0;
  for (const glyph of String(text)) {
    const size = encoder.encode(glyph).length;
    if (size > room) continue;
    if (bytes + size > room) { chunks.push(held); held = ""; bytes = 0; }
    held += glyph;
    bytes += size;
  }
  if (held !== "") chunks.push(held);
  return chunks;
}

/** The pointer's absolute position, in one display's own pixels.
 *
 *  Absolute, never relative, and the wire says why: Windows multiplies a
 *  relative delta by pointer acceleration by up to four times, so a relative
 *  protocol lands the far pointer somewhere the client cannot predict. */
function pointerMessage(monitor, x, y) {
  const out = new Uint8Array(10);
  const view = new DataView(out.buffer);
  out[0] = 0x42;
  out[1] = monitor & 0xff;
  view.setInt32(2, x | 0);
  view.setInt32(6, y | 0);
  return out;
}

/** A pointer button going down or coming up. */
function buttonMessage(code, down) {
  return new Uint8Array([0x43, code & 0xff, down ? 1 : 0]);
}

/** The wheel, in 1/120ths of a notch on each axis. */
function scrollMessage(dx, dy) {
  const out = new Uint8Array(9);
  const view = new DataView(out.buffer);
  out[0] = 0x44;
  view.setInt32(1, dx | 0);
  view.setInt32(5, dy | 0);
  return out;
}

/** Release everything held on the far machine.
 *
 *  **The single most important message this console sends.** A link that dies
 *  between a key going down and coming up leaves that key held on somebody
 *  else's machine, and a held Meta or a held mouse button makes that machine
 *  unusable to the person sitting in front of it with no indication of why. The
 *  agent applies its own release whenever the channel closes, so recovery never
 *  depends on this arriving — but this is what covers the case the agent cannot
 *  see, which is the window losing focus while the channel stays perfectly
 *  healthy. */
function releaseAllMessage() {
  return new Uint8Array([0x45]);
}

/** The wire's button code for a `MouseEvent.button`, or null for one the
 *  protocol cannot express.
 *
 *  A closed set on purpose: the wire cannot say "button 47", so nothing
 *  downstream has to decide what to do with one. */
function buttonCode(button) {
  const codes = { 0: 0x01, 1: 0x02, 2: 0x03, 3: 0x04, 4: 0x05 };
  return Object.prototype.hasOwnProperty.call(codes, button) ? codes[button] : null;
}

/** One axis of a `wheel` event converted to wire units — 1/120ths of a notch —
 *  keeping the browser's own sense of direction.
 *
 *  `deltaMode` says what the number means, and browsers disagree: a mouse in
 *  Chrome reports pixels (about a hundred to a notch), Firefox reports lines
 *  (three to a notch), and a page-mode delta is a whole screen. A console that
 *  assumed pixels would turn one Firefox notch into a hundred and twenty.
 *
 *  Returns a fraction rather than an integer, because a trackpad reports single
 *  pixels and a converter that truncated each one to zero would make a trackpad
 *  scroll nothing at all, forever. The caller keeps the remainder. */
function wheelUnits(delta, deltaMode) {
  const amount = finiteNumber(delta);
  if (amount === null) return 0;
  if (deltaMode === 1) return amount * 40;
  if (deltaMode === 2) return amount * 120;
  return amount * 1.2;
}

/** A whole `wheel` event as the wire's two axes.
 *
 *  **The sign lives here, on its own, because it is the one thing in this file
 *  that is invisible until somebody scrolls the wrong way on somebody else's
 *  machine.** The browser's positive `deltaY` means *the content scrolls down*;
 *  a wheel's positive rotation means *the wheel turned away from the user*,
 *  which scrolls up. Both platform injectors take the wheel's sense —
 *  `MOUSEEVENTF_WHEEL` on Windows and `CGEvent`'s scroll axis on macOS agree
 *  about this one — so the vertical axis is negated exactly once, here.
 *
 *  The horizontal axis is *not* negated: a positive `deltaX` and a positive wire
 *  `dx` both mean movement to the right. macOS's horizontal wheel axis runs the
 *  other way, and that is corrected in one tested line inside
 *  `crates/screen/src/synth.rs`, where the comment explaining it lives beside
 *  it. Correcting it twice would cancel out, which is why this says so. */
function scrollUnits(deltaX, deltaY, deltaMode) {
  return { dx: wheelUnits(deltaX, deltaMode), dy: -wheelUnits(deltaY, deltaMode) };
}

/** Where on the far display a pointer event landed, clipped to that display.
 *
 *  The viewport scales the far screen down to whatever room the window leaves
 *  it, so the offset inside the canvas element is divided by that scale to
 *  recover the pixel the operator is pointing at. Clipping is not decoration: a
 *  pointer released one pixel outside the canvas, or a rounding that lands on
 *  the width itself, would name a coordinate the far display does not have, and
 *  a coordinate a peer chooses is exactly the kind of number the rest of this
 *  file refuses rather than passes on. */
function remotePoint(offsetX, offsetY, scale, width, height) {
  const factor = finiteNumber(scale);
  const w = finiteNumber(width);
  const h = finiteNumber(height);
  if (factor === null || factor <= 0 || w === null || h === null || w <= 0 || h <= 0) return null;
  const x = Math.round((finiteNumber(offsetX) || 0) / factor);
  const y = Math.round((finiteNumber(offsetY) || 0) / factor);
  return {
    x: Math.min(Math.max(x, 0), Math.floor(w) - 1),
    y: Math.min(Math.max(y, 0), Math.floor(h) - 1),
  };
}

/** The two codes each modifier role can arrive under. */
const MODIFIER_SIDES = {
  Control: ["ControlLeft", "ControlRight"],
  Shift: ["ShiftLeft", "ShiftRight"],
  Alt: ["AltLeft", "AltRight"],
  Meta: ["MetaLeft", "MetaRight"],
};

/** Which held modifiers this console believes in that the browser says are not
 *  actually down.
 *
 *  **This is the fix for the classic remote-desktop fault**, and it is worth
 *  saying plainly what that fault is. A key-up is not guaranteed. Press
 *  `Cmd+Tab` and macOS switches applications on the key-down and delivers the
 *  key-up to whatever it switched to; press `Alt+Tab` on Windows and the same
 *  thing happens. The page therefore believes Meta is still held, keeps sending
 *  keys as though it were, and the far machine's every keystroke becomes a
 *  shortcut — the operator's diagnosis is "the remote machine has gone mad".
 *
 *  Blur handling covers most of it, and this covers the rest: every key event
 *  carries `getModifierState`, which is the *operating system's* opinion rather
 *  than a replay of events, so comparing the set we hold against it on every
 *  event catches a lost release at the very next keystroke. Pure, and given a
 *  plain record of the four roles so the whole of it is a table test. */
function strandedModifiers(held, pressed) {
  const stranded = [];
  for (const [role, codes] of Object.entries(MODIFIER_SIDES)) {
    if (pressed[role]) continue;
    for (const code of codes) {
      if (held.includes(code)) stranded.push(code);
    }
  }
  return stranded;
}

/** What to do about an input refusal, added to the agent's own sentence.
 *
 *  A refusal that says only what happened is half a message. `refusalSentence`
 *  is the agent's account — kept verbatim, under the parity rule that governs
 *  every sentence shared with the native console — and this is the console's
 *  answer to the question the operator actually has, which is *what do I do
 *  now*. Two of these have no action, and they say so: waiting is the action. */
function refusalAdvice(code) {
  const advice = {
    1: "ask for the keyboard — TAKE CONTROL mints a separate, freshly authorised ticket",
    2: "input is off in [desktop] on the box itself; nothing in this console can turn it on",
    3: "the prompt in front of the far screen will go on its own, and the keyboard comes back with it",
    4: "click a window that is not running as administrator; the platform never delivers synthetic input to an elevated one, by design",
    5: "wait for the state above to read LIVE",
    6: "that one physical key has no mapping on the far platform; the rest of the keyboard is unaffected",
  };
  return advice[code] || "";
}

/** The refusal banner's own words: the agent's sentence, opened so it reads as
 *  a refusal rather than as a status, and repeated for the count.
 *
 *  Silence is the thing this exists to prevent. An input event that vanishes
 *  with no word is the single fault that makes a person decide software is
 *  broken, because there is nothing to act on and nothing to report. */
function refusalHeadline(code, count) {
  const sentence = refusalSentence(code);
  if (!sentence) return "";
  const many = finiteNumber(count) || 0;
  const tally = many > 1 ? ` · ${many} events refused` : "";
  return `input refused — ${sentence}${tally}`;
}

/** Which of the four input modes a session is in.
 *
 *  Four rather than two, because "may I type" and "will my typing land" are
 *  different questions and a console that answers only the first leaves the
 *  operator pressing keys into a machine that is not accepting them. The order
 *  of the tests is the order of the truths: what the ticket granted, then what
 *  the far machine is doing, then where the keyboard is pointed. */
function inputMode(granted, live, focused) {
  if (!granted) return "watching";
  if (!live) return "suspended";
  return focused ? "driving" : "armed";
}

/** The mode's word, in the rail's small capitals. */
function modeWord(mode) {
  const words = {
    watching: "WATCHING", suspended: "INPUT SUSPENDED",
    armed: "KEYBOARD ARMED", driving: "DRIVING",
  };
  return words[mode] || "WATCHING";
}

/** The mode's sentence.
 *
 *  A person must never be unsure whether what they type is going somewhere. So
 *  each of these states what happens to the next key pressed, in the present
 *  tense, and `armed` — a keyboard granted but not aimed — gets the instruction
 *  rather than a description, because it is the only one with something to
 *  do. */
function modeLine(mode) {
  const lines = {
    watching: "This session watches the screen and cannot type on it.",
    suspended: "You hold the keyboard, and the far machine is not accepting input just now.",
    armed: "Click the screen to take the keyboard. Until you do, keys stay in this browser.",
    driving: "Every key, click and scroll goes to the far machine.",
  };
  return lines[mode] || "";
}

/** The mode's lamp. Green only while keys are actually landing — an armed
 *  keyboard that is not aimed is amber precisely because it looks like driving
 *  and is not. */
function modeLamp(mode) {
  if (mode === "driving") return "ok";
  if (mode === "armed" || mode === "suspended") return "warn";
  return "idle";
}

/** What a refused ticket mint means, and what the console should do about it.
 *
 *  Three of the daemon's answers are deliberately legible where every other
 *  refusal in that API is a uniform 401, and each wants a different response
 *  from this page, so they are told apart here rather than at the call site:
 *
 *  - `reauthenticate` — the login is older than `[desktop].reauth_window_secs`.
 *    The passkey prompt is the answer, and the session it mints is what makes
 *    the retry succeed.
 *  - `setting` — a switch in a file on the box is off. **No amount of
 *    re-authenticating will help**, and offering the biometric prompt anyway
 *    would be the console lying about what it is asking for.
 *  - a plain 401 — reachable here only after a view already worked, so it means
 *    this session may watch this machine and has not been granted a keyboard for
 *    it. Named as that rather than as "not permitted", which would read as the
 *    session having expired. */
function controlRefusal(status, body) {
  const code = finiteNumber(status) || 0;
  if (code === 403 && body && body.reauthenticate) {
    const within = finiteNumber(body.withinSecs);
    return {
      kind: "reauthenticate",
      withinSecs: within === null ? 0 : within,
      text: within === null || within <= 0
        ? "this login is too old to drive a machine"
        : `a keyboard needs a login no older than ${duration(within)}`,
    };
  }
  if (code === 403 && body && typeof body.setting === "string") {
    return {
      kind: "switch",
      setting: body.setting,
      text: `${refusalText(code, body)} — ${body.setting} is off in the configuration file on the box, `
        + "and nothing in this console can turn it on",
    };
  }
  if (code === 401) {
    return {
      kind: "denied",
      text: "the daemon refused a keyboard for this machine — this session may watch it, "
        + "and has not been granted control of it",
    };
  }
  return { kind: "error", text: refusalText(code, body) };
}

/** Whether a key event is the operator asking to paste.
 *
 *  Detected rather than forwarded, and only while the clipboard bridge is
 *  armed, because the two behaviours are genuinely different and the switch is
 *  what chooses between them. Forwarded, the chord pastes *the far machine's*
 *  clipboard, which is what a remote desktop ordinarily does. Intercepted, it
 *  sends *this browser's* clipboard, which is what the bridge is for. A console
 *  that did both at once would paste twice, and one that never intercepted
 *  would make the bridge unreachable from the keyboard.
 *
 *  `Alt` excludes the chord deliberately: `Ctrl+Alt+V` and `Cmd+Alt+V` are
 *  paste-special in a great many applications on the far machine, and those
 *  belong to the far machine. */
function pasteChord(code, ctrl, meta, alt) {
  return code === "KeyV" && !alt && (Boolean(ctrl) || Boolean(meta));
}

/** What the console says about the clipboard bridge, given how it stands.
 *
 *  # Which direction exists
 *
 *  One of the two. This console can read *the browser's* clipboard and type it
 *  into the far machine, which is the paste an operator asks for. Reading the
 *  *far machine's* clipboard back has no message on the wire at all — see
 *  `crates/desk/src/wire.rs`, which has no clipboard kind — so this plate must
 *  not present a bridge that carries nothing in that direction. Saying so is the
 *  whole of the honesty here: a toggle that looked two-way would be a promise
 *  the protocol cannot keep.
 *
 *  # Why the browser can refuse
 *
 *  `navigator.clipboard.readText()` needs a permission the operator may have
 *  denied, and it does not exist at all outside a secure context. Neither is a
 *  fault to report as an error, because there is a way through that needs no
 *  permission whatsoever: the `paste` event. Pressing the paste chord with the
 *  screen focused hands this page the clipboard directly, and that path is
 *  always available. So a refusal here is a redirection, not a failure. */
function clipboardSentence(state) {
  const lines = {
    off: "The clipboard bridge is off. Nothing on this machine's clipboard is read, "
      + "and the paste chord pastes the far machine's own clipboard.",
    ready: "The paste chord and the button send this browser's clipboard to the far machine "
      + "as typed text. Nothing travels the other way — the protocol carries no message for it.",
    asking: "Asking this browser for the clipboard…",
    refused: "The browser will not hand this page the clipboard without permission. "
      + "Press the paste chord with the screen focused instead — that path needs no permission.",
    // Observed, not theoretical: a page that is not the foreground tab can have
    // `readText()` neither resolve nor reject — the permission prompt it is
    // waiting on is never shown. A button that waits for ever on that is the
    // silent no-op this whole plate is built to avoid, so the wait has a
    // deadline and the deadline has a sentence.
    noanswer: "The browser never answered the request for the clipboard — that happens when this "
      + "tab is not the one in front. Bring it forward and try again, or press the paste chord, "
      + "which needs no permission.",
    unavailable: "This browser offers no clipboard to read from a page. "
      + "Press the paste chord with the screen focused instead.",
    empty: "There is nothing on the clipboard to send.",
    disabled: "This deployment does not share the clipboard. "
      + "[desktop].allow_clipboard is off in the configuration file on the box.",
  };
  return lines[state] || "";
}

/* ── 1e. The audit trail, as prose ─────────────────────────────────────
 *
 *  The trail is written for the capability that can type on somebody's machine,
 *  and the person who most needs to read it is the one who has just watched
 *  their own pointer move. It is written as machine-readable fields — one line
 *  per input message — and read here as sentences, because a column of
 *  `keydown:0x04` is a file nobody audits. */

/** A record's instant as a local wall clock, or an honest dash.
 *
 *  Local rather than UTC, and to the second: the question asked of an audit
 *  trail is almost always "was that me, just now", and that question is answered
 *  by a clock that agrees with the one on the wall. */
function auditWhen(unix) {
  const seconds = finiteNumber(unix);
  if (seconds === null || seconds <= 0) return "—";
  const when = new Date(seconds * 1000);
  if (Number.isNaN(when.getTime())) return "—";
  const pad = (value) => String(value).padStart(2, "0");
  return `${pad(when.getHours())}:${pad(when.getMinutes())}:${pad(when.getSeconds())}`;
}

/** A record's lamp. A refusal is the line an auditor is looking for. */
function auditLamp(outcome) {
  return outcome === "refuse" ? "bad" : "idle";
}

/** The reverse of `HID_USAGE`: a usage number back to the physical key it
 *  names, for reading a `keydown:0x04` in the trail as the key that was
 *  pressed. Built once from the one table, so the two can never disagree. */
const HID_CODES = (() => {
  const back = {};
  for (const [code, usage] of Object.entries(HID_USAGE)) back[usage] = code;
  return back;
})();

/** One record's detail as a sentence.
 *
 *  Total, and deliberately conservative: the detail is written by the daemon in
 *  a small closed vocabulary, and anything this does not recognise is shown
 *  verbatim rather than guessed at. A newer daemon writing a word this build has
 *  never seen must not have its record silently reworded into something else.
 *
 *  # What is not here, and why the trail is still worth reading
 *
 *  Never the characters typed. A `Text` message is recorded by the daemon as
 *  *how many* code units it carried, and a key by the physical key rather than
 *  the character the far machine's layout made of it — because the last thing
 *  typed on a machine is routinely a password, and a trail that quoted its
 *  subject's keystrokes would be a keylogger with a respectable filename. */
function auditDetail(detail) {
  const text = String(detail === undefined || detail === null ? "" : detail);
  const [body, refused] = text.split(" refused:");
  const suffix = refused ? ` · the platform refused it: ${refused}` : "";

  const key = /^key(down|up):0x([0-9a-fA-F]+)$/.exec(body);
  if (key) {
    const usage = parseInt(key[2], 16);
    const named = Object.prototype.hasOwnProperty.call(HID_CODES, usage)
      ? ` (${keyLabel(HID_CODES[usage])})` : "";
    return `key ${key[1] === "down" ? "down" : "up"} · usage 0x${key[2]}${named}${suffix}`;
  }
  const typed = /^text:(\d+)units$/.exec(body);
  if (typed) {
    const units = Number(typed[1]);
    return `typed ${units} ${units === 1 ? "character" : "characters"}${suffix}`;
  }
  const pointer = /^pointer:(\d+):(-?\d+),(-?\d+)$/.exec(body);
  if (pointer) return `pointer to ${pointer[2]},${pointer[3]} on display ${pointer[1]}${suffix}`;
  const button = /^button:(\w+):(down|up)$/.exec(body);
  if (button) return `${button[1].toLowerCase()} button ${button[2]}${suffix}`;
  const scroll = /^scroll:(-?\d+),(-?\d+)$/.exec(body);
  if (scroll) return `scrolled ${scroll[1]},${scroll[2]}${suffix}`;
  if (body === "release-all") return `released every held key and button${suffix}`;
  if (body === "session admitted") return "session admitted";
  const kill = /^kill-switch:(engaged|released) by:(.*)$/.exec(body);
  if (kill) return `the kill switch was ${kill[1]} by ${kill[2] || "an unnamed writer"}`;
  return `${body}${suffix}`;
}

/** Whether a record is one of the per-message input lines the trail is mostly
 *  made of.
 *
 *  One line is written per input message, so a minute of driving is thousands of
 *  pointer records, and a trail read newest-first shows a minute of pointer
 *  moves before it shows the session that opened. Separating the two lets the
 *  console hide the flood by default and *say how much it hid* — which keeps the
 *  record complete while making it readable, where a filter that quietly dropped
 *  lines would make the console a worse witness than the file. */
function isPointerNoise(record) {
  const detail = record && typeof record.detail === "string" ? record.detail : "";
  return detail.startsWith("pointer:") || detail.startsWith("scroll:");
}

/** The trail's own account of itself: how much is on screen, how much was held
 *  back, and the one thing an operator must know before trusting it.
 *
 *  `unreadable` is not a rounding error. It counts lines in `data/audit.log`
 *  that this build could not parse, and there are exactly two ways for that to
 *  happen: a newer daemon writing a format this console does not know, or a file
 *  somebody has edited. A person reading an audit trail is entitled to be told
 *  which lines were not read before they conclude anything from the ones that
 *  were. */
function trailNote(tail, hidden) {
  if (!tail) return "The audit trail has not been read yet.";
  const shown = Math.max(0, (finiteNumber(tail.returned) || 0) - Math.max(0, hidden || 0));
  const unreadable = Math.max(0, finiteNumber(tail.unreadable) || 0);
  if ((finiteNumber(tail.returned) || 0) === 0 && unreadable === 0) {
    return "Nothing has been recorded on this deployment. The trail is written when a "
      + "machine is driven, and no machine has been.";
  }
  const parts = [`${shown} ${shown === 1 ? "record" : "records"}`];
  const quiet = Math.max(0, hidden || 0);
  if (quiet > 0) parts.push(`${quiet} pointer and scroll ${quiet === 1 ? "line" : "lines"} hidden`);
  if (unreadable > 0) {
    parts.push(`${unreadable} ${unreadable === 1 ? "line" : "lines"} this build could not read `
      + "— a newer daemon, or a file that has been edited");
  }
  return parts.join(" · ");
}

/* ── 2. Self-tests: `node app.js` ───────────────────────────────────── */

if (typeof document === "undefined") {
  let failures = 0;
  const check = (label, got, want) => {
    const a = JSON.stringify(got), b = JSON.stringify(want);
    if (a !== b) { failures += 1; console.error(`FAIL ${label}: got ${a}, want ${b}`); }
  };

  check("duration seconds", duration(45), "45s");
  check("duration days", duration(534240), "6d 4h");
  check("duration minutes", duration(75), "1m 15s");

  check("running summary", present({ state: "running", pid: 4821, uptimeSecs: 534240 }).summary,
    "pid 4821 · up 6d 4h");
  check("running is not startable", present({ state: "running", pid: 1, uptimeSecs: 0 }).startable, false);
  check("signal death is named", present({ state: "exited", code: null }).summary, "killed by a signal");
  check("clean exit is named", present({ state: "exited", code: 0 }).summary, "exited cleanly");
  check("backoff summary", present({ state: "backoff", retryInSecs: 40, attempt: 3 }).summary,
    "attempt 3 · retrying in 40s");
  check("gave up is bad and startable", present({ state: "gave-up", attempts: 5, reason: "exit 1" }).status, "bad");
  check("backoff word", stateLabel("backoff"), "RESTARTING");
  check("unstartable word", stateLabel("unstartable"), "CANNOT START");

  const running = { state: "running", pid: 1, uptimeSecs: 10, totalRestarts: 3, name: "a" };
  check("a live flapper wears its count", railSummary(running).endsWith("3 restarts"), true);
  check("a troubled state does not", railSummary({ state: "backoff", retryInSecs: 9, attempt: 2, totalRestarts: 3 }).includes("restarts"), false);

  const attention = { state: "unstartable", reason: "no such file", name: "backups", totalRestarts: 0 };
  check("condition names the one service", condition("connected", [running, attention]), "backups needs attention");
  check("condition counts several", condition("connected", [attention, attention]), "2 services need attention");
  check("condition all running", condition("connected", [running]), "Everything is running");
  check("condition partial", condition("connected", [running, { state: "stopped" }, { state: "stopped" }]), "1 of 3 running");
  check("condition lost outranks services", condition("lost", [running]), "The daemon is not answering");
  check("condition empty machine", condition("connected", []), "No services installed");

  check("ordinary names pass", usableName("levelup-api.v2_1"), true);
  for (const bad of ["../health", "a/b", "a?x", "", ".", "..", "a b", "a".repeat(129)]) {
    check(`name refused: ${bad.slice(0, 12)}`, usableName(bad), false);
  }

  const env = parseEnv("A=1\n\nB = two=2\nnoequals\n=empty");
  check("env parses", env.env, { A: "1", B: "two=2" });
  check("env reports bad lines", env.bad, ["noequals", "=empty"]);
  check("lines parse", parseLines(" a \n\nb\n"), ["a", "b"]);

  check("problem maps snake_case", problemTarget("service.restart_delay_secs"), "f-delay");
  check("problem maps git", problemTarget("service.git.interval_secs"), "f-git-interval");
  check("unknown problem is general", problemTarget("service.mystery"), null);

  const open = exposureOf({ port: 443, proto: "tcp", scope: "internet", tag: "https", applied: true });
  check("internet reach is honest amber", open.reach[0], "warn");
  check("unapplied is red end to end", exposureOf({ port: 80, proto: "tcp", scope: "lan", tag: "http", applied: false }).reach[0], "bad");
  check("lan applied is green", exposureOf({ port: 80, proto: "tcp", scope: "lan", tag: "http", applied: true }).reach[0], "ok");

  check("guidance for an empty machine", guidance("connected", 0), "Nothing is installed yet. Add a service to begin.");
  check("guidance while lost", guidance("lost", 4), "The daemon is not answering.");

  check("empty sieve passes", sift("anything", ""), true);
  check("sieve is case-insensitive", sift("WARN slow query", "warn"), true);
  check("sieve refuses a miss", sift("GET /api 200", "error"), false);

  const bytes = new Uint8Array([0, 1, 250, 255]);
  check("b64url round trip", Array.from(b64urlToBuf(bufToB64url(bytes))), Array.from(bytes));
  check("b64url empty", bufToB64url(new Uint8Array(0)), "");
  check("b64url uses the url alphabet unpadded", bufToB64url(new Uint8Array([251, 255])), "-_8");
  check("the standard alphabet is refused", b64urlToBuf("a+b/"), null);
  check("a lone symbol is refused", b64urlToBuf("a"), null);

  check("credential ids pass", usableCredentialId("pQEC_Aw-"), true);
  for (const bad of ["", "a b", "a/b", "a+b", "x".repeat(1401), 7]) {
    check(`credential id refused: ${String(bad).slice(0, 12)}`, usableCredentialId(bad), false);
  }

  check("a Mac names itself", deviceLabel("Mozilla/5.0 (Macintosh; Intel Mac OS X)"), "Mac");
  check("an iPhone names itself", deviceLabel("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)"), "iPhone");
  check("an unknown agent stays generic", deviceLabel("curl/8.0"), "this device");

  check("a passkey day reads as a date", passkeyDay(86400), "1970-01-02");
  check("a missing day is a dash", passkeyDay(0), "—");
  check("a garbage day is a dash", passkeyDay("soon"), "—");

  check("link word while connecting", linkWord("connecting", 0), "CONNECTING");
  check("link word connected", linkWord("connected", 500), "CONNECTED");
  check("a fresh loss has no age", linkWord("lost", 1), "UNREACHABLE");
  check("an old loss wears its age", linkWord("lost", 95), "UNREACHABLE · 1m 35s");

  check("stream word live", streamWord("live"), "LIVE");
  check("stream word reconnecting", streamWord("lost"), "RECONNECTING");
  check("stream word opening", streamWord("opening"), "OPENING");
  check("an absent stream is not an error word", streamWord("off"), "POLLING");
  check("an unknown stream state is not an error word", streamWord("nonsense"), "POLLING");
  check("a live stream is green", streamLamp("live"), "ok");
  check("a lost stream is red", streamLamp("lost"), "bad");
  check("no stream at all is not red", streamLamp("off"), "idle");

  check("first retry is soon", backoffDelay(1), 500);
  check("retries double", backoffDelay(2), 1000);
  check("retries keep doubling", backoffDelay(5), 8000);
  check("retries are capped", backoffDelay(9), 15000);
  check("a weekend of sleep still retries within the cap", backoffDelay(400), 15000);
  check("a nonsense attempt is the first one", backoffDelay("soon"), 500);

  check("the handshake offers the protocol and the ticket",
    streamProtocols("ab"), ["selfhost.events.1", "tkt.ab"]);
  check("a real ticket passes", usableTicket("a".repeat(64)), true);
  for (const bad of ["", "A".repeat(64), "a".repeat(63), "a".repeat(65), "a b", 7, null]) {
    check(`ticket refused: ${String(bad).slice(0, 8)}`, usableTicket(bad), false);
  }

  check("bytes stay bytes", byteCount(512), "512 B");
  check("kilobytes are named", byteCount(2048), "2.0 kB");
  check("megabytes are named", byteCount(3 * 1024 * 1024), "3.0 MB");
  check("a nonsense count is zero", byteCount("lots"), "0 B");

  check("a lost link says what it is doing", diagnosisLine("lost", 0), "link lost, reconnecting");
  check("a quiet live link wears its silence",
    diagnosisLine("live", 95), "live · nothing has changed for 1m 35s");
  check("a busy live link says so",
    diagnosisLine("live", 3), "live · the daemon pushes every change as it happens");
  check("no stream explains the poll",
    diagnosisLine("off", 0), "no stream on this daemon · polling every second instead");

  /* ── files ────────────────────────────────────────────────────────── */

  check("an ordinary share id passes", usableShareId("vault"), true);
  check("separators between alphanumerics pass", usableShareId("alex-desktop_2.0"), true);
  for (const bad of ["", "Vault", "a b", "-vault", "vault-", "a--b", "a/b", "a".repeat(33), 7, null]) {
    check(`share id refused: ${String(bad).slice(0, 12)}`, usableShareId(bad), false);
  }
  check("a node name may be longer than a share id", usableNodeName("a".repeat(64)), true);
  check("but not unbounded", usableNodeName("a".repeat(65)), false);
  check("the local node names itself", usableNodeName("self"), true);

  check("segments drop the empties", pathSegments("/photos//2026/"), ["photos", "2026"]);
  check("segments drop a bare dot", pathSegments("photos/./x"), ["photos", "x"]);
  check("the share root is no segments", pathSegments(""), []);
  check("a url path encodes every segment", urlPath("holiday snaps/a&b=c.txt"),
    "holiday%20snaps/a%26b%3Dc.txt");
  check("a percent in a name survives the round trip", urlPath("100%.txt"), "100%25.txt");
  check("a hash cannot truncate a link", urlPath("a#b"), "a%23b");
  check("a quote cannot escape an attribute", urlPath('say "hi"'), "say%20%22hi%22");
  check("a newline is encoded, not sent raw", urlPath("two\nlines"), "two%0Alines");
  check("joining builds a plain path", joinPath("photos", "a&b.txt"), "photos/a&b.txt");
  check("joining at the root has no leading slash", joinPath("", "x"), "x");
  check("a name holding a separator is unaddressable", joinPath("photos", "a\\b.txt"), null);
  check("a name holding a slash is unaddressable", joinPath("photos", "a/b"), null);
  check("dot-dot is never a name", joinPath("photos", ".."), null);
  check("the parent of a leaf", parentPath("a/b/c"), "a/b");
  check("the root's parent is the root", parentPath(""), "");
  check("crumbs lead to prefixes", crumbs("a/b/c").map((c) => c.path), ["a", "a/b", "a/b/c"]);
  check("crumbs label with the name as written", crumbs("a b/c&d")[1].label, "c&d");
  check("the root has no crumbs", crumbs(""), []);

  check("bytes stay bytes in a listing", sizeText(512), "512 B");
  check("a kilobyte is named", sizeText(1024), "1.00 kB");
  check("five gigabytes read as five", sizeText(5 * 1024 * 1024 * 1024), "5.00 GB");
  check("a hundred megabytes drops its decimals", sizeText(100 * 1024 * 1024), "100 MB");
  check("an unmeasured size is a dash", sizeText(null), "—");
  check("a rate wears its unit", rateText(1024 * 1024), "1.00 MB/s");
  check("an unmeasured date is a dash", whenText(0), "—");
  check("a date reads as a date", /^\d{4}-\d\d-\d\d \d\d:\d\d$/.test(whenText(1700000000)), true);

  const listing = [
    { name: "beta.txt", kind: "file", size: 10, modified: 300 },
    { name: "Alpha", kind: "directory", size: 0, modified: 100 },
    { name: "alpha.txt", kind: "file", size: 900, modified: 200 },
  ];
  check("directories lead whatever the column",
    sortEntries(listing, "size", true).map((e) => e.name), ["Alpha", "beta.txt", "alpha.txt"]);
  check("names sort case-insensitively",
    sortEntries(listing, "name", true).map((e) => e.name), ["Alpha", "alpha.txt", "beta.txt"]);
  check("descending reverses the files only",
    sortEntries(listing, "name", false).map((e) => e.name), ["Alpha", "beta.txt", "alpha.txt"]);
  check("newest first is a real column",
    sortEntries(listing, "modified", false).map((e) => e.name), ["Alpha", "beta.txt", "alpha.txt"]);
  check("sorting does not disturb the caller's array", listing[0].name, "beta.txt");

  check("a quota refusal shows the server's own prose",
    refusalText(507, { error: "out-of-room", message: "this share is limited to 100 bytes and already holds 90; the upload needs another 40" }),
    "this share is limited to 100 bytes and already holds 90; the upload needs another 40");
  check("a refusal with only a tag shows the tag", refusalText(409, { error: "occupied" }), "occupied");
  check("a silent refusal is still a sentence", refusalText(500, null), "the server refused this (500)");
  check("an unreachable server says so", refusalText(0, null), "the server could not be reached");

  check("a share under its quota is green", quotaReading({ usedBytes: 10, quotaBytes: 100 }).status, "ok");
  check("a nearly full share is amber", quotaReading({ usedBytes: 90, quotaBytes: 100 }).status, "warn");
  check("a full share is red", quotaReading({ usedBytes: 99, quotaBytes: 100 }).status, "bad");
  check("a quota is drawn as a fraction", quotaReading({ usedBytes: 25, quotaBytes: 100 }).fraction, 0.25);
  check("no quota falls back to free space",
    quotaReading({ usedBytes: 1024, quotaBytes: null, availableBytes: 2048 }).text, "1.00 kB used · 2.00 kB free");
  check("an unmeasurable share says so, and is not reported as empty",
    quotaReading({ usedBytes: null, quotaBytes: 100 }).text, "usage cannot be measured");

  check("no shares configured is a sentence", sharesNote(null), "This deployment serves no shares.");
  check("no shares of one's own is a different sentence",
    sharesNote([]), "No share on this box is yours to open.");
  check("shares present need no sentence", sharesNote([{ id: "vault" }]), "");
  check("a transfer reads as a fraction", transferLine(512, 1024, 0), "50% · 512 B of 1.00 kB");
  check("a moving transfer wears its rate", transferLine(512, 1024, 2048), "50% · 512 B of 1.00 kB · 2.00 kB/s");
  check("a sizeless transfer reads as bytes", transferLine(512, 0, 0), "512 B");

  /* ── the desktop ──────────────────────────────────────────────────── */

  check("a desktop handshake offers the protocol and the ticket",
    deskProtocols("ab"), ["selfhost.desktop.1", "tkt.ab"]);
  check("the live sentence is the daemon's own", noticeSentence(2), "live");
  check("a secure desktop is stated, not warned about",
    noticeSentence(4), "secure desktop — screen and input suspended");
  check("nobody logged in is a state", noticeSentence(6), "no user is logged in — nothing to capture");
  check("an unknown notice has no sentence", noticeSentence(99), "");
  check("every notice carries a hint", [1, 2, 3, 4, 5, 6, 7, 8, 9].every((c) => noticeHint(c).length > 0), true);
  check("live is green", noticeLamp(2), "ok");
  check("a secure desktop is not an alarm", noticeLamp(4), "idle");
  check("nobody logged in is not an alarm", noticeLamp(6), "idle");
  check("a moved session is not an alarm", noticeLamp(5), "idle");
  check("a missing permission wants a person", noticeLamp(7), "warn");
  check("giving up is the one red state", noticeLamp(8), "bad");
  check("a view-only session says so", refusalSentence(1), "this session may view but not control");
  check("an unknown refusal has no sentence", refusalSentence(99), "");
  check("capabilities are read from the echo", capabilityWords(0x03), ["VIEW", "CONTROL"]);
  check("a watching session holds one", capabilityWords(0x01), ["VIEW"]);
  check("a monitor labels itself",
    monitorLabel({ width: 2560, height: 1440, scalePermille: 2000, primary: true }),
    "2560×1440 · 200% · primary");
  check("an unscaled monitor says nothing about scale",
    monitorLabel({ width: 1920, height: 1080, scalePermille: 1000, primary: false }), "1920×1080");

  check("no picture is stated plainly", frameLine(2, 0, false), "no frame has arrived yet");
  check("a fresh picture is current", frameLine(2, 1, true), "the picture is current");
  check("a still desktop is not an alarm", frameLine(2, 20, true), "still · nothing has changed for 20s");
  check("a long silence is called out",
    frameLine(2, 90, true), "nothing has arrived for 1m 30s — treat this picture as stale until it moves");
  check("a suspended picture explains itself",
    frameLine(4, 5, true), "the picture is 5s old and held while secure desktop — screen and input suspended");
  check("a still desktop keeps a green lamp", frameLamp(2, 20, true), "ok");
  check("a frozen one goes amber", frameLamp(2, 90, true), "warn");
  check("a suspended one is neither", frameLamp(4, 90, true), "idle");

  check("a sub-millisecond trip is named", msText(0.4), "<1 ms");
  check("a round trip reads in ms", msText(12.6), "13 ms");
  check("a slow trip reads in seconds", msText(2400), "2.4 s");
  check("an unmeasured trip is a dash", msText(null), "—");
  check("both hops are attributable",
    latencyLine(20, 95), "20 ms to this box · 75 ms beyond it · 95 ms end to end");
  check("one hop measured says which", latencyLine(20, null), "20 ms to this box · the far machine has not been timed");
  check("no hop measured says so", latencyLine(null, null), "no round trip has been measured yet");
  check("a healthy link says nothing about stalls", stallLine(0), "");
  check("a starved link explains itself",
    stallLine(1), "the link is starved — one frame dropped rather than queued, so the picture skips instead of lagging");
  check("no previous frame is no gap", sequenceGap(null, 9), 0);
  check("the next frame is no gap", sequenceGap(4, 5), 0);
  check("a jump is counted", sequenceGap(4, 9), 4);
  check("a repeat is not a gap", sequenceGap(9, 9), 0);

  check("a whole tile fills its square", tileBounds(64, 128, 128, 1, 1), { x: 64, y: 64, w: 64, h: 64 });
  check("an edge tile is clipped, not padded",
    tileBounds(64, 100, 70, 1, 1), { x: 64, y: 64, w: 36, h: 6 });
  check("a coordinate past the grid is refused", tileBounds(64, 128, 128, 2, 0), null);
  check("a negative coordinate is refused", tileBounds(64, 128, 128, -1, 0), null);
  check("a grid over no display is refused", tileBounds(64, 0, 0, 0, 0), null);

  const raw = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
  check("raw pixels pass through", Array.from(expandTile(0x00, raw, 2)), Array.from(raw));
  check("raw of the wrong length is refused", expandTile(0x00, raw, 3), null);
  check("a solid tile repeats its colour",
    Array.from(expandTile(0x03, new Uint8Array([9, 8, 7, 6]), 2)), [9, 8, 7, 6, 9, 8, 7, 6]);
  check("a solid tile carries exactly one pixel", expandTile(0x03, raw, 2), null);
  check("runs expand",
    Array.from(expandTile(0x01, new Uint8Array([2, 1, 2, 3, 4, 1, 5, 6, 7, 8]), 3)),
    [1, 2, 3, 4, 1, 2, 3, 4, 5, 6, 7, 8]);
  check("a run past the tile is refused", expandTile(0x01, new Uint8Array([9, 1, 2, 3, 4]), 3), null);
  check("a zero-length run is refused", expandTile(0x01, new Uint8Array([0, 1, 2, 3, 4]), 1), null);
  check("a truncated run record is refused", expandTile(0x01, new Uint8Array([1, 1, 2, 3]), 1), null);
  check("runs that fall short are refused", expandTile(0x01, new Uint8Array([1, 1, 2, 3, 4]), 2), null);
  check("an unknown encoding is refused", expandTile(0x7f, raw, 2), null);
  check("a tile of no pixels is refused", expandTile(0x00, new Uint8Array(0), 0), null);

  check("the wire's blue becomes the canvas's blue",
    Array.from(screenPixels(new Uint8Array([255, 0, 0, 0]))), [0, 0, 255, 255]);
  check("a screen is drawn opaque whatever the alpha byte says",
    screenPixels(new Uint8Array([1, 2, 3, 0]))[3], 255);
  check("a transparent cursor pixel keeps no colour",
    Array.from(cursorPixels(new Uint8Array([200, 200, 200, 0]))), [0, 0, 0, 0]);
  check("a half-transparent cursor pixel is un-premultiplied",
    Array.from(cursorPixels(new Uint8Array([64, 64, 64, 128]))), [128, 128, 128, 128]);

  // A local encoder, so the decoder is tested against bytes rather than against
  // itself. Big-endian throughout, exactly as `crates/desk/src/wire.rs` writes.
  const wire = (...parts) => {
    const bytes = [];
    for (const [width, value] of parts) {
      for (let shift = width - 1; shift >= 0; shift -= 1) {
        bytes.push(Math.floor(value / Math.pow(256, shift)) & 0xff);
      }
    }
    return new Uint8Array(bytes);
  };
  const hello = deskMessage(wire([1, 0x01], [2, 1], [2, 64], [1, 30], [1, 0x01], [1, 1],
    [1, 0], [4, 0], [4, 0], [4, 1920], [4, 1080], [2, 1000], [1, 1]));
  check("a hello names the protocol", hello && hello.protocol, 1);
  check("a hello carries its tile edge", hello && hello.edge, 64);
  check("a hello carries what was granted", hello && capabilityWords(hello.capabilities), ["VIEW"]);
  check("a hello carries every display", hello && hello.monitors.length, 1);
  check("a hello's display carries its size", hello && hello.monitors[0].width, 1920);
  check("a hello with a short monitor list is refused",
    deskMessage(wire([1, 0x01], [2, 1], [2, 64], [1, 30], [1, 1], [1, 2], [1, 0], [4, 0], [4, 0], [4, 1], [4, 1], [2, 1000], [1, 0])), null);
  check("a hello with trailing bytes is refused",
    deskMessage(wire([1, 0x01], [2, 1], [2, 64], [1, 30], [1, 1], [1, 0], [1, 0])), null);

  const status = deskMessage(new Uint8Array([0x02, 0x04, 0, 2, 0x68, 0x69]));
  check("a status carries its notice", status && status.notice, 4);
  check("a status carries its detail", status && status.detail, "hi");
  check("a status naming an unknown notice is refused",
    deskMessage(new Uint8Array([0x02, 0x63, 0, 0])), null);

  const begin = deskMessage(wire([1, 0x03], [1, 0], [8, 7], [4, 1920], [4, 1080], [1, 1]));
  check("a frame begins with its sequence", begin && begin.sequence, 7);
  check("a keyframe says so", begin && begin.keyframe, true);
  check("a frame ends with its sequence", deskMessage(wire([1, 0x05], [8, 7])).sequence, 7);

  const tile = deskMessage(wire([1, 0x04], [1, 0], [2, 3], [2, 4], [1, 0x03], [4, 4], [4, 0x01020304]));
  check("a tile names its cell", tile && [tile.col, tile.row], [3, 4]);
  check("a tile carries its payload", tile && Array.from(tile.payload), [1, 2, 3, 4]);
  check("a tile whose payload is shorter than declared is refused",
    deskMessage(wire([1, 0x04], [1, 0], [2, 0], [2, 0], [1, 0x00], [4, 8], [4, 0])), null);

  const pos = deskMessage(wire([1, 0x06], [4, 0xfffffff6], [4, 20], [1, 1]));
  check("a negative cursor position stays negative", pos && pos.x, -10);
  check("a hidden cursor says so", deskMessage(wire([1, 0x06], [4, 0], [4, 0], [1, 0])).visible, false);

  const shape = deskMessage(wire([1, 0x07], [8, 5], [2, 0], [2, 0], [2, 1], [2, 1], [4, 4], [4, 0]));
  check("a cursor shape carries its id", shape && shape.shape, 5);
  check("a cursor bitmap of the wrong length is refused",
    deskMessage(wire([1, 0x07], [8, 5], [2, 0], [2, 0], [2, 2], [2, 2], [4, 4], [4, 0])), null);
  check("a hotspot outside the bitmap is refused",
    deskMessage(wire([1, 0x07], [8, 5], [2, 4], [2, 0], [2, 1], [2, 1], [4, 4], [4, 0])), null);

  check("a refusal carries its reason", deskMessage(new Uint8Array([0x08, 0x01])).reason, 1);
  check("an unknown refusal code is refused", deskMessage(new Uint8Array([0x08, 0x63])), null);
  check("a key from the far machine is not a message this console reads",
    deskMessage(new Uint8Array([0x40, 0, 4, 1])), null);
  check("an empty frame is refused", deskMessage(new Uint8Array(0)), null);
  check("a message this build does not know is refused", deskMessage(new Uint8Array([0x7f])), null);
  // The property the Rust codec's fuzz-shaped test keeps, kept here too: every
  // byte string decodes or is refused, and none of them throws.
  let survived = true;
  for (let seed = 0; seed < 3000; seed += 1) {
    const length = seed % 24;
    const bytes = new Uint8Array(length);
    for (let at = 0; at < length; at += 1) bytes[at] = (seed * 31 + at * 17) & 0xff;
    try { deskMessage(bytes); } catch { survived = false; }
  }
  check("no byte string makes the decoder throw", survived, true);

  check("the full-frame request names its display", Array.from(requestFullFrame(1)), [0x46, 1]);

  /* ── driving: the keyboard, the pointer and the modes ─────────────── */

  check("a letter is the usage the hardware reports", hidUsage("KeyA"), 0x04);
  check("the two Alts are different keys", [hidUsage("AltLeft"), hidUsage("AltRight")], [0xE2, 0xE6]);
  check("a keypad digit is not a row digit", [hidUsage("Numpad4"), hidUsage("Digit4")], [0x5C, 0x21]);
  check("a key outside the vocabulary is refused, not guessed", hidUsage("IntlRo"), null);
  // The lookup is a member read on an object literal, so every inherited name
  // has to answer null or a page could send `constructor` as a keystroke.
  check("an inherited property is not a key", hidUsage("constructor"), null);
  check("a missing code is not a key", hidUsage(undefined), null);
  check("the table is the size the Rust table is", Object.keys(HID_USAGE).length, 116);
  check("no two codes share a usage", new Set(Object.values(HID_USAGE)).size, 116);

  check("a held Control reads as a Control", keyLabel("ControlLeft"), "⌃ L");
  check("a letter reads as the letter", keyLabel("KeyQ"), "Q");
  check("a key with no short name keeps its own", keyLabel("F13"), "F13");

  check("a key press is the usage and a direction",
    Array.from(keyMessage(0x04, true)), [0x40, 0x00, 0x04, 1]);
  check("a modifier's usage does not lose its high byte",
    Array.from(keyMessage(0xE3, false)), [0x40, 0x00, 0xE3, 0]);
  check("a button carries its code", Array.from(buttonMessage(0x03, true)), [0x43, 0x03, 1]);
  check("release-all is one byte", Array.from(releaseAllMessage()), [0x45]);
  check("a scroll is two signed words",
    Array.from(scrollMessage(0, -120)), [0x44, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0x88]);
  check("a pointer names its display and its pixel",
    Array.from(pointerMessage(1, 2, 3)), [0x42, 1, 0, 0, 0, 2, 0, 0, 0, 3]);
  check("a negative pointer coordinate survives the wire",
    Array.from(pointerMessage(0, -1, 0)).slice(2, 6), [0xff, 0xff, 0xff, 0xff]);

  check("text is length-prefixed", Array.from(textMessage("hi")), [0x41, 0, 2, 0x68, 0x69]);
  check("text is measured in bytes, not characters", textMessage("é")[2], 2);
  check("empty text is not a message", textMessage(""), null);
  check("text longer than the wire allows is refused", textMessage("a".repeat(1025)), null);
  check("a paste that fits is one message", textChunks("hello", 1024), ["hello"]);
  check("a long paste is divided", textChunks("abcdef", 4), ["abcd", "ef"]);
  // A boundary inside a multi-byte character would make a message the far
  // end's UTF-8 reader refuses, losing the whole paste rather than one
  // character of it.
  check("a paste never splits a character", textChunks("ééé", 5), ["éé", "é"]);
  check("nothing to paste is no messages", textChunks("", 1024), []);

  check("the primary button is the primary button", buttonCode(0), 0x01);
  check("the wheel button is not the secondary", [buttonCode(1), buttonCode(2)], [0x02, 0x03]);
  check("a button the wire cannot express is refused", buttonCode(9), null);

  check("a hundred pixels is one notch", wheelUnits(100, 0), 120);
  check("a line-mode browser is not a hundred and twenty notches", wheelUnits(3, 1), 120);
  check("a page-mode scroll is a whole notch", wheelUnits(1, 2), 120);
  check("a trackpad's single pixel is not rounded away here", wheelUnits(1, 0) !== 0, true);
  check("a nonsense delta is no scroll", wheelUnits("lots", 0), 0);
  // The sign is the one thing here that is invisible until somebody scrolls the
  // wrong way on somebody else's machine: a browser's positive deltaY scrolls
  // the content down, and a wheel's positive rotation scrolls it up.
  check("scrolling down turns the wheel backwards", scrollUnits(0, 100, 0).dy, -120);
  check("scrolling right stays right", scrollUnits(100, 0, 0).dx, 120);

  check("a pointer in a viewport shrunk by half doubles",
    remotePoint(100, 50, 0.5, 1920, 1080), { x: 200, y: 100 });
  check("a pointer at the far edge stays on the display",
    remotePoint(4000, 4000, 1, 1920, 1080), { x: 1919, y: 1079 });
  check("a pointer off the near edge stays on the display",
    remotePoint(-8, -8, 1, 1920, 1080), { x: 0, y: 0 });
  check("a viewport with no scale is no pointer", remotePoint(1, 1, 0, 1920, 1080), null);

  check("a modifier the operating system says is up is released",
    strandedModifiers(["MetaLeft", "KeyA"], { Control: false, Shift: false, Alt: false, Meta: false }),
    ["MetaLeft"]);
  check("a modifier that really is held is left alone",
    strandedModifiers(["ShiftLeft"], { Control: false, Shift: true, Alt: false, Meta: false }), []);
  check("both sides of a stranded role are released",
    strandedModifiers(["ControlLeft", "ControlRight"], { Control: false, Shift: false, Alt: false, Meta: false }),
    ["ControlLeft", "ControlRight"]);
  check("an ordinary key is never released by this",
    strandedModifiers(["KeyA"], { Control: false, Shift: false, Alt: false, Meta: false }), []);

  check("a refusal opens as a refusal",
    refusalHeadline(4, 1), "input refused — the focused window is elevated — the platform discards input");
  check("repeated refusals are counted rather than repeated",
    refusalHeadline(1, 12).endsWith("· 12 events refused"), true);
  check("an unknown refusal is not a sentence", refusalHeadline(99, 1), "");
  check("an elevated window says what to click",
    refusalAdvice(4).startsWith("click a window that is not running as administrator"), true);
  check("a deployment switch says it is not this console's to change",
    refusalAdvice(2).includes("nothing in this console can turn it on"), true);

  check("no keyboard is watching", inputMode(false, true, true), "watching");
  check("a keyboard the far machine will not take is suspended", inputMode(true, false, true), "suspended");
  check("a keyboard nobody has aimed is armed", inputMode(true, true, false), "armed");
  check("a keyboard aimed at a live machine is driving", inputMode(true, true, true), "driving");
  // The one that matters: an armed keyboard looks like a driving one and is
  // not, so it must never wear the green lamp.
  check("only driving is green", [modeLamp("driving"), modeLamp("armed"), modeLamp("watching")],
    ["ok", "warn", "idle"]);
  check("driving says where the keys go", modeLine("driving"), "Every key, click and scroll goes to the far machine.");
  check("armed says what to do about it", modeLine("armed").startsWith("Click the screen"), true);

  const stale = controlRefusal(403, { error: "too old", reauthenticate: true, withinSecs: 120 });
  check("a stale login asks for the passkey", stale.kind, "reauthenticate");
  check("a stale login names the window", stale.text, "a keyboard needs a login no older than 2m 0s");
  const shut = controlRefusal(403, { error: "this deployment does not allow input", setting: "[desktop].allow_input" });
  check("a switch in a file is not a re-authentication", shut.kind, "switch");
  check("a switch names the setting and says it is not ours",
    shut.text, "this deployment does not allow input — [desktop].allow_input is off in the "
      + "configuration file on the box, and nothing in this console can turn it on");
  check("a plain refusal is a grant this session lacks", controlRefusal(401, null).kind, "denied");
  check("a refused keyboard does not read as a lost session",
    controlRefusal(401, null).text.includes("may watch it"), true);
  check("anything else keeps the server's own words",
    controlRefusal(500, { message: "the daemon fell over" }).text, "the daemon fell over");

  check("either paste chord is the paste chord",
    [pasteChord("KeyV", true, false, false), pasteChord("KeyV", false, true, false)], [true, true]);
  check("paste-special belongs to the far machine", pasteChord("KeyV", true, false, true), false);
  check("a bare V is a letter", pasteChord("KeyV", false, false, false), false);
  check("another chord is not the paste chord", pasteChord("KeyC", true, false, false), false);

  check("a clipboard nobody armed says so", clipboardSentence("off").startsWith("The clipboard bridge is off"), true);
  check("the clipboard is honest about the direction it cannot carry",
    clipboardSentence("ready").includes("Nothing travels the other way"), true);
  check("a refused permission is a redirection, not a failure",
    clipboardSentence("refused").includes("needs no permission"), true);
  // Observed in a real browser: a background tab's `readText()` neither
  // resolves nor rejects, so a paste that waits on it silently does nothing.
  check("a browser that never answers is not silence",
    clipboardSentence("noanswer").includes("never answered"), true);
  check("an unknown clipboard state says nothing rather than something wrong",
    clipboardSentence("mystery"), "");

  check("an audit instant is a wall clock", auditWhen(0), "—");
  check("a refusal is the line an auditor wants", [auditLamp("refuse"), auditLamp("allow")], ["bad", "idle"]);
  check("a key press reads as a key press", auditDetail("keydown:0x04"), "key down · usage 0x04 (A)");
  check("a key with no name in this build is still legible",
    auditDetail("keyup:0x99"), "key up · usage 0x99");
  check("typing is counted, never quoted", auditDetail("text:12units"), "typed 12 characters");
  check("one character is not 1 characters", auditDetail("text:1units"), "typed 1 character");
  check("a pointer names its display", auditDetail("pointer:1:100,200"), "pointer to 100,200 on display 1");
  check("a button reads as a button", auditDetail("button:Left:down"), "left button down");
  check("a platform refusal is appended, not swallowed",
    auditDetail("keydown:0x04 refused:elevated-window"),
    "key down · usage 0x04 (A) · the platform refused it: elevated-window");
  check("release-all is the message it is", auditDetail("release-all"), "released every held key and button");
  check("the kill switch reads as prose", auditDetail("kill-switch:engaged by:alex"),
    "the kill switch was engaged by alex");
  // A daemon newer than this console writes words this build has never seen.
  // Showing them verbatim is the only honest answer; rewording a record is
  // inventing evidence.
  check("an unknown detail is shown as written", auditDetail("something:new"), "something:new");
  check("no detail is no sentence", auditDetail(undefined), "");
  check("a pointer line is the flood", isPointerNoise({ detail: "pointer:0:1,1" }), true);
  check("a keystroke is not the flood", isPointerNoise({ detail: "keydown:0x04" }), false);
  check("an empty trail is a sentence, not an error",
    trailNote({ returned: 0, unreadable: 0 }, 0).startsWith("Nothing has been recorded"), true);
  check("hidden lines are counted rather than dropped",
    trailNote({ returned: 10, unreadable: 0 }, 7), "3 records · 7 pointer and scroll lines hidden");
  check("a line this build could not read is said out loud",
    trailNote({ returned: 1, unreadable: 2 }, 0).includes("2 lines this build could not read"), true);

  if (failures > 0) { process.exitCode = 1; console.error(`${failures} failure(s)`); }
  else console.log("all self-tests passed");
} else {
  boot();
}

/* ── 3. The application ─────────────────────────────────────────────── */

/** Wires the page up and decides login vs console from the session. */
function boot() {

  /* How often the daemon is asked, in ms.
   *
   * The half-second poll this console was built on is gone: the daemon now
   * pushes its snapshot the moment anything changes, over one WebSocket that
   * costs nothing while nothing happens. What is left is a safety net — a full
   * refresh every ten seconds while the stream is live, so a stream that has
   * quietly stopped delivering cannot leave a stale screen looking live for
   * ever. When there is no stream (an older daemon, or one that refuses),
   * POLL_DEGRADED is this page's only source of news and is fast for that
   * reason, and the DIAGNOSTICS plate says which of the two is happening rather
   * than leaving it to be guessed from how the page feels. */
  const POLL_SAFETY = 10000;
  const POLL_DEGRADED = 1000;
  const POLL_SLOW = 30000;
  /* How often the selected service's log tail is fetched while streaming.
   * Logs are a per-selection cursor, not part of a machine-wide snapshot, so
   * they keep a poll of their own until the mux gives them a channel. */
  const POLL_LOGS = 1000;
  /* How many log lines are asked for per fetch, and kept on the page. */
  const LOG_BATCH = 500;
  const LOG_RING = 4000;

  /** Everything the page knows. The DOM is a function of this and nothing else. */
  const state = {
    view: "loading",            // "login" | "console"
    link: "connecting",         // "connecting" | "connected" | "lost"
    services: [],
    selected: null,             // tracked by NAME, never by index
    spec: null,                 // fetched definition for the selected service
    firewall: null,             // last firewall state, or null → panel hidden
    logs: { service: "", nextSeq: 0, missed: 0, count: 0 },
    notice: null,               // { kind: "done"|"problem", text }
    formOpen: false,
    passkeys: null,             // registered passkeys, or null → panel hidden
    user: null,                 // who this session belongs to, from the daemon
    stream: "off",              // "off" | "opening" | "live" | "lost"
    // The two subsystem plates use three states rather than two, because
    // "nobody has asked yet" and "the daemon answered, and there are none" are
    // different screens: the first shows nothing, and the second says so in
    // words. A plate that errors where the honest answer is a sentence is the
    // thing both of these exist to avoid.
    shares: undefined,          // undefined → unasked · null → none served · array → what this caller may open
    share: null,                // the chosen share's id
    dir: "",                    // the directory inside it, as a plain path
    listing: null,              // the directory's contents, or null while it is being fetched
    listingNote: "",            // why the listing is not on screen, in the server's own words
    desktop: undefined,         // undefined → unasked · null → none served · object → [desktop] as configured
    nodes: [],                  // the machines this caller may watch
    peer: "self",               // the one chosen
    agent: null,                // what the capture agent on that machine is doing
    // The trail is owner-only on the daemon, so `null` here means *this caller
    // may not read it* as often as it means there is none — and both are a
    // hidden plate rather than a refusal on screen. A person who has been
    // granted a machine is not being told off for asking; there is simply no
    // capability that honestly says "may read the record of everybody else".
    audit: undefined,           // undefined → unasked · null → not this caller's to read · object → the tail
  };

  const $ = (id) => document.getElementById(id);

  /* Poll bookkeeping: one loop, immediate re-poll after any command. */
  let pollTimer = null;
  let inFlight = false;
  let pollAgain = false;
  /* The push stream, its reconnection schedule, and what the DIAGNOSTICS plate
     reports about it. Counters only — nothing here decides anything. */
  let socket = null;
  let streamTimer = null;
  let streamAttempt = 0;
  let logTimer = null;
  const streamStats = { snapshots: 0, bytes: 0, reconnects: 0, lastAt: 0, openedAt: 0 };
  /* Whether the log view is pinned to its newest line, and what arrived while
     the reader was scrolled back. */
  let logPinned = true;
  let logUnseen = 0;
  /* The log toolbar's two sieves. */
  let stderrOnly = false;
  let logQuery = "";
  let logQueryTimer = null;
  /* Last rendered firewall JSON, to rebuild that table only on change. */
  let firewallDrawn = "";
  /* Last rendered fleet strip, to rebuild those chips only on change. */
  let stripDrawn = "";
  /* Rail rows by service name, updated in place so focus survives a poll. */
  const railRows = new Map();
  /* When the daemon last answered, for the masthead's age-of-loss reading. */
  let lastContact = 0;
  /* A done-notice dissolves on its own; a problem stays until dismissed. */
  let noticeTimer = null;

  /* ── transport ────────────────────────────────────────────────────── */

  /** One request to the admin API. Cookies ride along; anything mutating
   *  carries the CSRF header. Throws only on network failure. */
  async function api(path, options = {}) {
    const method = options.method || "GET";
    const headers = { "Accept": "application/json" };
    if (method !== "GET") headers["X-Selfhost-Console"] = "1";
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

  /* ── session ──────────────────────────────────────────────────────── */

  /** Decides which view to open from whether a session cookie is accepted.
   *  The probe rides a slow tunnel: anything typed into the password field
   *  while it was in flight must survive the view settling. */
  async function checkSession() {
    try {
      const reply = await api("/api/session");
      if (reply.status === 200) { rememberUser(reply); enterConsole(); }
      else showLogin("", { keep: true });
    } catch {
      showLogin("cannot reach the server", { keep: true });
    }
  }

  /** Keeps who the daemon says this session belongs to — every granted-session
   *  reply carries a `user` — for the masthead's account of itself. */
  function rememberUser(reply) {
    state.user = reply.body && typeof reply.body.user === "string" ? reply.body.user : null;
  }

  /** Puts that name in the masthead.
   *
   *  Separate from `enterConsole` because a session can be re-opened *without*
   *  entering the console: authorising a keyboard mints a fresh session, and the
   *  passkey that mints it may belong to a different person from the one who
   *  opened the tab. A console still naming the previous holder after that would
   *  be attributing one person's keystrokes to another on the very screen whose
   *  actions are being recorded under a name. */
  function showUser() {
    const who = $("who");
    who.hidden = !state.user;
    who.textContent = state.user ? `— ${state.user}` : "";
  }

  function showLogin(note, options = {}) {
    state.view = "login";
    clearTimeout(pollTimer);
    $("view-console").hidden = true;
    $("view-login").hidden = false;
    const line = $("login-note");
    line.textContent = note;
    line.hidden = note === "";
    if (!options.keep) $("login-password").value = "";
    $("login-password").focus();
  }

  /** Back to the password field, with everything the session showed dropped. */
  function toLogin() {
    closeStream();
    closeDesktop("the console session ended");
    state.shares = undefined;
    state.share = null;
    state.dir = "";
    state.listing = null;
    state.listingNote = "";
    state.desktop = undefined;
    state.nodes = [];
    state.agent = null;
    state.audit = undefined;
    forgetControl();
    abandonUploads();
    treeChildren.clear();
    treeOpen.clear();
    state.link = "connecting";
    state.services = [];
    state.selected = null;
    state.spec = null;
    state.firewall = null;
    state.notice = null;
    state.formOpen = false;
    state.passkeys = null;
    state.user = null;
    resetLogs("");
    firewallDrawn = "";
    for (const row of railRows.values()) row.remove();
    railRows.clear();
    showLogin("");
  }

  function enterConsole() {
    state.view = "console";
    state.link = "connecting";
    $("view-login").hidden = true;
    $("view-console").hidden = false;
    showUser();
    render();
    poll();
    // The stream is opened alongside the first poll rather than instead of it:
    // the poll is what proves the session works and fills the page, and the
    // handshake takes a ticket and a round trip that the operator should not
    // have to watch before seeing anything.
    openStream();
    // Outside the poll on purpose: passkeys change only through this page's
    // own register and remove buttons, which refresh the list themselves.
    refreshPasskeys();
    // Also outside the poll, and for a stronger reason than the passkeys are: a
    // directory listing must not change under the operator's hands. It is
    // fetched when they navigate, when they change something, and when they ask
    // — never on a timer, because a rename half-typed into a row that a poll has
    // just rebuilt is a rename of whatever moved into that row.
    refreshShares();
    // Off the poll for the same reason the passkeys are, plus one of its own:
    // this is a bounded read of a file that nothing rotates, and putting it on
    // a one-second loop would make reading the record of what was done the most
    // expensive thing the console does.
    refreshAudit();
  }

  async function submitLogin(event) {
    event.preventDefault();
    const note = $("login-note");
    note.hidden = true;
    $("login-submit").disabled = true;
    $("login-sweep").hidden = false;
    try {
      const reply = await api("/api/session", { method: "POST", body: { password: $("login-password").value } });
      if (reply.status >= 200 && reply.status < 300) { rememberUser(reply); enterConsole(); return; }
      note.hidden = false;
      if (reply.status === 401) note.textContent = "not accepted";
      else if (reply.status === 429) note.textContent = "too many attempts, wait a minute";
      else note.textContent = `login failed (${reply.status})`;
      $("login-password").value = "";
      $("login-password").focus();
    } catch {
      note.hidden = false;
      note.textContent = "cannot reach the server";
    } finally {
      $("login-submit").disabled = false;
      $("login-sweep").hidden = true;
    }
  }

  async function logout() {
    try { await api("/api/session", { method: "DELETE" }); }
    catch { /* the session is being abandoned either way */ }
    toLogin();
  }

  /* ── passkeys (biometric login) ───────────────────────────────────── */

  /** Unhides the login page's passkey button wherever the browser speaks
   *  WebAuthn at all: even without a built-in biometric, it can reach a
   *  phone by QR or a plugged-in security key — someone else's authenticator,
   *  which is the whole point of passkeys being per-person. */
  function offerPasskeyLogin() {
    $("login-passkey").hidden = !window.PublicKeyCredential;
  }

  /** One trip through the biometric door: challenge → authenticator →
   *  assertion → a session that is brand new.
   *
   *  Shared by the login page and by the desktop plate's keyboard
   *  authorisation, because they are the same act with different consequences.
   *  The login page has no session and this mints its first; the desktop plate
   *  has one and mints a *newer* one, which is the point — the daemon measures
   *  a session's age, so re-opening it is what makes a stale login a fresh one.
   *
   *  Reports rather than displays, so each caller can say what a failure means
   *  where it happened. `quick` is the one piece of forensics in it: a
   *  `NotAllowedError` that comes back in less time than a human takes to look
   *  at a fingerprint reader is the *browser* refusing to show the prompt — a
   *  gesture it did not consider recent enough — and not a person declining it.
   *  The two want opposite responses, so they are told apart here. */
  async function passkeyAssertion() {
    let issued;
    try { issued = await api("/api/webauthn/login/challenge", { method: "POST" }); }
    catch { return { ok: false, quick: true, text: "cannot reach the server" }; }
    const challenge = issued.status === 200 && issued.body
      ? b64urlToBuf(issued.body.challenge) : null;
    if (!challenge) {
      // A 401 before any biometric prompt means the daemon has nothing to
      // verify against — the one failure worth explaining, because the fix is a
      // registration, not a retry.
      return {
        ok: false,
        quick: true,
        noPasskey: issued.status === 401,
        text: issued.status === 429 ? "too many attempts, wait a minute"
          : issued.status === 401 ? "no passkey is registered yet" : "not accepted",
      };
    }
    const asked = Date.now();
    let credential = null;
    try {
      credential = await navigator.credentials.get({
        publicKey: {
          challenge,
          rpId: issued.body.rpId,
          // The point of the feature: the authenticator must verify the person
          // (biometric or PIN), not merely observe a touch.
          userVerification: "required",
          timeout: 60000,
        },
      });
    } catch {
      return { ok: false, quick: Date.now() - asked < 500, text: "the authenticator refused, or the prompt was dismissed" };
    }
    if (!credential) return { ok: false, quick: false, text: "no credential was offered" };
    const answer = credential.response;
    let reply;
    try {
      reply = await api("/api/webauthn/login", {
        method: "POST",
        body: {
          id: credential.id,
          clientDataJSON: bufToB64url(new Uint8Array(answer.clientDataJSON)),
          authenticatorData: bufToB64url(new Uint8Array(answer.authenticatorData)),
          signature: bufToB64url(new Uint8Array(answer.signature)),
        },
      });
    } catch { return { ok: false, quick: false, text: "cannot reach the server" }; }
    if (reply.status >= 200 && reply.status < 300) {
      rememberUser(reply);
      return { ok: true };
    }
    return {
      ok: false,
      quick: false,
      text: reply.status === 429 ? "too many attempts, wait a minute" : "not accepted",
    };
  }

  /** The biometric login. A cancelled prompt says nothing; a refusal wears the
   *  password form's own quiet words, because the daemon's refusals are
   *  deliberately uniform. */
  async function passkeyLogin() {
    const note = $("login-note");
    note.hidden = true;
    $("login-passkey").disabled = true;
    try {
      const proof = await passkeyAssertion();
      if (proof.ok) { enterConsole(); return; }
      // A dismissed authenticator is the operator changing their mind, and a
      // page that scolded them for it would be a page that shouts at a
      // fingertip. Only a refusal with something to say says it.
      if (!proof.text || proof.text === "the authenticator refused, or the prompt was dismissed") return;
      note.hidden = false;
      note.textContent = proof.noPasskey
        ? "no passkey registered yet — enter the password once, then register under PASSKEYS"
        : proof.text;
    } finally {
      $("login-passkey").disabled = false;
    }
  }

  /** Fetches the registered passkeys. A 404 — a daemon without the feature —
   *  hides the panel silently, exactly as the firewall panel handles it. */
  async function refreshPasskeys() {
    try {
      const reply = await api("/api/webauthn/credentials");
      if (reply.status === 401) { toLogin(); return; }
      state.passkeys = reply.status === 200 && reply.body && Array.isArray(reply.body.passkeys)
        ? reply.body.passkeys : null;
    } catch {
      state.passkeys = null;
    }
    renderPasskeys();
  }

  /** Registers a passkey on this device's platform authenticator for the
   *  person named in the field (the session's own user when left blank): an
   *  authenticated-session-only act, so the password remains the root key. */
  async function registerPasskey() {
    const who = ($("pk-user").value || "").trim().slice(0, 32) || state.user || "owner";
    $("pk-register").disabled = true;
    try {
      const issued = await api("/api/webauthn/register/challenge", { method: "POST" });
      if (issued.status === 401) { toLogin(); return; }
      const challenge = issued.status === 200 && issued.body
        ? b64urlToBuf(issued.body.challenge) : null;
      if (!challenge) {
        notify("problem", (issued.body && issued.body.error) || `could not start registration (${issued.status})`);
        return;
      }
      let credential;
      try {
        credential = await navigator.credentials.create({
          publicKey: {
            challenge,
            rp: { id: issued.body.rpId, name: "selfhost" },
            // One handle per person: the same name re-registered on the same
            // device replaces that person's passkey instead of piling up
            // copies, while different names stay separate resident
            // credentials — the browser's account picker at login.
            user: {
              id: new TextEncoder().encode(`selfhost-user:${who.toLowerCase()}`),
              name: who,
              displayName: who,
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            // No attachment restriction: the browser's own dialog offers this
            // device's biometric, another person's phone (by QR), or a
            // security key. One shared authenticator cannot tell people's
            // fingers apart — the OS accepts any enrolled finger and WebAuthn
            // reports only that verification happened — so a second person's
            // passkey belonging on *their* device is what makes "whose
            // biometric" a cryptographic fact instead of a picker choice.
            authenticatorSelection: {
              // Discoverable, so the login ceremony can name no credential
              // ids and the login door leaks nothing about what exists.
              residentKey: "required",
              userVerification: "required",
            },
            attestation: "none",
            timeout: 60000,
          },
        });
      } catch { return; /* cancelled at the authenticator */ }
      if (!credential) return;
      const made = credential.response;
      if (typeof made.getPublicKey !== "function" || typeof made.getAuthenticatorData !== "function") {
        notify("problem", "this browser cannot export the passkey's public key");
        return;
      }
      const reply = await api("/api/webauthn/register", {
        method: "POST",
        body: {
          id: credential.id,
          algorithm: made.getPublicKeyAlgorithm(),
          publicKey: bufToB64url(new Uint8Array(made.getPublicKey())),
          clientDataJSON: bufToB64url(new Uint8Array(made.clientDataJSON)),
          authenticatorData: bufToB64url(new Uint8Array(made.getAuthenticatorData())),
          user: who,
          label: deviceLabel(navigator.userAgent),
        },
      });
      if (reply.status === 401) { toLogin(); return; }
      if (reply.status >= 400) {
        notify("problem", (reply.body && reply.body.error) || `registration refused (${reply.status})`);
        return;
      }
      $("pk-user").value = "";
      notify("done", `Passkey registered — ${who} can now log in with this device's biometric`);
    } catch {
      notify("problem", "cannot reach the server");
    } finally {
      $("pk-register").disabled = false;
      refreshPasskeys();
    }
  }

  /** Revokes one passkey. One click, no typed confirm: unlike an uninstall,
   *  a removed passkey is recoverable by registering the device again. */
  async function removePasskey(id) {
    if (!usableCredentialId(id)) return;
    await command("Passkey removed", "DELETE", `/api/webauthn/credentials/${id}`);
    refreshPasskeys();
  }

  /** The PASSKEYS panel: hidden while the daemon lacks the feature, one row
   *  per person-and-device, and the register row only where it can work. */
  function renderPasskeys() {
    const panel = $("passkeys");
    panel.hidden = state.passkeys === null;
    if (state.passkeys === null) return;
    const passkeys = state.passkeys;
    $("pk-count").textContent = String(passkeys.length);
    $("pk-register-row").hidden = !window.PublicKeyCredential;
    const note = $("pk-note");
    note.hidden = passkeys.length > 0;
    note.textContent = window.PublicKeyCredential
      ? "No passkeys yet. Name whose it is and register — the browser offers this device's "
        + "biometric, their phone by QR, or a security key, and each person's passkey answers "
        + "only to their own hardware."
      : "No passkeys yet. Open the console in a browser that supports passkeys to register one.";
    const rows = $("pk-list");
    rows.textContent = "";
    for (const entry of passkeys) {
      if (!usableCredentialId(entry.id)) continue;
      const row = document.createElement("li");
      const person = document.createElement("span");
      person.className = "pk-label";
      person.textContent = String(entry.user || "owner");
      const label = document.createElement("span");
      label.className = "mono micro";
      label.textContent = String(entry.label || "passkey");
      const added = document.createElement("span");
      added.className = "mono micro";
      added.textContent = passkeyDay(entry.createdUnix);
      const rule = document.createElement("span");
      rule.className = "rule";
      const remove = document.createElement("button");
      remove.type = "button";
      remove.className = "btn danger small";
      remove.textContent = "REMOVE";
      remove.addEventListener("click", () => removePasskey(entry.id));
      row.append(person, label, added, rule, remove);
      rows.append(row);
    }
  }

  /* ── the push stream ──────────────────────────────────────────────── */

  /** Opens the events stream: mint a ticket, then hand it to the handshake.
   *
   *  The ticket is why this is two steps. A WebSocket handshake is a GET, a
   *  page cannot put a custom header on one, and there is no preflight — so the
   *  cookie alone would authorise it, and a hostile page in a logged-in browser
   *  could open this stream. The mint is an ordinary POST carrying the CSRF
   *  header, which such a page cannot forge, and the handshake carries proof
   *  that it happened.
   *
   *  A 404 — a daemon older than this page — settles into "off" silently and
   *  the poll carries the console, exactly as the firewall and passkey panels
   *  treat a feature that is not there. */
  async function openStream() {
    // "opening" is set synchronously below and is what makes this re-entrant:
    // there is an await between here and the socket existing, and two opens
    // racing through that gap would leave one socket unreferenced and never
    // closed.
    if (state.view !== "console" || socket || state.stream === "opening") return;
    clearTimeout(streamTimer);
    state.stream = "opening";
    renderMasthead();

    let ticket;
    try {
      const reply = await api("/api/desktop/ticket", { method: "POST", body: { want: ["events"] } });
      if (reply.status === 401) { toLogin(); return; }
      if (reply.status === 404) { settleStream("off"); return; }
      ticket = reply.body && reply.body.ticket;
    } catch {
      scheduleReconnect();
      return;
    }
    if (!usableTicket(ticket)) { scheduleReconnect(); return; }

    // Same origin, so the CSP's `connect-src 'self'` covers it and no directive
    // has to be widened for the stream to exist.
    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    try {
      socket = new WebSocket(`${scheme}//${location.host}/api/events`, streamProtocols(ticket));
    } catch {
      scheduleReconnect();
      return;
    }
    socket.binaryType = "arraybuffer";
    socket.addEventListener("open", onStreamOpen);
    socket.addEventListener("message", onStreamMessage);
    socket.addEventListener("close", onStreamEnd);
    socket.addEventListener("error", onStreamEnd);
  }

  function onStreamOpen() {
    streamAttempt = 0;
    streamStats.openedAt = Date.now();
    settleStream("live");
  }

  /** One snapshot. Binary, always: the daemon's codec sends no text frames, so
   *  nothing in the stack needs a UTF-8 validator and a text frame arriving
   *  would be a protocol error rather than a message. A payload that is not the
   *  JSON this page expects is dropped without disturbing what is on screen —
   *  the safety-net poll is what corrects a console that has fallen behind. */
  function onStreamMessage(event) {
    let value;
    try {
      const bytes = new Uint8Array(event.data);
      streamStats.bytes += bytes.length;
      value = JSON.parse(new TextDecoder().decode(bytes));
    } catch {
      return;
    }
    if (!value || value.kind !== "snapshot") return;
    streamStats.snapshots += 1;
    streamStats.lastAt = Date.now();
    applySnapshot(value);
  }

  /** The link went. Every ending arrives here — a close frame, a dropped
   *  tunnel, a daemon restart — because none of them differ in what the page
   *  must do about it. */
  function onStreamEnd() {
    if (!socket) return;
    dropSocket();
    streamStats.reconnects += 1;
    scheduleReconnect();
  }

  function scheduleReconnect() {
    dropSocket();
    if (state.view !== "console") return;
    settleStream("lost");
    streamAttempt += 1;
    // A little jitter, so a daemon restart does not bring every open console
    // back at the same instant.
    const delay = backoffDelay(streamAttempt) + Math.floor(Math.random() * 250);
    clearTimeout(streamTimer);
    streamTimer = setTimeout(openStream, delay);
  }

  /** Forgets the socket without letting its own close handler fire — otherwise
   *  closing on purpose would schedule a reconnection to something nobody
   *  wants any more. */
  function dropSocket() {
    if (!socket) return;
    const going = socket;
    socket = null;
    going.removeEventListener("open", onStreamOpen);
    going.removeEventListener("message", onStreamMessage);
    going.removeEventListener("close", onStreamEnd);
    going.removeEventListener("error", onStreamEnd);
    try { going.close(); } catch { /* already gone */ }
  }

  function closeStream() {
    clearTimeout(streamTimer);
    clearTimeout(logTimer);
    streamAttempt = 0;
    dropSocket();
    settleStream("off");
  }

  /** Records the stream's state and redraws everything that depends on it —
   *  the masthead lamp, the diagnostics plate, and the poll cadence, which is
   *  the point: the safety net slows down exactly when the stream takes over. */
  function settleStream(next) {
    state.stream = next;
    renderMasthead();
    renderDiagnostics();
    if (state.view === "console") {
      schedule(pollDelay());
      scheduleLogs();
    }
  }

  /** A pushed snapshot, applied as the poll's own reply would be. Deliberately
   *  the same shapes `/api/services` and `/api/firewall` answer with, so this
   *  agrees with the poll by construction rather than by two lots of parsing
   *  that have to be kept in step. */
  function applySnapshot(value) {
    state.link = "connected";
    lastContact = Date.now();
    const services = Array.isArray(value.services)
      ? value.services.filter((s) => s && usableName(s.name)) : [];
    state.services = services;
    if (!state.selected || !services.some((s) => s.name === state.selected)) {
      state.selected = services.length ? services[0].name : null;
      state.spec = null;
      resetLogs(state.selected || "");
      hideConfirm();
    }
    state.firewall = value.firewall && typeof value.firewall.backend === "string"
      ? value.firewall : null;
    render();
    // A snapshot only arrives when something changed, so this is not a poll in
    // disguise: it fetches the two things the snapshot does not carry, at
    // exactly the moments they are worth fetching.
    refreshDefinition();
    refreshLogs();
  }

  /* ── polling ──────────────────────────────────────────────────────── */

  function schedule(delay) {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(poll, delay);
  }

  /** How long until the next full refresh. While the stream is live this is
   *  only a safety net; without one it is the whole of the console's news. */
  function pollDelay() {
    if (document.hidden) return POLL_SLOW;
    return state.stream === "live" ? POLL_SAFETY : POLL_DEGRADED;
  }

  /** One poll. Called on a timer, and directly for an immediate re-poll
   *  after any command; overlapping calls queue one more rather than racing. */
  async function poll() {
    if (state.view !== "console") return;
    if (inFlight) { pollAgain = true; return; }
    inFlight = true;
    try {
      await refresh();
    } finally {
      inFlight = false;
      if (state.view === "console") {
        const delay = pollAgain ? 0 : pollDelay();
        pollAgain = false;
        schedule(delay);
      }
    }
  }

  /** The log tail's own timer, live only while the stream is: without a stream
   *  the full poll already fetches logs every second, and two timers asking for
   *  the same thing is how a console ends up hammering a route nobody meant to
   *  hammer. */
  function scheduleLogs() {
    clearTimeout(logTimer);
    if (state.stream !== "live" || document.hidden || !state.selected) return;
    logTimer = setTimeout(async () => {
      await refreshLogs();
      scheduleLogs();
    }, POLL_LOGS);
  }

  /** The poll body: services first (that is the connectivity signal), then
   *  the selection's definition and logs and the firewall, in parallel. */
  async function refresh() {
    let reply;
    try {
      reply = await api("/api/services");
    } catch {
      state.link = "lost";
      render();
      return;
    }
    if (reply.status === 401) { toLogin(); return; }
    if (reply.status !== 200 || !reply.body) { state.link = "lost"; render(); return; }

    state.link = "connected";
    lastContact = Date.now();
    const services = Array.isArray(reply.body.services)
      ? reply.body.services.filter((s) => s && usableName(s.name))
      : [];
    state.services = services;
    if (!state.selected || !services.some((s) => s.name === state.selected)) {
      state.selected = services.length ? services[0].name : null;
      state.spec = null;
      resetLogs(state.selected || "");
      hideConfirm();
    }

    await Promise.all([refreshDefinition(), refreshLogs(), refreshFirewall(), refreshDesktop()]);
    render();
  }

  /** Fetches the selected service's definition; a reply for a service that is
   *  no longer selected is discarded rather than shown under the wrong name. */
  async function refreshDefinition() {
    const name = state.selected;
    if (!name) return;
    let reply;
    try { reply = await api(`/api/services/${name}`); }
    catch { return; /* the services fetch is the connectivity signal */ }
    if (state.selected !== name) return;
    if (reply.status === 200 && reply.body && reply.body.spec && reply.body.spec.name === name) {
      state.spec = reply.body.spec;
    }
  }

  /** Cursor-based incremental log fetch, appended to the page's ring. */
  async function refreshLogs() {
    const name = state.selected;
    if (!name) return;
    if (state.logs.service !== name) resetLogs(name);
    const from = state.logs.nextSeq;
    let reply;
    try { reply = await api(`/api/services/${name}/logs?from=${from}&limit=${LOG_BATCH}`); }
    catch { return; /* retried in half a second; a notice per miss would bury everything */ }
    if (state.selected !== name || state.logs.service !== name) return;
    if (reply.status !== 200 || !reply.body) return;

    const lines = Array.isArray(reply.body.lines) ? reply.body.lines : [];
    state.logs.nextSeq = Number(reply.body.nextSeq) || from;
    state.logs.missed += Number(reply.body.missed) || 0;
    appendLogLines(lines);
  }

  /** Fetches the host firewall's state. A 404 — a daemon without the feature —
   *  hides the panel silently; that absence is not a problem to report. */
  async function refreshFirewall() {
    let reply;
    try { reply = await api("/api/firewall"); }
    catch { return; }
    if (reply.status === 404) { state.firewall = null; return; }
    if (reply.status === 200 && reply.body && typeof reply.body.backend === "string") {
      state.firewall = reply.body;
    }
  }

  /* ── commands ─────────────────────────────────────────────────────── */

  /** Runs one mutating request and reports what the daemon said about it.
   *  Every command is followed by an immediate re-poll, so the outcome lands
   *  on screen at once rather than half a second later. */
  async function command(done, method, path, body) {
    try {
      const reply = await api(path, { method, body });
      if (reply.status === 401) { toLogin(); return false; }
      if (reply.status >= 400) {
        notify("problem", (reply.body && reply.body.error) || `request failed (${reply.status})`);
        poll();
        return false;
      }
      notify("done", done);
      poll();
      return true;
    } catch {
      state.link = "lost";
      render();
      return false;
    }
  }

  function act(action) {
    const name = state.selected;
    if (!name || !usableName(name)) return;
    command(`Asked ${name} to ${action}`, "POST", `/api/services/${name}/${action}`);
  }

  function deployNow() {
    const name = state.selected;
    if (!name || !usableName(name)) return;
    command(`Deploy requested for ${name}`, "POST", `/api/services/${name}/deploy`);
  }

  async function uninstall(name) {
    if (!usableName(name)) return;
    hideConfirm();
    const removed = await command(`Uninstalled ${name}`, "DELETE", `/api/services/${name}`);
    if (removed && state.selected === name) {
      state.selected = null;
      state.spec = null;
      resetLogs("");
      render();
    }
  }

  function reconcileFirewall() {
    command("Firewall reconciled", "POST", "/api/firewall/reconcile");
  }

  function notify(kind, text) {
    state.notice = { kind, text };
    renderNotice();
    clearTimeout(noticeTimer);
    // A confirmation has said its piece after a few seconds; a problem waits
    // to be read and dismissed.
    if (kind === "done") {
      noticeTimer = setTimeout(() => {
        if (state.notice && state.notice.kind === "done") {
          state.notice = null;
          renderNotice();
        }
      }, 6000);
    }
  }

  /* ── selection ────────────────────────────────────────────────────── */

  function select(name) {
    if (state.selected === name) return;
    state.selected = name;
    state.spec = null;
    resetLogs(name);
    hideConfirm();
    render();
    poll();
    // The log timer follows the selection: it does nothing without one, and a
    // new selection wants its tail now rather than at the end of the old one's
    // interval.
    scheduleLogs();
  }

  function stepSelection(step) {
    const names = state.services.map((s) => s.name);
    if (names.length === 0) return;
    const at = names.indexOf(state.selected);
    const next = Math.min(names.length - 1, Math.max(0, (at < 0 ? 0 : at) + step));
    select(names[next]);
    const row = railRows.get(names[next]);
    if (row) row.focus();
  }

  /* ── the log panel ────────────────────────────────────────────────── */

  function resetLogs(service) {
    state.logs = { service, nextSeq: 0, missed: 0, count: 0 };
    logPinned = true;
    logUnseen = 0;
    logQuery = "";
    $("log-filter").value = "";
    renderJump();
    const scroll = $("log-scroll");
    while (scroll.lastChild && scroll.lastChild.id !== "log-empty") scroll.removeChild(scroll.lastChild);
  }

  /** Appends fetched lines, holds the ring at LOG_RING, and keeps the view
   *  pinned to the newest line unless the reader has scrolled back. */
  function appendLogLines(lines) {
    if (lines.length === 0) return;
    const scroll = $("log-scroll");
    const fragment = document.createDocumentFragment();
    let appended = 0;
    for (const line of lines) {
      if (!line || typeof line.text !== "string") continue;
      const row = document.createElement("div");
      row.className = line.stream === "stderr" ? "logline stderr" : "logline";
      const seq = document.createElement("span");
      seq.className = "seq";
      seq.textContent = String(Number(line.seq) || 0);
      const text = document.createElement("span");
      text.className = "text";
      text.textContent = line.text;
      if (!sift(line.text, logQuery)) row.classList.add("sifted");
      row.append(seq, text);
      fragment.append(row);
      state.logs.count += 1;
      appended += 1;
    }
    scroll.append(fragment);
    while (state.logs.count > LOG_RING) {
      const first = scroll.querySelector(".logline");
      if (!first) break;
      first.remove();
      state.logs.count -= 1;
    }
    $("log-empty").hidden = state.logs.count > 0;
    if (logPinned) {
      scroll.scrollTop = scroll.scrollHeight;
    } else {
      logUnseen += appended;
      renderJump();
    }
  }

  /** The way back down to now: hidden while pinned, wearing the count of
   *  lines that arrived while the reader was elsewhere. */
  function renderJump() {
    const jump = $("log-jump");
    jump.hidden = logPinned;
    if (!logPinned) jump.textContent = logUnseen > 0 ? `▾ ${logUnseen} NEW` : "▾ LATEST";
  }

  /** Applies the toolbar's sieves to every line already on the page. */
  function applyLogSieves() {
    $("log-scroll").classList.toggle("only-stderr", stderrOnly);
    for (const row of $("log-scroll").querySelectorAll(".logline")) {
      const text = row.querySelector(".text");
      row.classList.toggle("sifted", !sift(text ? text.textContent : "", logQuery));
    }
    if (logPinned) $("log-scroll").scrollTop = $("log-scroll").scrollHeight;
  }

  /* ── rendering ────────────────────────────────────────────────────── */

  function render() {
    if (state.view !== "console") return;
    renderMasthead();
    renderBank();
    renderRail();
    renderDetail();
    renderFirewall();
    renderDiagnostics();
    renderStorage();
    renderDesktop();
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
    $("link-sweep").hidden = !face.reaching;
    $("link-lamp").hidden = face.reaching;
    setLamp($("link-lamp"), face.status);
    setStateWord($("link-word"), face.status, linkWord(state.link, sinceSecs));

    // The LIVE lamp, beside the link's own. Two indicators rather than one
    // because they answer different questions: the link says whether the daemon
    // is reachable at all, and this says whether it is telling us things
    // unasked. A console can be perfectly connected and merely polling.
    const lamp = streamLamp(state.stream);
    setLamp($("live-lamp"), lamp);
    setStateWord($("live-word"), lamp, streamWord(state.stream));
  }

  /* ── the diagnostics plate ────────────────────────────────────────── */

  /** What the stream is actually doing, in numbers. Built in this phase and
   *  used to verify every phase after it: when a desktop session feels slow the
   *  question is always which hop is slow, and a console that cannot answer it
   *  leaves the operator guessing. Hop and end-to-end round trips join this
   *  plate with the peer link, which is where a second hop first exists. */
  function renderDiagnostics() {
    const panel = $("diagnostics");
    panel.hidden = state.view !== "console";
    if (panel.hidden) return;

    const quietSecs = streamStats.lastAt ? Math.floor((Date.now() - streamStats.lastAt) / 1000) : 0;
    const lamp = streamLamp(state.stream);
    setLamp($("dg-lamp"), lamp);
    setStateWord($("dg-word"), lamp, streamWord(state.stream));
    $("dg-note").textContent = diagnosisLine(state.stream, quietSecs);

    $("dg-snapshots").textContent = String(streamStats.snapshots);
    $("dg-received").textContent = byteCount(streamStats.bytes);
    $("dg-last").textContent = streamStats.lastAt ? duration(quietSecs) : "—";
    $("dg-uptime").textContent = state.stream === "live" && streamStats.openedAt
      ? duration(Math.floor((Date.now() - streamStats.openedAt) / 1000)) : "—";
    $("dg-reconnects").textContent = String(streamStats.reconnects);
    $("dg-poll").textContent = state.stream === "live" ? `${POLL_SAFETY / 1000}s net` : `${POLL_DEGRADED / 1000}s`;
  }

  function renderBank() {
    $("condition").textContent = condition(state.link, state.services);
    const total = state.services.length;
    $("evidence").hidden = total === 0;
    if (total === 0) return;
    const running = state.services.filter(isLive).length;
    const attention = state.services.filter(needsAttention).length;
    const restarts = state.services.reduce((sum, s) => sum + (Number(s.totalRestarts) || 0), 0);
    $("ev-running").textContent = `${running}/${total}`;
    $("ev-restarts").textContent = String(restarts);
    const attentionEl = $("ev-attention");
    attentionEl.textContent = String(attention);
    attentionEl.className = attention > 0 ? "mono bad-ink" : "mono";
    renderStrip();
  }

  /** The fleet strip: one chip per service, lit by its state, a handle to
   *  select it. Rebuilt only when what it would show actually changed. */
  function renderStrip() {
    const strip = $("strip");
    strip.hidden = state.services.length < 2;
    if (strip.hidden) { stripDrawn = ""; return; }
    const face = state.services.map((s) => [s.name, present(s).status, s.name === state.selected]);
    const drawn = JSON.stringify(face);
    if (drawn === stripDrawn) return;
    stripDrawn = drawn;
    strip.textContent = "";
    for (const [name, status, chosen] of face) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = `chip ${status}`;
      chip.title = name;
      chip.setAttribute("aria-label", `Select ${name}`);
      if (chosen) chip.setAttribute("aria-current", "true");
      const fill = document.createElement("span");
      fill.className = "fill";
      chip.append(fill);
      chip.addEventListener("click", () => select(name));
      strip.append(chip);
    }
  }

  /** One rail row, built once and updated in place afterwards. */
  function buildRailRow(name) {
    const row = document.createElement("li");
    row.setAttribute("role", "option");
    row.tabIndex = 0;
    const unit = document.createElement("span");
    unit.className = "unit";
    const lamp = document.createElement("span");
    lamp.className = "lamp idle";
    const main = document.createElement("span");
    main.className = "rowmain";
    const line = document.createElement("span");
    line.className = "rowline";
    const label = document.createElement("span");
    label.className = "rowname";
    const word = document.createElement("span");
    word.className = "stateword";
    const summary = document.createElement("span");
    summary.className = "rowsummary";
    line.append(label, word);
    main.append(line, summary);
    row.append(unit, lamp, main);
    row.addEventListener("click", () => select(name));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); select(name); }
    });
    return row;
  }

  function renderRail() {
    const list = $("service-list");
    $("service-count").textContent = String(state.services.length);
    $("rail-empty").hidden = state.services.length > 0;
    $("rail-empty").textContent = state.link === "connected"
      ? "The daemon is running no services yet." : "Waiting for the daemon.";

    const seen = new Set();
    // Rows are moved only when their order actually changed: re-inserting a
    // node restarts its lamp's animation and unsettles focus, and on the
    // ordinary poll nothing has moved.
    let cursor = list.firstElementChild;
    state.services.forEach((service, index) => {
      seen.add(service.name);
      let row = railRows.get(service.name);
      if (!row) {
        row = buildRailRow(service.name);
        railRows.set(service.name, row);
      }
      if (row === cursor) cursor = cursor.nextElementSibling;
      else list.insertBefore(row, cursor);
      const chosen = state.selected === service.name;
      row.setAttribute("aria-selected", chosen ? "true" : "false");
      const { status } = present(service);
      const [unit, lamp, main] = row.children;
      unit.textContent = String(index + 1).padStart(2, "0");
      setLamp(lamp, status);
      const [line, summary] = main.children;
      const [label, word] = line.children;
      label.textContent = displayName(service);
      setStateWord(word, status, stateLabel(service.state));
      summary.textContent = railSummary(service);
    });
    for (const [name, row] of railRows) {
      if (!seen.has(name)) { row.remove(); railRows.delete(name); }
    }
  }

  function renderDetail() {
    $("form-pane").hidden = !state.formOpen;
    $("detail").hidden = state.formOpen;
    if (state.formOpen) return;

    const service = state.services.find((s) => s.name === state.selected);
    $("detail-empty").hidden = Boolean(service);
    $("detail-body").hidden = !service;
    if (!service) {
      $("detail-guidance").textContent = guidance(state.link, state.services.length);
      return;
    }

    const { status, startable, summary } = present(service);
    $("d-name").textContent = displayName(service);
    setLamp($("d-lamp"), status);
    setStateWord($("d-stateword"), status, stateLabel(service.state));
    $("d-summary").textContent = summary;

    // The dials: what a glance should carry away. A dash is an honest
    // "no such number", never a zero that lies.
    $("d-readings").hidden = false;
    const live = isLive(service);
    $("d-r-pid").textContent = live && service.pid ? String(service.pid) : "—";
    $("d-r-uptime").textContent = service.state === "running" ? duration(service.uptimeSecs) : "—";
    const restarts = Number(service.totalRestarts) || 0;
    const restartsEl = $("d-r-restarts");
    restartsEl.textContent = String(restarts);
    restartsEl.className = needsAttention(service) ? "mono bad-ink" : "mono";
    $("d-r-mode").textContent = String(service.startMode || "automatic");

    $("d-start").disabled = !startable;
    $("d-stop").disabled = !isLive(service);
    // Restart is offered whatever the state: on a stopped service it means
    // "start", and the supervisor treats it that way.
    $("d-restart").disabled = false;

    const spec = state.spec && state.spec.name === service.name ? state.spec : null;
    $("d-edit").disabled = !spec;
    $("d-deploy").hidden = !(spec && spec.git);

    renderDefinition(service, spec);

    $("d-output-note").textContent = state.logs.missed > 0
      ? `${state.logs.missed} EARLIER LINES DROPPED` : "LIVE";
    $("log-empty").hidden = state.logs.count > 0;
    $("log-empty").textContent = "This service has printed nothing since the daemon started.";
  }

  function defRow(label, value, mono) {
    const row = document.createElement("div");
    row.className = "defrow";
    const term = document.createElement("dt");
    term.textContent = label;
    const detail = document.createElement("dd");
    if (mono) detail.className = "mono";
    detail.textContent = value;
    row.append(term, detail);
    return row;
  }

  /** The DEFINITION block: what the service is configured to be. Before the
   *  definition arrives, only what the live status already carries is shown. */
  function renderDefinition(service, spec) {
    const block = $("d-def");
    block.textContent = "";
    const startModes = {
      automatic: "starts with the daemon", manual: "started by hand", disabled: "disabled",
    };
    if (spec) {
      block.append(defRow("PROGRAM", String(spec.program || ""), true));
      block.append(defRow("ARGUMENTS",
        Array.isArray(spec.args) && spec.args.length ? spec.args.join(" ") : "none",
        Array.isArray(spec.args) && spec.args.length > 0));
      block.append(defRow("RUNS IN", spec.cwd ? String(spec.cwd) : "the daemon's data directory", Boolean(spec.cwd)));
      const env = spec.env && typeof spec.env === "object" ? Object.entries(spec.env) : [];
      if (env.length) {
        block.append(defRow("ENVIRONMENT", env.map(([key, value]) => `${key}=${value}`).join("\n"), true));
      }
      const restarts = { never: "never", "on-failure": "on failure", always: "always" };
      const most = Number(spec.maxRestarts) || 0;
      block.append(defRow("POLICY",
        `${startModes[spec.startMode] || spec.startMode} · restart ${restarts[spec.restart] || spec.restart}`
        + ` · give up after ${most === 0 ? "never" : `${most} attempts`}`));
      if (Array.isArray(spec.stopCommand) && spec.stopCommand.length) {
        block.append(defRow("STOP", spec.stopCommand.join(" "), true));
      }
      if (spec.git) {
        const watch = spec.git;
        const flags = `${watch.enabled === false ? " · paused" : ""}${watch.autoUpdate === false ? " · manual deploys" : ""}`;
        block.append(defRow("GIT",
          `${watch.repository} @ ${watch.branch || "main"} → ${watch.path}`
          + ` · every ${Number(watch.intervalSecs) || 60}s${flags}`, true));
      }
    } else {
      block.append(defRow("START MODE", startModes[service.startMode] || String(service.startMode || "")));
    }
    block.append(defRow("RESTARTS", `${Number(service.totalRestarts) || 0} since the daemon started`));
    if (service.description) block.append(defRow("NOTES", service.description));
  }

  /* ── the firewall panel ───────────────────────────────────────────── */

  function renderFirewall() {
    const firewall = state.firewall;
    const panel = $("firewall");
    panel.hidden = !firewall;
    if (!firewall) { firewallDrawn = ""; return; }
    const drawn = JSON.stringify(firewall);
    if (drawn === firewallDrawn) return;
    firewallDrawn = drawn;

    const backends = { pf: "macOS pf", nftables: "nftables", netsh: "Windows Firewall", unsupported: "unsupported" };
    $("fw-backend").textContent = backends[firewall.backend] || firewall.backend;
    setStateWord($("fw-managed"), firewall.managed ? "ok" : "warn", firewall.managed ? "MANAGED" : "UNMANAGED");
    $("fw-reconcile").hidden = !firewall.managed;

    const note = $("fw-note");
    const inbound = $("fw-inbound");
    const wrap = $("fw-table-wrap");
    const rules = Array.isArray(firewall.rules) ? firewall.rules.filter((r) => r && Number.isFinite(Number(r.port))) : [];

    if (!firewall.managed) {
      note.hidden = false;
      note.textContent = "Unmanaged — the daemon asserts nothing about this host's firewall.";
      inbound.hidden = true;
      wrap.hidden = true;
      return;
    }

    inbound.hidden = false;
    const deny = Boolean(firewall.defaultInboundBlock);
    setLamp($("fw-inbound-lamp"), deny ? "ok" : "warn");
    $("fw-inbound-text").textContent = deny
      ? "inbound default-deny · only the openings below are reachable"
      : "inbound default-allow · ports may be reachable without an opening";

    if (firewall.backend === "unsupported") {
      note.hidden = false;
      note.textContent = "This platform has no firewall backend selfhost can drive, so the exposure here cannot be verified.";
      wrap.hidden = true;
      return;
    }
    if (rules.length === 0) {
      note.hidden = false;
      note.textContent = "No public listeners — every bind is loopback, so nothing off this machine can reach it.";
      wrap.hidden = true;
      return;
    }

    note.hidden = true;
    wrap.hidden = false;
    const body = $("fw-rows");
    body.textContent = "";
    for (const rule of rules) {
      const exposure = exposureOf(rule);
      const row = document.createElement("tr");
      const service = document.createElement("td");
      service.textContent = exposure.service;
      const bind = document.createElement("td");
      bind.className = "mono";
      bind.textContent = exposure.bind;
      row.append(service, bind);
      for (const [status, label] of [exposure.firewall, exposure.router, exposure.reach]) {
        const cell = document.createElement("td");
        const verdict = document.createElement("span");
        verdict.className = "verdict";
        const lamp = document.createElement("span");
        setLamp(lamp, status);
        const word = document.createElement("span");
        setStateWord(word, status, label);
        verdict.append(lamp, word);
        cell.append(verdict);
        row.append(cell);
      }
      body.append(row);
    }
  }

  /* ── notices ──────────────────────────────────────────────────────── */

  function renderNotice() {
    const strip = $("notice");
    strip.hidden = !state.notice;
    if (!state.notice) return;
    strip.className = `alert ${state.notice.kind}`;
    $("notice-text").textContent = state.notice.text;
  }

  /* ── uninstall confirm ────────────────────────────────────────────── */

  function showConfirm() {
    const name = state.selected;
    if (!name) return;
    $("d-confirm").hidden = false;
    $("d-confirm-label").textContent = `Type ${name} to confirm the uninstall`;
    $("d-confirm-input").value = "";
    $("d-confirm-go").disabled = true;
    $("d-confirm-input").focus();
  }

  function hideConfirm() {
    $("d-confirm").hidden = true;
    $("d-confirm-input").value = "";
  }

  /* ── the install / edit form ──────────────────────────────────────── */

  function clearFormProblems() {
    for (const problem of document.querySelectorAll("#form-pane .problem")) {
      problem.hidden = true;
      problem.textContent = "";
    }
    const general = $("form-problems");
    general.hidden = true;
    general.textContent = "";
  }

  /** Renders 422 problems (or client-side ones in the same shape) inline
   *  beside their fields, and the rest in the list at the top. */
  function showFormProblems(problems) {
    clearFormProblems();
    const general = [];
    for (const problem of problems) {
      const target = problemTarget(problem.field || "");
      const holder = target && document.querySelector(`.field[data-problem="${target}"] .problem`);
      if (holder) {
        holder.hidden = false;
        holder.textContent = problem.message || "invalid";
      } else {
        general.push(`${problem.field}: ${problem.message}`);
      }
    }
    if (general.length) {
      const list = $("form-problems");
      list.hidden = false;
      for (const line of general) {
        const item = document.createElement("li");
        item.textContent = line;
        list.append(item);
      }
    }
  }

  function openBlank() {
    state.formOpen = true;
    clearFormProblems();
    $("f-title").textContent = "ADD SERVICE";
    $("f-name").value = "";
    $("f-name").readOnly = false;
    $("f-display").value = "";
    $("f-desc").value = "";
    $("f-program").value = "";
    $("f-args").value = "";
    $("f-env").value = "";
    $("f-cwd").value = "";
    $("f-node").value = "";
    $("f-startmode").value = "automatic";
    $("f-restart").value = "on-failure";
    $("f-delay").value = "5";
    $("f-maxrestarts").value = "5";
    $("f-stoptimeout").value = "10";
    $("f-stopcmd").value = "";
    $("f-git-repo").value = "";
    $("f-git-branch").value = "";
    $("f-git-path").value = "";
    $("f-git-interval").value = "";
    $("f-git-enabled").checked = true;
    $("f-git-auto").checked = true;
    $("f-git-postpull").value = "";
    render();
    $("f-name").focus();
  }

  function openEdit(spec) {
    state.formOpen = true;
    clearFormProblems();
    $("f-title").textContent = `EDIT ${spec.name.toUpperCase()}`;
    $("f-name").value = spec.name;
    // The path names the service; renaming is an install of a new one.
    $("f-name").readOnly = true;
    $("f-display").value = spec.displayName && spec.displayName !== spec.name ? spec.displayName : "";
    $("f-desc").value = spec.description || "";
    $("f-program").value = spec.program || "";
    $("f-args").value = Array.isArray(spec.args) ? spec.args.join("\n") : "";
    const env = spec.env && typeof spec.env === "object" ? Object.entries(spec.env) : [];
    $("f-env").value = env.map(([key, value]) => `${key}=${value}`).join("\n");
    $("f-cwd").value = spec.cwd || "";
    $("f-node").value = spec.node || "";
    $("f-startmode").value = spec.startMode || "automatic";
    $("f-restart").value = spec.restart || "on-failure";
    $("f-delay").value = String(spec.restartDelaySecs ?? 5);
    $("f-maxrestarts").value = String(spec.maxRestarts ?? 5);
    $("f-stoptimeout").value = String(spec.stopTimeoutSecs ?? 10);
    $("f-stopcmd").value = Array.isArray(spec.stopCommand) ? spec.stopCommand.join("\n") : "";
    const watch = spec.git || null;
    $("f-git-repo").value = watch ? watch.repository || "" : "";
    $("f-git-branch").value = watch ? watch.branch || "" : "";
    $("f-git-path").value = watch ? watch.path || "" : "";
    $("f-git-interval").value = watch && watch.intervalSecs !== undefined ? String(watch.intervalSecs) : "";
    $("f-git-enabled").checked = watch ? watch.enabled !== false : true;
    $("f-git-auto").checked = watch ? watch.autoUpdate !== false : true;
    $("f-git-postpull").value = watch && Array.isArray(watch.postPull) ? watch.postPull.join("\n") : "";
    render();
    $("f-program").focus();
  }

  function closeForm() {
    state.formOpen = false;
    render();
  }

  /** Reads the form into the ServiceSpec wire shape, collecting client-side
   *  problems in the server's own {field, message} form so both render alike. */
  function collectSpec() {
    const problems = [];
    const number = (id, field) => {
      const raw = $(id).value.trim();
      const value = Number(raw);
      if (raw === "" || !Number.isInteger(value) || value < 0) {
        problems.push({ field, message: "must be a whole number" });
        return 0;
      }
      return value;
    };

    const name = $("f-name").value.trim();
    // usableName allows up to 128 for path safety; the daemon's own limit for
    // a *new* name is 64 (crates/config service.rs), so hold the form to that.
    if (!usableName(name) || name.length > 64) {
      problems.push({
        field: "service.name",
        message: "letters, digits, dot, dash and underscore only, up to 64 characters",
      });
    }
    const program = $("f-program").value.trim();
    if (!program) problems.push({ field: "service.program", message: "name the executable to run" });

    const parsedEnv = parseEnv($("f-env").value);
    if (parsedEnv.bad.length) {
      problems.push({ field: "service.env", message: `each line must be NAME=value (not "${parsedEnv.bad[0]}")` });
    }

    const spec = {
      name,
      program,
      description: $("f-desc").value.trim(),
      args: parseLines($("f-args").value),
      env: parsedEnv.env,
      startMode: $("f-startmode").value,
      restart: $("f-restart").value,
      restartDelaySecs: number("f-delay", "service.restart_delay_secs"),
      maxRestarts: number("f-maxrestarts", "service.max_restarts"),
      stopTimeoutSecs: number("f-stoptimeout", "service.stop_timeout_secs"),
    };
    const display = $("f-display").value.trim();
    if (display) spec.displayName = display;
    const cwd = $("f-cwd").value.trim();
    if (cwd) spec.cwd = cwd;
    const node = $("f-node").value.trim();
    if (node) spec.node = node;
    const stop = parseLines($("f-stopcmd").value);
    if (stop.length) spec.stopCommand = stop;

    const repo = $("f-git-repo").value.trim();
    const path = $("f-git-path").value.trim();
    if (repo || path) {
      // Half a watch is dropped silently by the daemon; refuse it here where
      // the missing field can be pointed at.
      if (!repo) problems.push({ field: "service.git.repository", message: "a watch needs a repository" });
      if (!path) problems.push({ field: "service.git.path", message: "a watch needs a working copy path" });
      const watch = { repository: repo, path };
      const branch = $("f-git-branch").value.trim();
      if (branch) watch.branch = branch;
      const interval = $("f-git-interval").value.trim();
      if (interval) {
        const value = Number(interval);
        if (!Number.isInteger(value) || value < 1) {
          problems.push({ field: "service.git.interval_secs", message: "must be a whole number of seconds" });
        } else {
          watch.intervalSecs = value;
        }
      }
      watch.enabled = $("f-git-enabled").checked;
      watch.autoUpdate = $("f-git-auto").checked;
      const postPull = parseLines($("f-git-postpull").value);
      if (postPull.length) watch.postPull = postPull;
      spec.git = watch;
    }

    return { spec, problems };
  }

  async function submitForm(event) {
    event.preventDefault();
    const { spec, problems } = collectSpec();
    if (problems.length) { showFormProblems(problems); return; }
    clearFormProblems();
    $("f-save").disabled = true;
    try {
      const reply = await api(`/api/services/${spec.name}`, { method: "PUT", body: spec });
      if (reply.status === 401) { toLogin(); return; }
      if (reply.status === 422 && reply.body && Array.isArray(reply.body.problems)) {
        showFormProblems(reply.body.problems);
        return;
      }
      if (reply.status >= 400) {
        showFormProblems([{ field: "service", message: (reply.body && reply.body.error) || `save failed (${reply.status})` }]);
        return;
      }
      state.formOpen = false;
      notify("done", `Saved ${spec.name}`);
      // `select` renders and re-polls; when the edited service was already
      // chosen it returns early, so those happen here instead.
      if (state.selected === spec.name) { render(); poll(); }
      else select(spec.name);
    } catch {
      showFormProblems([{ field: "service", message: "cannot reach the server" }]);
    } finally {
      $("f-save").disabled = false;
    }
  }

  /* ── the files plate ──────────────────────────────────────────────── */

  /* Everything in this plate obeys the two rules stated in full above
     `urlPath`: a stored name reaches the page through `textContent`, and a
     stored name reaches a URL through `urlPath`. There is no third way to do
     either, on purpose. */

  /** The tree's fetched children by plain path: the directory names inside it,
   *  or null while a fetch is in flight. Kept beside the listing rather than
   *  inside it because the tree outlives any one directory the main pane shows. */
  const treeChildren = new Map();
  /** Which tree nodes the operator has expanded, by plain path. */
  const treeOpen = new Set();
  /** Transfers, oldest first, and the row each one draws itself into. */
  const uploads = [];
  const uploadRows = new Map();
  let uploadSerial = 0;
  /** The listing's order, which belongs to the operator rather than the server:
   *  the daemon answers in its own display order, and this re-sorts what
   *  arrived rather than asking for it again. */
  let sortColumn = "name";
  let sortAscending = true;
  /** The entry being renamed in place, the entry a confirm bar is armed to
   *  delete, and the entry the move bar is moving. One at a time, because two
   *  open forms over one listing is two ways to act on a row that has moved. */
  let renaming = null;
  let condemned = null;
  let moving = null;
  /** How many nested dragenters deep the pointer is over the drop field.
   *  Counted rather than toggled: a drag over a child element fires `dragleave`
   *  on the parent, and a veil that watched only the boolean would flicker. */
  let dropDepth = 0;
  /** What has changed since the last draw. Rebuilding a listing on every poll
   *  would destroy a half-typed rename, so each region is redrawn only when
   *  something it shows actually moved. */
  let sharesDirty = true;
  let treeDirty = true;
  let rowsDirty = true;

  /** Fetches the shares this caller may open.
   *
   *  A 404 — a daemon with no `[[shares]]` — settles to `null` and the plate
   *  says so in a sentence, which is the difference between this and the
   *  firewall panel: an absent firewall is not worth a line, and an absent file
   *  service on a box whose whole point is files is worth exactly one. */
  async function refreshShares() {
    let reply;
    try { reply = await api("/api/storage/shares"); }
    catch { return; }
    if (reply.status === 401) { toLogin(); return; }
    if (reply.status === 200 && reply.body && Array.isArray(reply.body.shares)) {
      state.shares = reply.body.shares.filter((share) => share && usableShareId(share.id));
    } else {
      state.shares = null;
    }
    sharesDirty = true;
    // A share's writability decides which verbs a row offers, so the rows are
    // stale the moment this list is.
    rowsDirty = true;
    const shares = state.shares;
    if (Array.isArray(shares) && shares.length > 0
      && !shares.some((share) => share.id === state.share)) {
      chooseShare(shares[0].id);
      return;
    }
    if (!Array.isArray(shares) || shares.length === 0) {
      state.share = null;
      state.listing = null;
    }
    render();
  }

  /** The chosen share, as the server described it. */
  function currentShare() {
    if (!Array.isArray(state.shares)) return null;
    return state.shares.find((share) => share.id === state.share) || null;
  }

  /** Whether this caller may change anything in the chosen share. The server
   *  decides again on every request; this only greys a button rather than
   *  offering one that will be refused. */
  function shareWritable() {
    const share = currentShare();
    return Boolean(share && share.writable);
  }

  function chooseShare(id) {
    if (!usableShareId(id)) return;
    state.share = id;
    treeChildren.clear();
    treeOpen.clear();
    closeStorageForms();
    openDirectory("");
  }

  /** Navigates to a directory inside the chosen share. */
  function openDirectory(path) {
    state.dir = plainPath(pathSegments(path));
    state.listing = null;
    state.listingNote = "";
    closeStorageForms();
    // Every ancestor of where we are standing is open, so the tree always shows
    // the path taken to get here rather than needing to be re-expanded.
    treeOpen.add("");
    for (const crumb of crumbs(state.dir)) treeOpen.add(crumb.path);
    sharesDirty = true;
    treeDirty = true;
    rowsDirty = true;
    render();
    refreshListing();
    refreshTree();
  }

  /** One directory's contents, or the reason there are none.
   *
   *  Returns null when the session went — the caller has already been sent to
   *  the login page and must not also draw an error over it. */
  async function fetchListing(share, path) {
    let reply;
    try { reply = await api(`/api/storage/shares/${share}/list?path=${urlPath(path)}`); }
    catch { return { ok: false, note: refusalText(0, null) }; }
    if (reply.status === 401) { toLogin(); return null; }
    if (reply.status === 200 && reply.body && Array.isArray(reply.body.entries)) {
      return { ok: true, listing: reply.body };
    }
    return { ok: false, note: refusalText(reply.status, reply.body) };
  }

  /** Fetches the directory the main pane is showing. A reply for a directory
   *  the operator has already navigated away from is discarded rather than
   *  drawn under the wrong breadcrumb. */
  async function refreshListing() {
    const share = state.share;
    const directory = state.dir;
    if (!share) return;
    // Claimed before the await, so `refreshTree` does not fetch the same
    // directory a second time in the gap: this reply fills that node too.
    if (!treeChildren.has(directory)) treeChildren.set(directory, null);
    const answer = await fetchListing(share, directory);
    if (answer === null) return;
    if (state.share !== share || state.dir !== directory) return;
    if (answer.ok) {
      state.listing = answer.listing;
      state.listingNote = "";
      // The same reply fills the tree: the directories the main pane is showing
      // are exactly this node's children, so expanding it costs no fetch.
      treeChildren.set(directory, answer.listing.entries
        .filter((entry) => entry.kind === "directory" && entry.reachable !== false)
        .map((entry) => entry.name));
    } else {
      state.listing = null;
      state.listingNote = answer.note;
      // A directory that could not be read has no children to show, rather than
      // a spinner that never resolves.
      treeChildren.set(directory, []);
    }
    treeDirty = true;
    rowsDirty = true;
    render();
  }

  /** Fetches the children of every expanded tree node that has none yet. */
  async function refreshTree() {
    const share = state.share;
    if (!share) return;
    const wanted = Array.from(treeOpen).filter((path) => !treeChildren.has(path));
    if (wanted.length === 0) return;
    for (const path of wanted) treeChildren.set(path, null);
    await Promise.all(wanted.map(async (path) => {
      const answer = await fetchListing(share, path);
      if (answer === null || state.share !== share) return;
      treeChildren.set(path, answer.ok
        ? answer.listing.entries
          .filter((entry) => entry.kind === "directory" && entry.reachable !== false)
          .map((entry) => entry.name)
        : []);
    }));
    if (state.share !== share) return;
    treeDirty = true;
    render();
  }

  /** Runs one mutating storage request and reports what the server said.
   *
   *  The refusal is the server's own prose, not a word of ours: a `507` carries
   *  the limit, what the share already holds and what the upload needed, and
   *  that sentence is the difference between an operator who knows to delete
   *  something and one who files a bug. */
  async function storageCommand(done, method, path, body) {
    let reply;
    try { reply = await api(path, { method, body }); }
    catch { notify("problem", refusalText(0, null)); return false; }
    if (reply.status === 401) { toLogin(); return false; }
    if (reply.status >= 400) {
      notify("problem", refusalText(reply.status, reply.body));
      return false;
    }
    notify("done", done);
    return true;
  }

  /** Closes every inline form, so navigating never leaves one armed at a row
   *  that is no longer under it. */
  function closeStorageForms() {
    renaming = null;
    condemned = null;
    moving = null;
    rowsDirty = true;
    $("fs-mkdir-row").hidden = true;
    $("fs-move-row").hidden = true;
    $("fs-confirm").hidden = true;
  }

  async function makeDirectory() {
    const name = $("fs-mkdir-name").value.trim();
    const share = state.share;
    if (!share || name === "") return;
    if (joinPath(state.dir, name) === null) {
      notify("problem", "a folder name may not contain a slash, a backslash or a dot on its own");
      return;
    }
    const made = await storageCommand(`Created ${name}`, "POST",
      `/api/storage/shares/${share}/mkdir`, { path: joinPath(state.dir, name) });
    $("fs-mkdir-name").value = "";
    $("fs-mkdir-row").hidden = true;
    if (made) { treeChildren.delete(state.dir); refreshListing(); refreshTree(); }
  }

  /** Renames one entry in place. A rename is a move whose destination is the
   *  same directory, which is why it goes through the same route — two ways to
   *  move a file is two sets of rules about what may overwrite what. */
  async function renameEntry(entry, to) {
    const share = state.share;
    const from = joinPath(state.dir, entry.name);
    const target = joinPath(state.dir, to);
    renaming = null;
    rowsDirty = true;
    if (!share || from === null || target === null || to === entry.name) { render(); return; }
    const moved = await storageCommand(`Renamed to ${to}`, "POST",
      `/api/storage/shares/${share}/rename`, { from, to: target });
    if (moved) { treeChildren.delete(state.dir); refreshListing(); refreshTree(); }
    else render();
  }

  /** Moves one entry into another directory, in this share or another one.
   *
   *  `replace` is never sent, so the server's refusal to destroy something
   *  already at the destination stands: a move that silently overwrote would be
   *  a delete nobody asked for. */
  async function moveEntry(entry, fromDirectory, toShare, toDirectory) {
    const share = state.share;
    const from = joinPath(fromDirectory, entry.name);
    const to = joinPath(toDirectory, entry.name);
    if (!share || from === null || to === null || !usableShareId(toShare)) return;
    if (toShare === share && plainPath(pathSegments(toDirectory)) === plainPath(pathSegments(fromDirectory))) {
      closeStorageForms();
      render();
      return;
    }
    const body = { from, to };
    if (toShare !== share) body.toShare = toShare;
    closeStorageForms();
    const moved = await storageCommand(`Moved ${entry.name}`, "POST",
      `/api/storage/shares/${share}/rename`, body);
    if (moved) {
      treeChildren.delete(fromDirectory);
      treeChildren.delete(toDirectory);
      refreshShares();
      refreshListing();
      refreshTree();
    } else {
      render();
    }
  }

  async function deleteEntry(entry) {
    const share = state.share;
    const path = joinPath(state.dir, entry.name);
    closeStorageForms();
    if (!share || path === null) { render(); return; }
    const gone = await storageCommand(`Deleted ${entry.name}`, "DELETE",
      `/api/storage/shares/${share}/entry?path=${urlPath(path)}`);
    if (gone) {
      treeChildren.delete(state.dir);
      treeChildren.delete(path);
      treeOpen.delete(path);
      refreshShares();
      refreshListing();
      refreshTree();
    } else {
      render();
    }
  }

  /* ── uploads ──────────────────────────────────────────────────────── */

  /** Starts one upload.
   *
   *  **The `File` is handed to the request as its body and is never read.** A
   *  five-gigabyte file has no business in this page's heap: `xhr.send(file)`
   *  lets the browser stream it off the disk with a real `Content-Length`,
   *  which is also the only framing the bulk route accepts. `FormData` would
   *  buy nothing and cost a multipart parse at the other end, and
   *  `file.arrayBuffer()` would put the whole thing in memory to no purpose at
   *  all — on a phone it would simply crash the tab.
   *
   *  `?replace=0` is deliberate: a drag onto a folder must not destroy a file
   *  that is already in it. The `409` that answers a collision is offered back
   *  to the operator as a REPLACE button, which is a decision rather than an
   *  accident. */
  function startUpload(file, replace) {
    const share = state.share;
    const directory = state.dir;
    const path = joinPath(directory, file.name);
    const transfer = {
      id: (uploadSerial += 1),
      name: file.name,
      share,
      directory,
      size: file.size,
      sent: 0,
      startedAt: Date.now(),
      rate: 0,
      state: "sending",
      note: "",
      file,
      request: null,
    };
    uploads.push(transfer);
    if (!share || path === null) {
      transfer.state = "refused";
      transfer.note = "this name cannot be addressed over HTTP — a slash or a backslash in it means "
        + "no URL names this file; copy it in over SMB or rename it at the machine";
      renderUploads();
      return;
    }

    const request = new XMLHttpRequest();
    transfer.request = request;
    const query = replace ? "" : "?replace=0";
    request.open("PUT", `/api/storage/blob/${share}/${urlPath(path)}${query}`, true);
    // The same header every mutating request in this console carries: a page
    // that is not this one cannot set it, and the API refuses a non-GET without
    // it before it touches the store.
    request.setRequestHeader("X-Selfhost-Console", "1");
    request.setRequestHeader("Accept", "application/json");
    request.upload.addEventListener("progress", (event) => {
      if (!event.lengthComputable) return;
      transfer.sent = event.loaded;
      const elapsed = (Date.now() - transfer.startedAt) / 1000;
      transfer.rate = elapsed > 0.4 ? event.loaded / elapsed : 0;
      drawUpload(transfer);
    });
    request.addEventListener("load", () => {
      let body = null;
      try { body = JSON.parse(request.responseText); } catch { /* an empty body is fine */ }
      if (request.status === 401) { toLogin(); return; }
      if (request.status >= 200 && request.status < 300) {
        transfer.state = "done";
        transfer.sent = transfer.size;
        transfer.note = "";
        if (transfer.share === state.share && transfer.directory === state.dir) refreshListing();
        refreshShares();
      } else if (request.status === 409) {
        transfer.state = "collided";
        transfer.note = refusalText(request.status, body);
      } else {
        transfer.state = "refused";
        transfer.note = refusalText(request.status, body);
      }
      drawUpload(transfer);
    });
    request.addEventListener("error", () => {
      transfer.state = "refused";
      transfer.note = refusalText(0, null);
      drawUpload(transfer);
    });
    request.addEventListener("abort", () => {
      transfer.state = "cancelled";
      transfer.note = "cancelled";
      drawUpload(transfer);
    });
    request.send(file);
    renderUploads();
  }

  function startUploads(files) {
    if (!state.share) return;
    if (!shareWritable()) {
      notify("problem", "this share is read-only for you");
      return;
    }
    for (const file of files) startUpload(file, false);
  }

  /** Cancels everything still moving. Called when the session ends, because an
   *  upload that outlives its cookie will be refused mid-body anyway and a row
   *  left counting upwards would be a lie on the way out. */
  function abandonUploads() {
    for (const transfer of uploads) {
      if (transfer.state === "sending" && transfer.request) {
        try { transfer.request.abort(); } catch { /* already finished */ }
      }
    }
    uploads.length = 0;
    for (const row of uploadRows.values()) row.remove();
    uploadRows.clear();
  }

  function clearFinishedUploads() {
    for (let at = uploads.length - 1; at >= 0; at -= 1) {
      if (uploads[at].state === "sending") continue;
      const row = uploadRows.get(uploads[at].id);
      if (row) { row.remove(); uploadRows.delete(uploads[at].id); }
      uploads.splice(at, 1);
    }
    renderUploads();
  }

  /* ── drawing the files plate ──────────────────────────────────────── */

  function renderStorage() {
    const panel = $("storage");
    panel.hidden = state.shares === undefined;
    if (panel.hidden) return;

    const shares = state.shares;
    const sentence = sharesNote(shares);
    $("fs-count").textContent = Array.isArray(shares) ? String(shares.length) : "";
    $("fs-note").hidden = sentence === "";
    $("fs-note").textContent = sentence;

    const have = Array.isArray(shares) && shares.length > 0;
    $("fs-shares").hidden = !have;
    $("fs-panes").hidden = !have;
    if (!have) return;

    renderShareCards();
    renderTree();
    renderCrumbs();
    renderRows();
    renderUploads();
  }

  /** One card per share: what it is, and a gauge of what it holds. */
  function renderShareCards() {
    if (!sharesDirty) return;
    sharesDirty = false;
    const holder = $("fs-shares");
    holder.textContent = "";
    for (const share of state.shares) {
      const card = document.createElement("button");
      card.type = "button";
      card.className = "sharecard";
      if (share.id === state.share) card.setAttribute("aria-current", "true");

      const line = document.createElement("span");
      line.className = "cardline";
      const name = document.createElement("span");
      name.className = "cardname";
      name.textContent = share.id;
      const word = document.createElement("span");
      const readOnly = !share.writable;
      setStateWord(word, readOnly ? "warn" : "ok", readOnly ? "READ ONLY" : "WRITABLE");
      line.append(name, word);

      const reading = quotaReading(share);
      const gauge = document.createElement("span");
      gauge.className = reading.fraction === null && reading.status === "warn"
        ? "gauge unknown" : `gauge ${reading.status}`;
      const lit = document.createElement("span");
      lit.className = "lit";
      lit.style.width = reading.fraction === null ? "0" : `${Math.round(reading.fraction * 100)}%`;
      gauge.append(lit);

      const usage = document.createElement("span");
      usage.className = "cardusage";
      usage.textContent = share.smb && share.smb.name
        ? `${reading.text} · SMB ${share.smb.name}` : reading.text;

      card.append(line, gauge, usage);
      card.addEventListener("click", () => chooseShare(share.id));
      holder.append(card);
    }
  }

  /** The folder tree, drawn from whatever has been fetched so far. A node
   *  nobody has expanded is a twist and nothing else — the tree never walks the
   *  volume on its own, because a share is a disk and a disk can be enormous. */
  function renderTree() {
    if (!treeDirty) return;
    treeDirty = false;
    const tree = $("fs-tree");
    tree.textContent = "";
    tree.append(treeRow(state.share, "", 0, true));
    appendTreeChildren(tree, "", 1);
  }

  function appendTreeChildren(tree, path, depth) {
    if (!treeOpen.has(path)) return;
    const children = treeChildren.get(path);
    if (children === null) {
      const waiting = document.createElement("span");
      waiting.className = "caption dim";
      waiting.style.paddingLeft = `${depth * 11 + 4}px`;
      waiting.textContent = "reading…";
      tree.append(waiting);
      return;
    }
    if (children === undefined) return;
    for (const name of children) {
      const child = joinPath(path, name);
      if (child === null) continue;
      tree.append(treeRow(name, child, depth, false));
      appendTreeChildren(tree, child, depth + 1);
    }
  }

  /** One tree row. The label is a stored name and goes in as text. */
  function treeRow(label, path, depth, isRoot) {
    const row = document.createElement("button");
    row.type = "button";
    row.className = "treerow";
    if (path === state.dir) row.setAttribute("aria-current", "true");
    for (let level = 0; level < depth; level += 1) {
      const tick = document.createElement("span");
      tick.className = "depth";
      row.append(tick);
    }
    const twist = document.createElement("span");
    twist.className = "twist";
    twist.textContent = treeOpen.has(path) ? "▾" : "▸";
    const name = document.createElement("span");
    name.className = "treename";
    name.textContent = isRoot ? String(label || "") : label;
    row.append(twist, name);

    twist.addEventListener("click", (event) => {
      event.stopPropagation();
      if (treeOpen.has(path)) treeOpen.delete(path);
      else treeOpen.add(path);
      treeDirty = true;
      render();
      refreshTree();
    });
    row.addEventListener("click", () => openDirectory(path));
    makeDropTarget(row, () => path);
    return row;
  }

  /** The breadcrumb trail. Each crumb is a drop target, so moving something up
   *  a level is a drag rather than a form. */
  function renderCrumbs() {
    const bar = $("fs-crumbs");
    bar.textContent = "";
    const trail = [{ label: state.share || "", path: "" }].concat(crumbs(state.dir));
    trail.forEach((crumb, index) => {
      if (index > 0) {
        const separator = document.createElement("span");
        separator.className = "sep";
        separator.textContent = "/";
        bar.append(separator);
      }
      const button = document.createElement("button");
      button.type = "button";
      button.className = index === trail.length - 1 ? "crumb here" : "crumb";
      button.textContent = crumb.label;
      button.addEventListener("click", () => openDirectory(crumb.path));
      makeDropTarget(button, () => crumb.path);
      bar.append(button);
    });
    $("fs-up").disabled = state.dir === "";
    const writable = shareWritable();
    $("fs-mkdir").disabled = !writable;
    $("fs-upload").disabled = !writable;
  }

  /** The listing.
   *
   *  Every cell here is `textContent` and every link is `urlPath`. The header of
   *  this file says why at length; this is the function it was written about. */
  function renderRows() {
    if (!rowsDirty) return;
    rowsDirty = false;
    const body = $("fs-rows");
    body.textContent = "";
    const empty = $("fs-empty");
    const listing = state.listing;

    if (!listing) {
      $("fs-table-wrap").hidden = true;
      empty.hidden = false;
      empty.textContent = state.listingNote || "Reading…";
      empty.className = state.listingNote ? "caption centered bad-ink" : "caption centered";
      return;
    }
    $("fs-table-wrap").hidden = false;
    empty.hidden = listing.entries.length > 0;
    empty.className = "caption centered";
    empty.textContent = shareWritable()
      ? "This folder is empty. Drop files on it, or make one inside it."
      : "This folder is empty.";

    for (const entry of sortEntries(listing.entries, sortColumn, sortAscending)) {
      body.append(entryRow(entry));
    }
  }

  function entryRow(entry) {
    const row = document.createElement("tr");
    const directory = entry.kind === "directory";
    const reachable = entry.reachable !== false && joinPath(state.dir, entry.name) !== null;
    if (!reachable) row.classList.add("unreachable");

    const nameCell = document.createElement("td");
    const holder = document.createElement("span");
    holder.className = "entryname";
    const glyph = document.createElement("span");
    glyph.className = "glyph";
    glyph.textContent = directory ? "▣" : "▢";
    holder.append(glyph);

    if (renaming === entry.name) {
      const field = document.createElement("input");
      field.className = "label mono";
      field.value = entry.name;
      field.spellcheck = false;
      field.setAttribute("aria-label", "New name");
      field.addEventListener("keydown", (event) => {
        if (event.key === "Enter") { event.preventDefault(); renameEntry(entry, field.value.trim()); }
        else if (event.key === "Escape") { event.preventDefault(); renaming = null; rowsDirty = true; render(); }
      });
      holder.append(field);
      // Focus after the row is in the document, which it is not yet.
      setTimeout(() => { field.focus(); field.select(); }, 0);
    } else if (!reachable) {
      const label = document.createElement("span");
      label.className = "label";
      label.textContent = entry.name;
      label.title = entry.blockedReason
        ? `unreachable over HTTP: ${entry.blockedReason}` : "unreachable over HTTP";
      holder.append(label);
    } else if (directory) {
      const label = document.createElement("button");
      label.type = "button";
      label.className = "label";
      label.textContent = entry.name;
      label.addEventListener("click", () => openDirectory(joinPath(state.dir, entry.name)));
      holder.append(label);
    } else {
      const label = document.createElement("a");
      label.className = "label";
      label.textContent = entry.name;
      // Straight at the bulk route, so the browser streams it through the
      // Range machinery and a paused download resumes rather than restarting.
      label.href = `/api/storage/blob/${state.share}/${urlPath(joinPath(state.dir, entry.name))}`;
      label.setAttribute("download", entry.name);
      holder.append(label);
    }
    nameCell.append(holder);

    const sizeCell = document.createElement("td");
    sizeCell.className = "numeric mono";
    sizeCell.textContent = directory ? "—" : sizeText(entry.size);

    const whenCell = document.createElement("td");
    whenCell.className = "mono";
    whenCell.textContent = whenText(entry.modified);

    const toolCell = document.createElement("td");
    const tools = document.createElement("span");
    tools.className = "rowtools";
    if (reachable && renaming !== entry.name) {
      if (shareWritable()) {
        tools.append(rowButton("RENAME", "ghost", () => {
          closeStorageForms();
          renaming = entry.name;
          rowsDirty = true;
          render();
        }));
        tools.append(rowButton("MOVE", "ghost", () => openMove(entry)));
        tools.append(rowButton("DELETE", "danger", () => armDelete(entry)));
      }
    }
    toolCell.append(tools);

    row.append(nameCell, sizeCell, whenCell, toolCell);

    if (reachable && shareWritable()) {
      row.draggable = true;
      row.addEventListener("dragstart", (event) => {
        dragged = { share: state.share, directory: state.dir, entry };
        row.classList.add("dragging");
        if (event.dataTransfer) {
          event.dataTransfer.effectAllowed = "move";
          // A payload is set because a drag with none is refused outright by
          // some browsers; nothing ever reads it back, because the source is
          // this page and `dragged` already holds it.
          event.dataTransfer.setData("text/plain", entry.name);
        }
      });
      row.addEventListener("dragend", () => { dragged = null; row.classList.remove("dragging"); });
    }
    if (directory && reachable) makeDropTarget(row, () => joinPath(state.dir, entry.name));
    return row;
  }

  function rowButton(text, kind, act) {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `btn ${kind} small`;
    button.textContent = text;
    button.addEventListener("click", act);
    return button;
  }

  /** What is being dragged inside this page, or null. Held here rather than
   *  read back from the drag payload because `dataTransfer.getData` is
   *  deliberately unreadable during `dragover`, which is when a drop target
   *  must decide whether it wants the drop. */
  let dragged = null;

  /** Makes an element accept an entry dragged from the listing. */
  function makeDropTarget(element, destination) {
    element.addEventListener("dragover", (event) => {
      if (!dragged) return;
      event.preventDefault();
      if (event.dataTransfer) event.dataTransfer.dropEffect = "move";
      element.classList.add("dropping");
    });
    element.addEventListener("dragleave", () => element.classList.remove("dropping"));
    element.addEventListener("drop", (event) => {
      element.classList.remove("dropping");
      if (!dragged) return;
      event.preventDefault();
      event.stopPropagation();
      const into = destination();
      const source = dragged;
      dragged = null;
      if (into === null) return;
      // Dropping a folder into itself, or into where it already is, is not a
      // move; it is the ordinary result of a slightly missed drag.
      const self = joinPath(source.directory, source.entry.name);
      if (self !== null && (into === self || into.startsWith(`${self}/`))) return;
      moveEntry(source.entry, source.directory, source.share, into);
    });
  }

  function openMove(entry) {
    closeStorageForms();
    moving = entry;
    $("fs-move-label").textContent = `Move ${entry.name} into`;
    const picker = $("fs-move-share");
    picker.textContent = "";
    for (const share of state.shares) {
      if (!share.writable) continue;
      const option = document.createElement("option");
      option.value = share.id;
      option.textContent = share.id;
      if (share.id === state.share) option.selected = true;
      picker.append(option);
    }
    $("fs-move-path").value = state.dir;
    $("fs-move-row").hidden = false;
    $("fs-move-path").focus();
  }

  function commitMove() {
    if (!moving) return;
    const entry = moving;
    const toShare = $("fs-move-share").value;
    const toDirectory = $("fs-move-path").value;
    moveEntry(entry, state.dir, toShare, toDirectory);
  }

  /** Arms the delete. A directory goes depth-infinity, which is what the button
   *  means to a person and what `DELETE` means in RFC 4918 — so, exactly like an
   *  uninstall, it takes a typed name rather than a click. A single file is one
   *  confirmation, because it is one thing and the operator can see which. */
  function armDelete(entry) {
    closeStorageForms();
    condemned = entry;
    const directory = entry.kind === "directory";
    const bar = $("fs-confirm");
    const input = $("fs-confirm-input");
    $("fs-confirm-label").textContent = directory
      ? `Type ${entry.name} to delete this folder and everything inside it`
      : `Delete ${entry.name}?`;
    input.hidden = !directory;
    input.value = "";
    $("fs-confirm-go").disabled = directory;
    bar.hidden = false;
    if (directory) input.focus();
  }

  /* ── the transfer log ─────────────────────────────────────────────── */

  function renderUploads() {
    const panel = $("fs-transfers");
    panel.hidden = uploads.length === 0;
    if (panel.hidden) return;
    const active = uploads.filter((transfer) => transfer.state === "sending").length;
    $("fs-transfer-count").textContent = active > 0
      ? `${active} MOVING · ${uploads.length}` : String(uploads.length);
    const list = $("fs-uploads");
    for (const transfer of uploads) {
      if (!uploadRows.has(transfer.id)) list.append(buildUploadRow(transfer));
      drawUpload(transfer);
    }
  }

  function buildUploadRow(transfer) {
    const row = document.createElement("li");
    const name = document.createElement("span");
    name.className = "upname mono";
    name.textContent = transfer.name;
    const note = document.createElement("span");
    note.className = "upnote";
    const rule = document.createElement("span");
    rule.className = "rule";
    const action = document.createElement("button");
    action.type = "button";
    action.className = "btn ghost small";
    const bar = document.createElement("span");
    bar.className = "bar";
    const fill = document.createElement("span");
    fill.className = "fill";
    bar.append(fill);
    const line = document.createElement("span");
    line.className = "upline";
    line.append(bar);
    row.append(name, note, rule, action, line);
    action.addEventListener("click", () => actOnUpload(transfer));
    uploadRows.set(transfer.id, row);
    return row;
  }

  /** Updates one transfer's row in place. In place rather than rebuilt because
   *  a progress event arrives many times a second and a rebuilt row cannot be
   *  clicked. */
  function drawUpload(transfer) {
    const row = uploadRows.get(transfer.id);
    if (!row) return;
    const [, note, , action, line] = row.children;
    const bar = line.firstElementChild;
    const fill = bar.firstElementChild;
    const fraction = transfer.size > 0 ? Math.min(1, transfer.sent / transfer.size) : 0;

    if (transfer.state === "sending") {
      note.className = "upnote";
      note.textContent = transferLine(transfer.sent, transfer.size, transfer.rate);
      bar.className = "bar";
      fill.style.width = `${Math.round(fraction * 100)}%`;
      action.textContent = "CANCEL";
      action.hidden = false;
      action.className = "btn ghost small";
    } else if (transfer.state === "done") {
      note.className = "upnote";
      note.textContent = `sent · ${sizeText(transfer.size)}`;
      bar.className = "bar done";
      fill.style.width = "100%";
      action.hidden = true;
    } else if (transfer.state === "collided") {
      note.className = "upnote warn-ink";
      note.textContent = `${transfer.note} — replacing is a decision, not a default`;
      bar.className = "bar bad";
      fill.style.width = "100%";
      action.textContent = "REPLACE";
      action.hidden = false;
      action.className = "btn small";
    } else {
      note.className = "upnote bad-ink";
      note.textContent = transfer.note;
      bar.className = "bar bad";
      fill.style.width = "100%";
      action.hidden = transfer.state === "cancelled";
      action.textContent = "RETRY";
      action.className = "btn ghost small";
    }
  }

  function actOnUpload(transfer) {
    if (transfer.state === "sending") {
      if (transfer.request) { try { transfer.request.abort(); } catch { /* already finished */ } }
      return;
    }
    if (transfer.state === "collided" || transfer.state === "refused") {
      const at = uploads.indexOf(transfer);
      if (at >= 0) uploads.splice(at, 1);
      const row = uploadRows.get(transfer.id);
      if (row) { row.remove(); uploadRows.delete(transfer.id); }
      startUpload(transfer.file, transfer.state === "collided");
      renderUploads();
    }
  }

  /* ── the desktop plate ────────────────────────────────────────────── */

  /* The viewport is drawn from ArrayBuffers through `putImageData` and nothing
     else. That is a security decision before it is a rendering one: this page's
     CSP is `default-src 'none'` with no `blob:` and no `data:`, which forbids
     blob URLs, `createImageBitmap`, Workers and WebCodecs as written — and that
     CSP is the strongest single defence the console has, so the viewport is
     built to need no widening of it.

     WATCHING AND DRIVING ARE TWO STREAMS, NOT TWO MODES OF ONE. A stream's
     capability set is fixed in the `Hello` the agent sends and this page cannot
     widen one, so taking the keyboard means minting a ticket that authorises it
     and opening a *second* stream with that ticket. That is not a limitation
     worked around: it is the mechanism. A session opened this morning cannot
     become a keyboard, because becoming one requires a credential presented at
     the moment it is asked for. What survives the handover is the picture on
     the canvas, so the operator does not watch a black rectangle for a round
     trip every time they reach for the keyboard.

     WHAT IS SENT, AND ONLY WHAT IS SENT. A watching stream sends exactly one
     message — `RequestFullFrame`, which the driver honours at `VIEW`, carries no
     capability and cannot type. A driving stream adds keys, pointer positions,
     buttons, the wheel, pasted text, and the release that undoes all of it. It
     sends nothing while the frame is not focused, so a console left open in a
     background tab is a console typing nowhere. */

  /** How often the plate's own clock ticks while a session is up: the frame's
   *  age, the frame rate and the round trips. */
  const DESK_TICK = 1000;
  /** How often the first hop is timed. Often enough to notice a tunnel going
   *  bad mid-session, rarely enough to be free. */
  const HOP_INTERVAL = 5000;
  /** How long a refusal stays on the picture after the last one arrived.
   *
   *  Long enough to be read, short enough that a refusal from a minute ago is
   *  not still being shown over a session that has since started working —
   *  which would be a banner that lies, and a banner that lies is worse than no
   *  banner at all. */
  const REFUSAL_LINGER = 9000;
  /** How many unsent bytes make the link "backed up", after which pointer
   *  positions are dropped rather than queued.
   *
   *  Only pointer positions, and only because each one supersedes the last: a
   *  keystroke dropped is a keystroke lost, but a position dropped is a position
   *  that was about to be wrong anyway. Queueing them is what makes a slow link
   *  feel like a broken one — the pointer arrives seconds behind the hand. */
  const POINTER_BACKLOG = 64 * 1024;
  /** How often the audit trail refreshes itself while a keyboard is live.
   *
   *  Only while one is: the trail is written when a machine is driven, so this
   *  is the one time it changes under the reader, and it is also the one time
   *  the reader is most entitled to see it change. */
  const AUDIT_INTERVAL = 10000;
  /** How long the browser is given to answer a request for the clipboard.
   *
   *  Generous, because a permission prompt is a person deciding, and finite,
   *  because a prompt that is never shown is a promise that never settles. */
  const CLIPBOARD_DEADLINE = 8000;

  /** Everything one desktop session knows. Reset wholesale on connect, so a
   *  second session cannot inherit a reading from the first. */
  const desk = freshDesk();
  let deskTimer = null;
  let hopTimer = null;
  /* The plate ticks once a second while a session is up, so the two regions
     that are rebuilt rather than updated are drawn only when what they would
     show actually changed. Rebuilding a button a person is about to click is
     how a console loses a click. */
  let peersDrawn = "";
  let monitorsDrawn = "";
  let heldDrawn = "";
  /* The operator's standing intent, which outlives any one stream: whether the
     next session should ask for a keyboard, and whether it should carry the
     clipboard. Kept apart from `desk` precisely because `desk` is emptied on
     every handover and this must not be. */
  let wantControl = false;
  let wantClipboard = false;
  /* What the plate is doing that has no state of its own: minting a ticket,
     waiting on an authenticator. A sentence, shown and then cleared. */
  let deskBusy = "";
  /* The plate's last word about a control request — a refusal in prose, or the
     note that says what this session is. Never an error code. */
  let deskSaid = "";
  /* What is pending behind an authorisation prompt, so the retry asks for
     exactly what was refused rather than for whatever the toggles say by the
     time the operator finishes at the fingerprint reader. */
  let pendingWant = null;
  /* How the clipboard bridge last behaved, as one of `clipboardSentence`'s
     states. */
  let clipboardState = "off";

  function freshDesk() {
    return {
      socket: null,
      phase: "idle",        // "idle" | "opening" | "watching"
      why: "",              // why the last session ended, in the closer's words
      hello: null,
      notice: 1,
      detail: "",
      refusal: null,        // {code, count, at} — the last input refusal, and how many
      monitor: 0,
      geometry: null,       // {width, height} of the display being drawn
      sequence: null,
      lastFrameAt: 0,
      frames: 0,
      tiles: 0,
      bytes: 0,
      gaps: 0,
      stalls: null,
      recent: [],           // frame instants inside the last few seconds, for the rate
      hopMs: null,
      endMs: null,
      askedFullAt: 0,
      cursor: null,         // {x, y, visible, hotspotX, hotspotY, width, height}
      scale: 1,

      /* ── the driving half ──────────────────────────────────────────
         `granted` is read from the `Hello` and never from what was asked for:
         the point of the agent echoing the capability set is that the screen
         states what is true rather than what was requested, and a ticket whose
         grant was revoked between the mint and the handshake opens a
         *downgraded* stream rather than being refused.

         `held` and `buttons` are this console's belief about what is currently
         down on somebody else's machine. They exist so that belief can be
         undone — which is the whole of the answer to a link that dies mid-key,
         and the reason the strip showing them is on screen. */
      granted: 0,
      focused: false,
      held: new Set(),      // KeyboardEvent.code of every key believed down
      buttons: new Set(),   // wire button codes believed down
      sent: 0,              // input messages this session has sent
      refused: 0,           // input events the far end declined
      dropped: 0,           // pointer positions dropped rather than queued
      wheelX: 0,            // sub-unit wheel remainders, so a trackpad still scrolls
      wheelY: 0,
      pointerX: null,       // the last position sent, so a still pointer sends nothing
      pointerY: null,
    };
  }

  function resetDesk() {
    Object.assign(desk, freshDesk());
  }

  /** Whether this session was actually granted a keyboard.
   *
   *  From the `Hello`, always. Asking what the ticket requested would answer the
   *  question the console asked rather than the one the daemon decided, and
   *  those differ exactly when a grant was withdrawn while the ticket was in
   *  flight — which is the case worth getting right. */
  function driving() {
    return (desk.granted & 0x02) !== 0;
  }

  /** Whether the clipboard bridge was granted as well. */
  function bridging() {
    return (desk.granted & 0x04) !== 0;
  }

  /** Whether there is an open stream to write to. */
  function streamOpen() {
    return Boolean(desk.socket) && desk.socket.readyState === 1;
  }

  /** When the desktop plate last asked the daemon anything, and how long it
   *  waits between askings.
   *
   *  The full poll runs every second when there is no push stream, and this
   *  plate costs three requests — so riding that cadence would nearly double
   *  the console's traffic to keep a fleet list fresh that changes on the scale
   *  of minutes. The interval is the plate's own, and a live session refreshes
   *  the reading that does move on its own clock. */
  const DESKTOP_INTERVAL = 4000;
  let desktopFetchedAt = 0;

  /** Fetches the desktop subsystem's own account of itself: the operator's
   *  switches, the machines this caller may watch, and what the agent on the
   *  chosen one is doing. A 404 settles to `null`, which the plate renders as a
   *  sentence rather than as an error. */
  async function refreshDesktop() {
    const now = Date.now();
    if (now - desktopFetchedAt < DESKTOP_INTERVAL) return;
    desktopFetchedAt = now;
    let settings;
    try { settings = await api("/api/desktop"); }
    catch { return; }
    if (settings.status === 401) { toLogin(); return; }
    if (settings.status !== 200 || !settings.body) {
      state.desktop = null;
      state.nodes = [];
      state.agent = null;
      return;
    }
    state.desktop = settings.body;

    try {
      const nodes = await api("/api/desktop/nodes");
      if (nodes.status === 401) { toLogin(); return; }
      state.nodes = nodes.status === 200 && nodes.body && Array.isArray(nodes.body.nodes)
        ? nodes.body.nodes.filter((node) => node && usableNodeName(node.node)) : [];
    } catch { return; }
    if (state.nodes.length > 0 && !state.nodes.some((node) => node.node === state.peer)) {
      state.peer = state.nodes[0].node;
    }
    if (!usableNodeName(state.peer)) return;

    try {
      const agent = await api(`/api/desktop/agent?peer=${encodeURIComponent(state.peer)}`);
      if (agent.status === 401) { toLogin(); return; }
      state.agent = agent.status === 200 && agent.body && typeof agent.body.sentence === "string"
        ? agent.body : null;
      // The stall counter belongs to the capture loop on the far side, so this
      // console can only report what the daemon states. It is read
      // optimistically: a daemon that carries the field shows a number, and one
      // that does not shows a dash rather than a zero it never claimed.
      desk.stalls = state.agent ? finiteNumber(state.agent.creditStalls) : null;
    } catch { /* the nodes list is the connectivity signal for this plate */ }
  }

  function chooseNode(name) {
    if (!usableNodeName(name) || name === state.peer) return;
    if (desk.socket) closeDesktop("you switched to another machine");
    state.peer = name;
    state.agent = null;
    render();
    // Asked for now rather than at the next interval: the operator has just
    // pointed at a machine and is waiting to be told about that one.
    desktopFetchedAt = 0;
    refreshDesktop().then(render);
  }

  /** The abilities the next session should ask for, from the operator's
   *  standing intent.
   *
   *  `desktop.view` is always in the list even though the daemon adds it
   *  itself — `Ability::implies` makes control and clipboard both imply it,
   *  because the wire refuses either without VIEW. Naming it here anyway keeps
   *  the request a complete statement of what the console wants rather than a
   *  fragment that only means the right thing after the server finishes it. */
  function wantedAbilities() {
    const want = ["desktop.view"];
    if (wantControl) want.push("desktop.control");
    if (wantControl && wantClipboard) want.push("desktop.clipboard");
    return want;
  }

  /** Mints the single-use credential a handshake must present, or says why not.
   *
   *  Two steps for the reason the events stream is two steps — a page cannot put
   *  a custom header on a handshake, so the CSRF-protected moment is moved into
   *  an ordinary `POST` and the handshake carries proof it happened. **The URL
   *  never names a capability**: the daemon derives the minimum ability from the
   *  target and takes everything above it from the redeemed ticket, because a
   *  query string asking for a keyboard would be a keyboard a page could ask for
   *  with no header at all. */
  async function mintTicket(want) {
    let reply;
    try {
      reply = await api("/api/desktop/ticket", {
        method: "POST",
        body: { want, peer: state.peer },
      });
    } catch {
      return { refusal: controlRefusal(0, null) };
    }
    if (reply.status >= 200 && reply.status < 300) {
      const ticket = reply.body && reply.body.ticket;
      return usableTicket(ticket)
        ? { ticket }
        : { refusal: { kind: "error", text: "the daemon issued no usable ticket" } };
    }
    if (reply.status === 401 && !(await sessionAlive())) { toLogin(); return { gone: true }; }
    return { refusal: controlRefusal(reply.status, reply.body) };
  }

  /** Whether the console's own session is still accepted.
   *
   *  Asked only after a 401 on a mint, and it is the difference between two
   *  answers that are identical on the wire and want opposite responses: a
   *  session that has expired must send the operator to the login page, and a
   *  session that is perfectly good but holds no grant for this machine must
   *  not. Throwing an authorised operator out of the console because they asked
   *  for a keyboard they do not have would be a fault they would report as the
   *  console logging them out at random. */
  async function sessionAlive() {
    try { return (await api("/api/session")).status === 200; }
    catch { return false; }
  }

  /** Opens a session with exactly the abilities named — or replaces the one
   *  that is up, when the operator reaches for the keyboard or gives it back.
   *
   *  The ticket is minted **before** anything is torn down, so a refusal leaves
   *  the session that is running exactly as it was. That ordering is the whole
   *  reason asking for a keyboard and being told no does not cost the operator
   *  the picture they were watching. */
  async function openDesktop(want, doing) {
    if (deskBusy) return;
    if (!usableNodeName(state.peer)) return;
    deskBusy = doing;
    deskSaid = "";
    hideAuthorisation();
    renderDesktop();

    let minted;
    try { minted = await mintTicket(want); }
    finally { deskBusy = ""; }
    if (minted.gone) return;
    if (minted.refusal) { refusedControl(minted.refusal, want); return; }
    handOver(minted.ticket);
  }

  /** Swaps whichever stream is up for one opened with this ticket.
   *
   *  Everything held is released **through the outgoing socket, before it is
   *  dropped**. A key believed down on the far machine is the one piece of state
   *  this console owns that lives on somebody else's computer, and abandoning a
   *  socket while it is set is how a remote session leaves a stranger's machine
   *  with a stuck Command key.
   *
   *  The picture is carried across deliberately. Everything else is emptied,
   *  because a reading from the previous stream shown against the new one would
   *  be a measurement of a connection that no longer exists — but the pixels on
   *  the canvas are still an honest picture of that machine, and the frame line
   *  goes on reporting exactly how old they are. */
  function handOver(ticket) {
    const held = desk.phase === "watching" || desk.phase === "opening"
      ? {
        frames: desk.frames,
        lastFrameAt: desk.lastFrameAt,
        geometry: desk.geometry,
        monitor: desk.monitor,
        cursor: desk.cursor,
        stalls: desk.stalls,
      }
      : null;
    releaseEverything();
    dropDeskSocket();
    stopDeskClock();
    resetDesk();
    if (held) Object.assign(desk, held);

    const scheme = location.protocol === "https:" ? "wss:" : "ws:";
    const target = `${scheme}//${location.host}/api/desktop/session?peer=${encodeURIComponent(state.peer)}`;
    let socket;
    try { socket = new WebSocket(target, deskProtocols(ticket)); }
    catch { settleDesk("idle", "the browser refused the handshake"); return; }
    desk.phase = "opening";
    desk.socket = socket;
    socket.binaryType = "arraybuffer";
    socket.addEventListener("open", onDeskOpen);
    socket.addEventListener("message", onDeskFrame);
    socket.addEventListener("close", onDeskClose);
    socket.addEventListener("error", onDeskClose);
    renderDesktop();
  }

  /** Opens a watching session. */
  function connectDesktop() {
    return openDesktop(wantedAbilities(), "minting a ticket and opening the stream");
  }

  /** Asks for the keyboard, and proves who is asking at the moment of asking.
   *
   *  # Why the prompt is here and not at the login page
   *
   *  Because a console session is a door and a keyboard on somebody's machine is
   *  not the same thing as being allowed through a door. A session opened this
   *  morning and left in a tab is exactly as valid as one opened a second ago,
   *  which is the right rule for reading a service list and the wrong one for
   *  typing on a desk somebody may be sitting at. The daemon enforces the
   *  difference — `[desktop].reauth_window_secs` — and answers a stale request
   *  with a 403 that says so. This is the console honouring that answer rather
   *  than working around it: the passkey is offered when the daemon asks for it,
   *  and the session it mints is what makes the retry succeed.
   *
   *  The mint is attempted first rather than prompting unconditionally, because
   *  a login a few seconds old is already fresh and a biometric prompt for it
   *  would be theatre — and a console that asks for a fingerprint it does not
   *  need is a console people learn to dismiss without reading. */
  function takeControl() {
    wantControl = true;
    const want = wantedAbilities();
    // A machine nobody is watching yet goes straight to a driving session; there
    // is no reason to open a stream twice.
    return openDesktop(want, "asking for a keyboard");
  }

  /** Gives the keyboard back, keeping the picture.
   *
   *  A separate act rather than a disconnect, because the operator who has
   *  finished typing usually has not finished watching, and because a session
   *  that may drive and is not being driven is a keyboard left within reach of
   *  whatever else is behind this loopback gate. */
  function releaseControl() {
    wantControl = false;
    if (desk.phase === "idle") { deskSaid = ""; renderDesktop(); return; }
    return openDesktop(wantedAbilities(), "giving the keyboard back");
  }

  /** Forgets that a keyboard was ever wanted. Used when the session ends, so
   *  that a stream re-opened later opens as a watcher. */
  function forgetControl() {
    wantControl = false;
    wantClipboard = false;
    pendingWant = null;
    deskSaid = "";
    clipboardState = "off";
  }

  /** What to do about a refused mint.
   *
   *  Each of the daemon's three legible refusals gets the response it actually
   *  calls for, and a switch in a file on the box gets the response it *does
   *  not*: offering the biometric prompt for `[desktop].allow_input = false`
   *  would be the console asking for a fingerprint to change a setting a
   *  fingerprint cannot change. The toggle that was refused is turned back off
   *  in the same breath, so the console's own state agrees with the box's rather
   *  than asking again on the next click. */
  function refusedControl(refusal, want) {
    if (refusal.kind === "reauthenticate") {
      pendingWant = want;
      askForAuthorisation(refusal.text);
      return;
    }
    if (refusal.kind === "switch") {
      if (refusal.setting === "[desktop].allow_clipboard") {
        wantClipboard = false;
        clipboardState = "disabled";
      } else {
        wantControl = false;
      }
    }
    if (refusal.kind === "denied") wantControl = false;
    // The sentence lives in one place — under the button that was refused —
    // rather than also in the plate's own note, where it would be the same
    // refusal read twice. A refusal to *widen* a session leaves the session
    // that is running exactly as it was.
    deskSaid = refusal.text;
    renderDesktop();
  }

  /* ── proving a person is here ──────────────────────────────────────── */

  /** Opens the authorisation row and, where a passkey exists, goes straight for
   *  it — the operator clicked TAKE CONTROL and the answer to that click is the
   *  prompt, not another button to press.
   *
   *  The row is opened *first* so that the fallback is already on screen if the
   *  browser declines to show the prompt at all. Browsers require a recent user
   *  gesture for `navigator.credentials.get`, and the round trip that fetches
   *  the challenge can be long enough over a tunnel to spend it — in which case
   *  the assertion fails in milliseconds without any prompt appearing, and
   *  PROVE IT IS YOU is a fresh gesture that will work. */
  function askForAuthorisation(why) {
    const row = $("dv-reauth");
    row.hidden = false;
    $("dv-reauth-note").textContent = `${why} — prove you are here, and the keyboard opens.`;
    const canPasskey = Boolean(window.PublicKeyCredential);
    $("dv-reauth-go").hidden = !canPasskey;
    showPasswordFallback(!canPasskey, !canPasskey);
    renderDesktop();
    if (canPasskey) proveWithPasskey({ quiet: true });
    else $("dv-reauth-pass").focus();
  }

  function hideAuthorisation() {
    $("dv-reauth").hidden = true;
    $("dv-reauth-pass").value = "";
  }

  /** Shows or hides the password half of the row.
   *
   *  The password is not a lesser door here: the daemon measures a session's
   *  *age*, and both credentials mint a new session. It is second because a
   *  passkey proves a person is physically present at this machine, which a
   *  password typed into a tab does not — but a deployment with no passkey
   *  registered must still be able to reach a keyboard, or the feature would be
   *  unavailable to exactly the operator who has not set one up yet. */
  function showPasswordFallback(show, focus) {
    $("dv-reauth-pass").hidden = !show;
    $("dv-reauth-pass-go").hidden = !show;
    // Offered without being aimed at when a passkey is still the better route:
    // a cursor that jumped into a password box would be the console pushing
    // the operator towards the weaker of the two doors.
    if (show && focus) $("dv-reauth-pass").focus();
  }

  /** The passkey half. `quiet` suppresses the wording for the one failure that
   *  is not a failure — a browser that would not show the prompt — because the
   *  answer to that is the button now on screen rather than a sentence. */
  async function proveWithPasskey(options = {}) {
    $("dv-reauth-go").disabled = true;
    $("dv-reauth-note").textContent = "waiting for the authenticator…";
    let proof;
    try { proof = await passkeyAssertion(); }
    finally { $("dv-reauth-go").disabled = false; }
    if (proof.ok) { authorised(); return; }
    if (proof.noPasskey) {
      $("dv-reauth-go").hidden = true;
      $("dv-reauth-note").textContent = "No passkey is registered on this deployment. "
        + "The console password re-opens the session just as well; a passkey is the better "
        + "credential for this and is registered under PASSKEYS.";
      showPasswordFallback(true, true);
      return;
    }
    // Whatever went wrong, the other door opens now. A browser that speaks
    // WebAuthn but can reach no authenticator this deployment knows — a
    // machine whose reader is not enrolled, a security key left at home —
    // would otherwise face a button that can never succeed, and a dead end in
    // an authorisation flow is how an operator loses access to their own
    // machine. The password is the root credential here, not a lesser one.
    $("dv-reauth-note").textContent = proof.quick && options.quiet
      ? "Press PROVE IT IS YOU, or authorise with the console password."
      : proof.quick
        ? "The browser would not show the prompt. Press PROVE IT IS YOU again, or use the password."
        : `${proof.text}. The keyboard was not opened.`;
    showPasswordFallback(true, !proof.quick);
  }

  /** The password half: the same act through the other door. */
  async function proveWithPassword() {
    const field = $("dv-reauth-pass");
    const password = field.value;
    if (password === "") { field.focus(); return; }
    $("dv-reauth-pass-go").disabled = true;
    let reply;
    try { reply = await api("/api/session", { method: "POST", body: { password } }); }
    catch {
      $("dv-reauth-note").textContent = "cannot reach the server. The keyboard was not opened.";
      $("dv-reauth-pass-go").disabled = false;
      return;
    }
    $("dv-reauth-pass-go").disabled = false;
    field.value = "";
    if (reply.status >= 200 && reply.status < 300) { rememberUser(reply); authorised(); return; }
    $("dv-reauth-note").textContent = reply.status === 429
      ? "too many attempts, wait a minute. The keyboard was not opened."
      : "not accepted. The keyboard was not opened.";
    field.focus();
  }

  /** A person proved they are here. Retry exactly what was refused.
   *
   *  `pendingWant` rather than `wantedAbilities()`, because the toggles may have
   *  been moved while the operator was at the fingerprint reader and the thing
   *  that was authorised is the thing that was asked for. */
  function authorised() {
    showUser();
    hideAuthorisation();
    const want = pendingWant || wantedAbilities();
    pendingWant = null;
    openDesktop(want, "opening the keyboard");
  }

  function onDeskOpen() {
    desk.phase = "watching";
    desk.why = "";
    // The first end-to-end measurement rides the frame the session needs
    // anyway: the driver has no surface for this client yet, so the keyframe is
    // coming regardless and timing it costs nothing.
    askFullFrame();
    startDeskClock();
    renderDesktop();
  }

  /** One message. Binary always: the codec sends no text frames, so a text
   *  frame arriving would be a protocol error rather than a message, and
   *  nothing in this path needs a UTF-8 validator. A payload this build cannot
   *  read is dropped without disturbing what is on screen. */
  function onDeskFrame(event) {
    if (typeof event.data === "string") return;
    let bytes;
    try { bytes = new Uint8Array(event.data); } catch { return; }
    desk.bytes += bytes.length;
    const message = deskMessage(bytes);
    if (!message) return;

    switch (message.kind) {
      case "hello":
        desk.hello = message;
        // What the session *is*, from the machine's own mouth. A ticket that
        // asked for a keyboard and a stream that was given one are different
        // facts, and this is the second: a grant withdrawn between the mint and
        // the handshake opens a downgraded stream, and the plate must show the
        // stream rather than the request.
        desk.granted = message.capabilities;
        desk.monitor = message.monitors.length > 0 ? message.monitors[0].id : 0;
        if (!driving() && wantControl) {
          deskSaid = "the stream opened without a keyboard — the grant for this machine "
            + "was withdrawn between the ticket and the handshake";
          wantControl = false;
        }
        if (driving() && wantClipboard && !bridging()) {
          clipboardState = "disabled";
        }
        scheduleAudit();
        renderDesktop();
        break;
      case "status":
        desk.notice = message.notice;
        desk.detail = message.detail;
        renderDesktop();
        break;
      case "frameBegin":
        beginFrame(message);
        break;
      case "tile":
        paintTile(message);
        break;
      case "frameEnd":
        endFrame();
        break;
      case "cursorPos":
        moveCursor(message);
        break;
      case "cursorShape":
        paintCursor(message);
        break;
      case "inputRefused":
        noteRefusal(message.reason);
        break;
      default:
        break;
    }
  }

  /** Records an input refusal, whether it came back from the agent or was
   *  decided here.
   *
   *  **A refused input must never be silent.** It is the one fault in this whole
   *  subsystem with no other symptom: the picture keeps arriving, the readings
   *  stay green, and the operator's keys do nothing. That is precisely the
   *  experience that makes a person conclude software is broken, because there
   *  is nothing to act on and nothing to report. So every refusal reaches the
   *  screen in the agent's own sentence, with the console's own advice under it,
   *  and repeated refusals raise a count instead of flickering.
   *
   *  A locally-decided refusal — a key with no mapping on the far platform — is
   *  recorded here rather than sent and bounced, because the answer is the same
   *  sentence and a round trip would only delay it. */
  function noteRefusal(code) {
    const same = desk.refusal && desk.refusal.code === code;
    desk.refusal = {
      code,
      count: same ? desk.refusal.count + 1 : 1,
      at: Date.now(),
    };
    desk.refused += 1;
    renderDesktop();
  }

  function onDeskClose(event) {
    if (!desk.socket) return;
    const said = event && typeof event.reason === "string" ? event.reason.trim() : "";
    const code = event && typeof event.code === "number" ? event.code : 0;
    // Nothing may be believed held across a closed channel. The agent releases
    // everything on its own when a channel goes — recovery must not depend on a
    // message from the peer that just disappeared — so this is bookkeeping
    // rather than a cure, and its job is to stop the strip from showing keys
    // that are no longer down anywhere.
    const drove = desk.sent > 0;
    desk.held.clear();
    desk.buttons.clear();
    dropDeskSocket();
    settleDesk("idle", said || (code === 1000 ? "the machine closed the session" : "the link went"));
    scheduleAudit();
    // What was done is worth reading straight after it stops being done.
    if (drove) refreshAudit();
  }

  /** Forgets the socket without letting its own close handler fire, so closing
   *  on purpose does not also report a link failure. */
  function dropDeskSocket() {
    const going = desk.socket;
    desk.socket = null;
    if (!going) return;
    going.removeEventListener("open", onDeskOpen);
    going.removeEventListener("message", onDeskFrame);
    going.removeEventListener("close", onDeskClose);
    going.removeEventListener("error", onDeskClose);
    try { going.close(); } catch { /* already gone */ }
  }

  /** Ends the session on purpose.
   *
   *  **There is no automatic reconnection here, unlike the events stream**, and
   *  that is the design rather than an omission: a ticket is single-use and
   *  lives thirty seconds, so reconnecting means minting a fresh credential, and
   *  a console that silently re-opens a view of somebody's screen is a console
   *  that watches a desk nobody is standing at. Coming back is one click, and it
   *  is the operator's.
   *
   *  A keyboard is never inherited by the next session either, for the same
   *  reason and a stronger one: control was authorised by a credential presented
   *  at a moment that has passed, and re-opening it must ask again. */
  function closeDesktop(why) {
    const drove = desk.sent > 0;
    releaseEverything();
    dropDeskSocket();
    stopDeskClock();
    forgetControl();
    hideAuthorisation();
    settleDesk("idle", why || "");
    scheduleAudit();
    if (drove) refreshAudit();
  }

  function settleDesk(phase, why) {
    desk.phase = phase;
    desk.why = why;
    if (phase === "idle") {
      stopDeskClock();
      // A session that has ended grants nothing. `granted` is read by
      // everything that decides whether this console may type — the mode
      // banner, the held strip, the clipboard row, the audit refresh — and
      // leaving the previous stream's grant in it would leave a disconnected
      // plate offering to give back a keyboard nobody holds.
      desk.granted = 0;
    }
    renderDesktop();
  }

  function startDeskClock() {
    stopDeskClock();
    deskTimer = setInterval(renderDesktop, DESK_TICK);
    hopTimer = setInterval(measureHop, HOP_INTERVAL);
    measureHop();
  }

  function stopDeskClock() {
    clearInterval(deskTimer);
    clearInterval(hopTimer);
    deskTimer = null;
    hopTimer = null;
  }

  /** Times the first hop, and refreshes what the far side is reporting.
   *
   *  Two jobs in one request on purpose. The hop is *this browser to the admin
   *  API*, through the tunnel and the reverse proxy — a WebSocket ping would be
   *  the natural instrument and a page cannot send one, so the round trip is
   *  measured around the cheapest request the API serves, riding the connection
   *  the console already holds open so that what it measures is the tunnel
   *  rather than a fresh handshake.
   *
   *  The agent route is the request chosen because it is answered from the
   *  daemon's own state with no second hop of its own — so it is still a
   *  first-hop measurement — and it carries the one number this console cannot
   *  observe for itself. `credit_stalls` belongs to the capture loop on the far
   *  side, is per session, and is reset here when a session opens; without this
   *  it would sit at its opening value for the life of the stream, which is a
   *  starved link reported as a healthy one. */
  async function measureHop() {
    if (!usableNodeName(state.peer)) return;
    const started = (typeof performance !== "undefined" ? performance.now() : Date.now());
    let reply;
    try { reply = await api(`/api/desktop/agent?peer=${encodeURIComponent(state.peer)}`); }
    catch { return; }
    if (reply.status === 401) { toLogin(); return; }
    if (reply.status !== 200 || !reply.body) return;
    const ended = (typeof performance !== "undefined" ? performance.now() : Date.now());
    desk.hopMs = ended - started;
    if (typeof reply.body.sentence === "string") state.agent = reply.body;
    desk.stalls = finiteNumber(reply.body.creditStalls);
    renderDesktop();
  }

  /** Asks the far machine for a whole frame, and starts the end-to-end clock.
   *
   *  The round trip from this byte to the keyframe that answers it runs through
   *  every hop there is — the tunnel, this box, the link to the machine, and the
   *  machine's own capture — which is exactly the number that, set beside the
   *  hop, says which half of a slow session is slow. */
  function askFullFrame() {
    if (!desk.socket || desk.socket.readyState !== 1) return;
    try { desk.socket.send(requestFullFrame(desk.monitor)); }
    catch { return; }
    desk.askedFullAt = (typeof performance !== "undefined" ? performance.now() : Date.now());
    desk.sequence = null;
  }

  /** Asks for a different display. `RequestFullFrame` names a monitor, which is
   *  how a viewer changes screens: there is no other message for it, and there
   *  deliberately is not — switching displays is asking for a picture, not
   *  driving the machine. */
  function chooseMonitor(id) {
    if (desk.monitor === id) return;
    desk.monitor = id;
    desk.geometry = null;
    desk.cursor = null;
    askFullFrame();
    renderDesktop();
  }

  function beginFrame(frame) {
    if (frame.monitor !== desk.monitor) desk.monitor = frame.monitor;
    desk.gaps += sequenceGap(desk.sequence, frame.sequence);
    desk.sequence = frame.sequence;

    // The end-to-end clock stops here rather than after the resize, because the
    // very first frame of a session is always a resize: the canvas starts at
    // its placeholder size, and a measurement that skipped that case would skip
    // the one measurement every session takes.
    if (frame.keyframe && desk.askedFullAt > 0) {
      const now = (typeof performance !== "undefined" ? performance.now() : Date.now());
      desk.endMs = now - desk.askedFullAt;
      desk.askedFullAt = 0;
    }

    desk.geometry = { width: frame.width, height: frame.height };
    const canvas = $("dv-screen");
    if (canvas.width === frame.width && canvas.height === frame.height) return;
    // Resizing clears the canvas, so a difference frame arriving into a resized
    // surface would paint its changed tiles onto black and leave the rest of
    // the screen missing. Ask for the whole picture rather than presenting a
    // mostly-empty one — a resolution change mid-session is ordinary.
    canvas.width = frame.width;
    canvas.height = frame.height;
    // The far screen's shape, so the stylesheet can cap the viewport by height
    // as well as by width and keep the whole picture on one screenful. Written
    // through the CSSOM rather than into a `style` attribute for the reason
    // `placeCursor` gives: `style-src 'self'` governs the attribute, not a
    // property set on an element's own declaration block.
    $("dv-frame").style.setProperty("--shot", String(frame.width / Math.max(1, frame.height)));
    desk.cursor = null;
    measureViewport();
    if (!frame.keyframe) askFullFrame();
  }

  function paintTile(tile) {
    const geometry = desk.geometry;
    const edge = desk.hello ? desk.hello.edge : 0;
    if (!geometry || tile.monitor !== desk.monitor) return;
    // A tile whose payload says nothing is a keyframe's way of naming a cell
    // that happens not to have changed, and it is drawn by leaving it alone.
    if (tile.encoding === 0x02) return;
    const bounds = tileBounds(edge, geometry.width, geometry.height, tile.col, tile.row);
    if (!bounds) return;
    const pixels = expandTile(tile.encoding, tile.payload, bounds.w * bounds.h);
    if (!pixels) return;
    const context = $("dv-screen").getContext("2d");
    if (!context) return;
    context.putImageData(new ImageData(screenPixels(pixels), bounds.w, bounds.h), bounds.x, bounds.y);
    desk.tiles += 1;
  }

  function endFrame() {
    const now = Date.now();
    desk.frames += 1;
    desk.lastFrameAt = now;
    desk.recent.push(now);
    while (desk.recent.length > 0 && now - desk.recent[0] > 3000) desk.recent.shift();
    renderViewport();
  }

  /** The cursor's own bitmap, drawn once per distinct shape and then only
   *  moved. The pointer travels on its own channel precisely so that it can be
   *  composited here at the browser's frame rate instead of the stream's — a
   *  still desktop sends no frames at all, and a pointer that froze with the
   *  picture would make every quiet moment look like a dead session. */
  function paintCursor(shape) {
    const canvas = $("dv-cursor");
    canvas.width = shape.width;
    canvas.height = shape.height;
    const context = canvas.getContext("2d");
    if (!context) return;
    context.putImageData(new ImageData(cursorPixels(shape.pixels), shape.width, shape.height), 0, 0);
    desk.cursor = Object.assign(desk.cursor || { x: 0, y: 0, visible: false }, {
      hotspotX: shape.hotspotX,
      hotspotY: shape.hotspotY,
      width: shape.width,
      height: shape.height,
    });
    placeCursor();
  }

  function moveCursor(position) {
    desk.cursor = Object.assign(desk.cursor || { hotspotX: 0, hotspotY: 0, width: 0, height: 0 }, {
      x: position.x,
      y: position.y,
      visible: position.visible,
    });
    placeCursor();
  }

  /** Puts the cursor canvas where the pointer is.
   *
   *  Positions arrive in virtual-desktop coordinates, so the display's own
   *  origin comes off first — on a two-monitor desk the right-hand screen's
   *  pixels start at x = 1920 and drawing them at 1920 would put the pointer
   *  off the edge of the canvas. The transform then scales by however much the
   *  viewport is shrunk to fit, so the pointer lands on the pixel it is
   *  actually over. */
  function placeCursor() {
    const canvas = $("dv-cursor");
    const cursor = desk.cursor;
    if (!cursor || !cursor.width || !cursor.visible || !desk.geometry) {
      canvas.hidden = true;
      return;
    }
    const display = desk.hello
      ? desk.hello.monitors.find((monitor) => monitor.id === desk.monitor) : null;
    const localX = cursor.x - (display ? display.originX : 0);
    const localY = cursor.y - (display ? display.originY : 0);
    if (localX < 0 || localY < 0 || localX >= desk.geometry.width || localY >= desk.geometry.height) {
      canvas.hidden = true;
      return;
    }
    const scale = desk.scale;
    canvas.hidden = false;
    // Written through the CSSOM rather than into a `style` attribute, which
    // matters under this page's CSP: `style-src 'self'` governs style *attributes*
    // and `<style>` blocks, and does not govern a property set on an element's
    // own declaration block. So the pointer can be moved sixty times a second
    // without `'unsafe-inline'` anywhere — the same reason the viewport is drawn
    // with `putImageData` instead of a blob URL.
    canvas.style.transform = `translate(${(localX - cursor.hotspotX) * scale}px, `
      + `${(localY - cursor.hotspotY) * scale}px) scale(${scale})`;
  }

  /** How much the viewport is shrinking the far screen, cached rather than read
   *  per pointer move: `clientWidth` forces layout, and the pointer moves far
   *  more often than the window resizes. */
  function measureViewport() {
    const canvas = $("dv-screen");
    desk.scale = canvas.width > 0 && canvas.clientWidth > 0 ? canvas.clientWidth / canvas.width : 1;
    placeCursor();
  }

  /* ── driving: what this browser sends to somebody else's machine ─────
   *
   *  Nothing in here fires unless two things are true at once: the `Hello` said
   *  this stream may drive, and the viewport has the focus. The second is not
   *  belt-and-braces — it is the difference between a console and a trap. A page
   *  that forwarded keys whenever it held a control stream would type into a
   *  stranger's machine every time the operator pressed a key while reading
   *  something else on this page, and there would be no way to tell from
   *  looking.
   *
   *  The DOM half is deliberately thin: every conversion — a code to a usage, a
   *  wheel delta to notches, an offset to a pixel — is a pure function above,
   *  table-tested, so the handlers here contain no arithmetic that can be
   *  quietly wrong. */

  /** Sends one input message, and counts it.
   *
   *  The capability is checked here, on the last line before the socket, rather
   *  than trusted from wherever the event came from. It is the same check the
   *  driver makes on the far side per message, and having it in both places is
   *  the point: this one keeps a console that has lost its keyboard from
   *  spraying input that the far end will only refuse. */
  function sendInput(bytes) {
    if (!bytes || !driving() || !streamOpen()) return false;
    try { desk.socket.send(bytes); } catch { return false; }
    desk.sent += 1;
    return true;
  }

  /** Presses a key on the far machine, and remembers that it is down. */
  function pressKey(code, usage) {
    desk.held.add(code);
    sendInput(keyMessage(usage, true));
  }

  /** Releases a key, **only if this console believed it was down**.
   *
   *  The guard is not tidiness. Some platforms treat a key-up for a key that was
   *  never down as a key-down, so a duplicate release is a phantom keystroke on
   *  somebody's machine — and duplicates arise naturally here, because the
   *  modifier reconciliation below may already have released the very key whose
   *  `keyup` is being handled. This is the same rule `HeldKeys::release` keeps in
   *  `crates/desk/src/keys.rs`, for the same reason. */
  function liftKey(code, usage) {
    if (!desk.held.delete(code)) return;
    sendInput(keyMessage(usage, false));
  }

  /** Releases every key and button this console believes is down on the far
   *  machine, and tells the far end to do the same.
   *
   *  # The failure this exists for
   *
   *  A remote keyboard has a fault a local one does not: the key-up need never
   *  arrive. `Cmd+Tab` on macOS and `Alt+Tab` on Windows are handled by the
   *  window manager on the key-*down*, and the key-up is delivered to whatever
   *  the machine switched to — never to this page. The page then believes Meta
   *  is held, every subsequent keystroke becomes a shortcut on the far machine,
   *  and the operator's diagnosis is that the remote machine has gone mad.
   *
   *  So this runs on every blur, on every hide, on every handover and on every
   *  close. `ReleaseAll` is sent whatever this console believes, and whatever it
   *  believes about its own capabilities: the driver handles that message
   *  *before* the control gate precisely so a session giving up its keyboard can
   *  still put it down. */
  function releaseEverything() {
    const had = desk.held.size > 0 || desk.buttons.size > 0;
    desk.held.clear();
    desk.buttons.clear();
    desk.pointerX = null;
    desk.pointerY = null;
    desk.wheelX = 0;
    desk.wheelY = 0;
    if (streamOpen()) {
      try { desk.socket.send(releaseAllMessage()); desk.sent += 1; } catch { /* the link is going anyway */ }
    }
    if (had) renderHeld();
  }

  /** Releases any modifier the operating system says is not really down.
   *
   *  `getModifierState` is the platform's own answer rather than a replay of
   *  events this page may have missed, so comparing what is believed against it
   *  on every key event catches a lost release at the very next keystroke — the
   *  half of the stuck-modifier problem that blur handling cannot reach, because
   *  the window never lost focus. */
  function reconcileModifiers(event) {
    if (typeof event.getModifierState !== "function") return;
    const pressed = {
      Control: event.getModifierState("Control"),
      Shift: event.getModifierState("Shift"),
      Alt: event.getModifierState("Alt"),
      Meta: event.getModifierState("Meta"),
    };
    for (const code of strandedModifiers(Array.from(desk.held), pressed)) {
      const usage = hidUsage(code);
      if (usage !== null) liftKey(code, usage);
    }
  }

  /** One key down or up.
   *
   *  # Why everything is taken, including Tab and Escape
   *
   *  Because a key the browser keeps is a key the far machine never sees, and a
   *  remote desktop whose Tab moves the focus of the page in front of it is one
   *  where the next keystroke lands in this console instead of on the machine.
   *  So while driving, this page's own keyboard shortcuts do not exist. The way
   *  out is the pointer — click anywhere off the picture, or press RELEASE ALL —
   *  which is always available because pointer events outside the viewport are
   *  untouched.
   *
   *  A handful of chords are the operating system's and cannot be taken by any
   *  page: `Cmd+Tab`, `Cmd+Q`, `Alt+Tab`, `Ctrl+Alt+Del`, and the browser's own
   *  window keys. The plate says which, rather than leaving the operator to
   *  discover it by pressing one. */
  function onDeskKey(event) {
    if (!driving() || !desk.focused) return;
    event.preventDefault();
    const down = event.type === "keydown";
    reconcileModifiers(event);

    if (down && wantClipboard && bridging() && pasteChord(event.code, event.ctrlKey, event.metaKey, event.altKey)) {
      pasteToMachine();
      return;
    }

    const usage = hidUsage(event.code);
    if (usage === null) {
      // Refused here rather than sent and bounced: the answer is the same
      // sentence either way, and a key with no mapping on the far platform is
      // knowledge this console already has.
      noteRefusal(6);
      return;
    }
    if (down) pressKey(event.code, usage);
    else liftKey(event.code, usage);
    renderHeld();
  }

  /** Where the pointer is on the far display, sent only when it has moved.
   *
   *  The position is taken from the canvas's own box rather than from
   *  `offsetX`, because the pointer can legitimately be over the cursor overlay
   *  or the refusal banner and an offset relative to one of those would land the
   *  far pointer somewhere else entirely. */
  function sendPointer(event) {
    const canvas = $("dv-screen");
    const box = canvas.getBoundingClientRect();
    const point = remotePoint(event.clientX - box.left, event.clientY - box.top,
      desk.scale, canvas.width, canvas.height);
    if (!point) return;
    if (point.x === desk.pointerX && point.y === desk.pointerY) return;
    if (desk.socket && desk.socket.bufferedAmount > POINTER_BACKLOG) {
      desk.dropped += 1;
      return;
    }
    desk.pointerX = point.x;
    desk.pointerY = point.y;
    sendInput(pointerMessage(desk.monitor, point.x, point.y));
  }

  function onDeskPointerMove(event) {
    if (!driving() || !desk.focused) return;
    sendPointer(event);
  }

  /** A button going down.
   *
   *  The position is sent first, so the far machine clicks where the pointer
   *  appears to be rather than where it last was — a button and a move arriving
   *  in the other order is a click on the previous target, which on a menu is
   *  the wrong menu item.
   *
   *  The pointer is captured so that a drag which leaves the viewport still
   *  delivers its release here. Without it, dragging a window on the far machine
   *  past the edge of the picture drops the button somewhere this page never
   *  hears about, and the far machine keeps dragging for ever. */
  function onDeskPointerDown(event) {
    if (!driving() || !desk.focused) return;
    const code = buttonCode(event.button);
    if (code === null) return;
    event.preventDefault();
    try { $("dv-frame").setPointerCapture(event.pointerId); } catch { /* not a capturable pointer */ }
    sendPointer(event);
    desk.buttons.add(code);
    sendInput(buttonMessage(code, true));
    renderHeld();
  }

  function onDeskPointerUp(event) {
    if (!driving()) return;
    const code = buttonCode(event.button);
    if (code === null) return;
    event.preventDefault();
    try { $("dv-frame").releasePointerCapture(event.pointerId); } catch { /* already released */ }
    if (!desk.buttons.delete(code)) return;
    sendInput(buttonMessage(code, false));
    renderHeld();
  }

  /** The wheel.
   *
   *  The remainder is kept between events because a trackpad reports single
   *  pixels and a converter that truncated each one to zero would make a
   *  trackpad scroll nothing at all, for ever. It is dropped when a session ends,
   *  because an accumulated fraction from a session that is over is a scroll
   *  nobody asked for. */
  function onDeskWheel(event) {
    if (!driving() || !desk.focused) return;
    event.preventDefault();
    const units = scrollUnits(event.deltaX, event.deltaY, event.deltaMode);
    desk.wheelX += units.dx;
    desk.wheelY += units.dy;
    const dx = Math.trunc(desk.wheelX);
    const dy = Math.trunc(desk.wheelY);
    desk.wheelX -= dx;
    desk.wheelY -= dy;
    if (dx === 0 && dy === 0) return;
    sendInput(scrollMessage(dx, dy));
  }

  /** The viewport gained or lost the keyboard.
   *
   *  Losing it releases everything, always. This is the case the far machine
   *  cannot see: the channel is perfectly healthy, the agent has no reason to
   *  clean up, and only this page knows that the keys it reported as down are
   *  never going to be reported as up. */
  function onDeskFocus() {
    desk.focused = true;
    renderDesktop();
  }

  function onDeskBlur() {
    if (!desk.focused) return;
    desk.focused = false;
    releaseEverything();
    renderDesktop();
  }

  /* ── the clipboard bridge ───────────────────────────────────────────── */

  /** Sends the browser's clipboard to the far machine as typed text.
   *
   *  # One direction, and it is the one that exists
   *
   *  Text travels to the machine on the wire's own `Text` message, which takes
   *  the platforms' unicode path. Nothing travels back: `crates/desk/src/wire.rs`
   *  has no clipboard message at all, so a console offering a two-way bridge
   *  would be offering a channel the protocol does not carry. The note beside
   *  the switch says so.
   *
   *  # Why the modifiers come off first
   *
   *  Because the operator is holding the paste chord as this runs. Typed text
   *  injected while Command or Control is down is a shortcut on the far machine
   *  rather than a paste — `Cmd+V`, `Cmd+e`, `Cmd+l`, one per character — so the
   *  modifiers believed held are lifted before a single character goes. */
  async function pasteToMachine() {
    if (!driving() || !bridging()) return;
    liftModifiers();
    if (!navigator.clipboard || typeof navigator.clipboard.readText !== "function") {
      clipboardState = "unavailable";
      renderDesktop();
      return;
    }
    clipboardState = "asking";
    renderDesktop();
    let text;
    try { text = await withDeadline(navigator.clipboard.readText(), CLIPBOARD_DEADLINE); }
    catch {
      // A denied permission is not an error to report: the `paste` event path
      // needs no permission at all and is still open. Saying which is the whole
      // of the graceful handling.
      clipboardState = "refused";
      renderDesktop();
      return;
    }
    if (text === undefined) {
      clipboardState = "noanswer";
      renderDesktop();
      return;
    }
    typeOnMachine(text);
  }

  /** A promise given a deadline, resolving to `undefined` if it passes.
   *
   *  Not a general utility — it exists for one observed behaviour.
   *  `navigator.clipboard.readText()` can neither resolve nor reject when the
   *  permission prompt it waits on is never shown, which is what happens in a
   *  tab that is not in front. Without a deadline the PASTE button waits for
   *  ever and does nothing, which is indistinguishable from broken. */
  function withDeadline(promise, ms) {
    return Promise.race([
      promise,
      new Promise((settle) => setTimeout(() => settle(undefined), ms)),
    ]);
  }

  /** Types a run of text on the far machine, split into messages the wire
   *  accepts. */
  function typeOnMachine(text) {
    const chunks = textChunks(text, MAX_TEXT_BYTES);
    if (chunks.length === 0) {
      clipboardState = "empty";
      renderDesktop();
      return;
    }
    for (const chunk of chunks) sendInput(textMessage(chunk));
    clipboardState = "ready";
    renderDesktop();
  }

  /** Lifts every modifier this console believes is down, ordinary keys first.
   *
   *  Ordinary keys first is the order `HeldKeys::drain` keeps and for its
   *  reason: releasing Control before `C` can be observed by the far machine as
   *  a bare `C` arriving in whatever window has focus. */
  function liftModifiers() {
    const held = Array.from(desk.held);
    const isModifier = (code) => hidUsage(code) !== null && hidUsage(code) >= 0xE0;
    for (const code of held.filter((one) => !isModifier(one))) liftKey(code, hidUsage(code));
    for (const code of held.filter(isModifier)) liftKey(code, hidUsage(code));
    renderHeld();
  }

  /* ── drawing the desktop plate ────────────────────────────────────── */

  function renderDesktop() {
    const panel = $("desktop");
    panel.hidden = state.desktop === undefined;
    if (panel.hidden) return;

    const settings = state.desktop;
    const off = settings === null;
    const lamp = off ? "idle"
      : desk.phase === "watching" ? noticeLamp(desk.notice)
      : desk.phase === "opening" ? "warn" : "idle";
    setLamp($("dv-lamp"), lamp);
    setStateWord($("dv-word"), lamp, off ? "NOT SERVED"
      : desk.phase === "watching" ? noticeWord(desk.notice)
      : desk.phase === "opening" ? "CONNECTING" : "NOT CONNECTED");

    const note = $("dv-note");
    const hint = $("dv-hint");
    if (off) {
      // Deliberately one sentence for two configurations: `[desktop].enabled =
      // false` and no `[desktop]` block at all are indistinguishable on the
      // wire, and a console that could tell them apart would be telling anyone
      // behind the loopback gate whether this box has a screen worth asking
      // about.
      note.textContent = "The desktop subsystem is off. No screen on this deployment can be watched "
        + "from the console.";
      hint.hidden = true;
      $("dv-peers").hidden = true;
      $("dv-agent").hidden = true;
      $("dv-actions").hidden = true;
      $("dv-reauth").hidden = true;
      $("dv-mode").hidden = true;
      $("dv-control-note").hidden = true;
      $("dv-stage").hidden = true;
      $("dv-held-row").hidden = true;
      $("dv-clip-row").hidden = true;
      $("dv-frameline").hidden = true;
      $("dv-stall").hidden = true;
      $("dv-latency").hidden = true;
      $("dv-readings").hidden = true;
      return;
    }

    if (deskBusy) {
      note.textContent = deskBusy;
      hint.hidden = true;
    } else if (desk.phase === "watching") {
      note.textContent = desk.detail
        ? `${noticeSentence(desk.notice)} · ${desk.detail}` : noticeSentence(desk.notice);
      hint.hidden = false;
      hint.textContent = noticeHint(desk.notice);
    } else if (desk.phase === "opening") {
      note.textContent = "opening the stream";
      hint.hidden = true;
    } else if (state.nodes.length === 0) {
      // A desktop that is switched on and lists no machines is not an error
      // either: it is a fleet nobody has enrolled, or a caller who holds no
      // machine. Both read as a sentence, and the second deliberately does not
      // say which — a refusal that named the machines would be an enumeration
      // of the fleet.
      note.textContent = "The desktop subsystem is on, and no machine here is yours to watch.";
      hint.hidden = true;
    } else {
      note.textContent = desk.why
        ? `Not watching — ${desk.why}.`
        : "Not watching. Nothing is being shown and nothing is being sent.";
      hint.hidden = true;
    }

    renderPeers();
    renderAgent();

    $("dv-actions").hidden = false;
    const watching = desk.phase === "watching";
    const busy = Boolean(deskBusy);
    $("dv-connect").hidden = watching || desk.phase === "opening";
    $("dv-connect").disabled = state.nodes.length === 0 || busy;
    $("dv-disconnect").hidden = !watching && desk.phase !== "opening";
    $("dv-full").hidden = !watching;
    renderControlButton(settings, busy);
    renderMode(watching);
    renderMonitors();
    renderViewport();
    renderHeld();
    renderClipboard(settings);
  }

  /** The keyboard button, and the sentence under it.
   *
   *  The button is the *only* affordance for control in this console, and it is
   *  never hidden — a power that appears and disappears is one an operator
   *  cannot reason about. When `[desktop].allow_input` is off it stands there
   *  disabled with the reason written out, which is a better answer than a
   *  button that mints a ticket in order to be told no. */
  function renderControlButton(settings, busy) {
    const button = $("dv-control");
    const note = $("dv-control-note");
    const armed = Boolean(settings.allowInput);
    const holding = driving();
    button.textContent = holding ? "GIVE THE KEYBOARD BACK" : "TAKE CONTROL";
    button.className = holding ? "btn" : "btn ghost";
    button.disabled = busy || (!holding && (!armed || state.nodes.length === 0));
    button.setAttribute("aria-pressed", holding ? "true" : "false");

    note.hidden = false;
    if (deskSaid) { note.textContent = deskSaid; note.className = "caption bad-ink"; return; }
    note.className = "caption dim";
    if (!armed) {
      note.textContent = "Input is off for this deployment. [desktop].allow_input is a setting in a "
        + "file on the box, and nothing in this console can turn it on.";
      return;
    }
    if (holding) {
      note.textContent = "While driving, this page's own keyboard shortcuts do not exist — Tab, "
        + "Escape and the arrows all go to the far machine. The operating system keeps a few "
        + "chords whatever a page asks for (Cmd+Tab, Cmd+Q, Alt+Tab, Ctrl+Alt+Del); click off "
        + "the picture to get the keyboard back.";
      return;
    }
    note.textContent = "Taking control asks for the passkey at the moment it is clicked, however "
      + "long this console has been open, and opens a second stream with what that authorised. "
      + "A session cannot become a keyboard.";
  }

  /** The mode banner: whether what you type is going anywhere.
   *
   *  The one reading on this plate that must never need a second look, so it is
   *  drawn in three places at once — this line, the bezel around the picture,
   *  and the badge on it. Redundant on purpose: a person glancing at the screen
   *  is looking at the picture, not at a caption under it. */
  function renderMode(watching) {
    const line = $("dv-mode");
    line.hidden = !watching;
    if (!watching) {
      $("dv-frame").className = "";
      $("dv-frame").tabIndex = -1;
      $("dv-badge").hidden = true;
      $("dv-focusveil").hidden = true;
      return;
    }
    const mode = inputMode(driving(), desk.notice === 2, desk.focused);
    const lamp = modeLamp(mode);
    setLamp($("dv-mode-lamp"), lamp);
    setStateWord($("dv-mode-word"), lamp, modeWord(mode));
    $("dv-mode-text").textContent = modeLine(mode);

    const frame = $("dv-frame");
    const current = desk.frames > 0 && Date.now() - desk.lastFrameAt < 5000;
    frame.className = mode === "driving" ? (current ? "driving current" : "driving")
      : mode === "armed" || mode === "suspended" ? "armed" : "";
    // Focusable only while there is a keyboard to take, so Tab through the page
    // does not land on a picture that would do nothing with it.
    frame.tabIndex = driving() ? 0 : -1;
    $("dv-badge").hidden = mode !== "driving";
    $("dv-focusveil").hidden = mode !== "armed";
  }

  /** What is held down on the far machine.
   *
   *  Shown whenever a keyboard is held, empty or not, because the strip's value
   *  is that it is *always there to be checked*: a person who suspects a stuck
   *  modifier must be able to confirm or dismiss it by looking, not by pressing
   *  keys to find out. */
  function renderHeld() {
    const row = $("dv-held-row");
    row.hidden = !driving();
    if (row.hidden) { heldDrawn = ""; return; }
    const codes = Array.from(desk.held).sort();
    const buttons = Array.from(desk.buttons).sort();
    const drawn = JSON.stringify([codes, buttons]);
    if (drawn === heldDrawn) return;
    heldDrawn = drawn;

    const strip = $("dv-held");
    strip.textContent = "";
    if (codes.length === 0 && buttons.length === 0) {
      const none = document.createElement("span");
      none.className = "none";
      none.textContent = "NOTHING";
      strip.append(none);
      return;
    }
    for (const code of codes) {
      const chip = document.createElement("span");
      chip.className = "heldkey";
      chip.textContent = keyLabel(code);
      strip.append(chip);
    }
    for (const button of buttons) {
      const chip = document.createElement("span");
      chip.className = "heldkey";
      chip.textContent = `BUTTON ${button}`;
      strip.append(chip);
    }
  }

  /** The clipboard row: the switch, the button, and the sentence.
   *
   *  Offered only where the deployment allows it, because a switch that always
   *  refuses is a switch that teaches the operator to distrust every other
   *  switch on the page. */
  function renderClipboard(settings) {
    const row = $("dv-clip-row");
    const allowed = Boolean(settings.allowClipboard);
    row.hidden = !driving() || !allowed;
    if (row.hidden) return;
    $("dv-clip").checked = wantClipboard;
    $("dv-clip").disabled = Boolean(deskBusy);
    $("dv-paste").hidden = !bridging();
    $("dv-paste").disabled = clipboardState === "asking";
    $("dv-clip-note").textContent = clipboardSentence(
      !wantClipboard ? "off" : clipboardState === "off" ? "ready" : clipboardState,
    );
  }

  /** The machines this caller may watch. A machine that is down keeps its row
   *  and wears the reason — absence is never the answer, because a fleet that
   *  quietly loses a member is a fleet nobody notices losing one. */
  function renderPeers() {
    const holder = $("dv-peers");
    holder.hidden = state.nodes.length === 0;
    if (holder.hidden) { peersDrawn = ""; return; }
    const drawn = JSON.stringify([state.peer, state.nodes]);
    if (drawn === peersDrawn) return;
    peersDrawn = drawn;
    holder.textContent = "";
    for (const node of state.nodes) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "peer";
      if (node.node === state.peer) button.setAttribute("aria-current", "true");
      const lamp = document.createElement("span");
      setLamp(lamp, node.live ? "ok" : "bad");
      const name = document.createElement("span");
      name.className = "peername";
      name.textContent = node.node;
      const why = document.createElement("span");
      why.className = "peerwhy";
      const seen = finiteNumber(node.lastSeenSecs);
      why.textContent = node.live
        ? "reachable"
        : `${node.reason || "not answering"}${seen === null ? "" : ` · last seen ${duration(seen)} ago`}`;
      button.append(lamp, name, why);
      button.addEventListener("click", () => chooseNode(node.node));
      holder.append(button);
    }
  }

  function renderAgent() {
    const line = $("dv-agent");
    const agent = state.agent;
    line.hidden = !agent;
    if (!agent) return;
    setLamp($("dv-agent-lamp"), agent.live ? "ok" : "idle");
    const monitors = finiteNumber(agent.monitors) || 0;
    const respawns = finiteNumber(agent.respawns) || 0;
    const extra = agent.live && monitors > 0
      ? ` · ${monitors} ${monitors === 1 ? "display" : "displays"}` : "";
    const restarts = respawns > 0 ? ` · ${respawns} ${respawns === 1 ? "respawn" : "respawns"}` : "";
    $("dv-agent-text").textContent = `${agent.sentence}${extra}${restarts}`;
  }

  function renderMonitors() {
    const picker = $("dv-monitors");
    const monitors = desk.hello ? desk.hello.monitors : [];
    const drawn = JSON.stringify([desk.monitor, monitors]);
    if (drawn === monitorsDrawn) return;
    monitorsDrawn = drawn;
    picker.textContent = "";
    if (monitors.length < 2) return;
    for (const monitor of monitors) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "btn ghost small";
      button.textContent = `DISPLAY ${monitor.id}`;
      button.title = monitorLabel(monitor);
      button.setAttribute("aria-pressed", monitor.id === desk.monitor ? "true" : "false");
      button.addEventListener("click", () => chooseMonitor(monitor.id));
      picker.append(button);
    }
  }

  /** The viewport and its readings. Called on the plate's own clock as well as
   *  on every frame, because the reading that matters most — how old the
   *  picture is — changes while nothing arrives, which is precisely the case it
   *  exists to make visible. */
  function renderViewport() {
    if (state.desktop === undefined || state.desktop === null) return;
    const watching = desk.phase === "watching";
    $("dv-stage").hidden = !watching;
    $("dv-frameline").hidden = !watching;
    $("dv-latency").hidden = !watching;
    $("dv-readings").hidden = !watching;
    if (!watching) { $("dv-stall").hidden = true; return; }

    const hasPicture = desk.frames > 0;
    const sinceSecs = hasPicture ? Math.floor((Date.now() - desk.lastFrameAt) / 1000) : 0;
    const veil = $("dv-veil");
    veil.hidden = hasPicture;
    if (!hasPicture) {
      $("dv-veil-text").textContent = desk.notice === 2
        ? "waiting for the first frame"
        : `${noticeSentence(desk.notice)} — ${noticeHint(desk.notice)}`;
    }

    renderRefusal();

    setLamp($("dv-frame-lamp"), frameLamp(desk.notice, sinceSecs, hasPicture));
    $("dv-frame-text").textContent = frameLine(desk.notice, sinceSecs, hasPicture);

    const stall = stallLine(desk.stalls);
    $("dv-stall").hidden = stall === "";
    $("dv-stall").textContent = stall;

    $("dv-latency").textContent = latencyLine(desk.hopMs, desk.endMs);

    $("dv-r-frames").textContent = String(desk.frames);
    const samples = desk.recent.length;
    $("dv-r-fps").textContent = samples > 1
      ? String(Math.round((samples - 1) * 1000 / Math.max(1, desk.recent[samples - 1] - desk.recent[0])))
      : "0";
    $("dv-r-bytes").textContent = byteCount(desk.bytes);
    $("dv-r-hop").textContent = msText(desk.hopMs);
    $("dv-r-end").textContent = msText(desk.endMs);
    // A dash rather than a zero: this counter is the *far side's*, and a daemon
    // that does not report it has not told us there were none.
    $("dv-r-stalls").textContent = desk.stalls === null ? "—" : String(desk.stalls);
    const gaps = $("dv-r-gaps");
    gaps.textContent = String(desk.gaps);
    gaps.className = desk.gaps > 0 ? "mono warn-ink" : "mono";
    // The dropped positions are folded in here rather than given a dial of
    // their own: they are not a fault, they are this console declining to queue
    // a position that the next one supersedes, and a dial for them would read
    // as loss.
    $("dv-r-sent").textContent = desk.dropped > 0
      ? `${desk.sent} · ${desk.dropped} skipped` : String(desk.sent);
    const refused = $("dv-r-refused");
    refused.textContent = String(desk.refused);
    refused.className = desk.refused > 0 ? "mono bad-ink" : "mono";
    // From the Hello, never from what was asked for.
    $("dv-r-caps").textContent = desk.hello
      ? capabilityWords(desk.granted).join(" + ") || "NONE" : "—";
  }

  /** The refusal banner over the picture.
   *
   *  It lingers rather than flashing, and it goes on its own rather than waiting
   *  to be dismissed. A banner that stayed would eventually be describing a
   *  session that has since started working perfectly, which is a banner that
   *  lies; a banner that vanished in a frame would be one the operator sees only
   *  as a flicker and cannot read. */
  function renderRefusal() {
    const banner = $("dv-refusal");
    const refusal = desk.refusal;
    const fresh = refusal && Date.now() - refusal.at < REFUSAL_LINGER;
    banner.hidden = !fresh;
    if (!fresh) return;
    $("dv-refusal-text").textContent = refusalHeadline(refusal.code, refusal.count);
    const advice = refusalAdvice(refusal.code);
    $("dv-refusal-advice").hidden = advice === "";
    $("dv-refusal-advice").textContent = advice;
  }

  /* ── the audit plate ──────────────────────────────────────────────────
   *
   *  What was done, read where it was done. The daemon writes one line per input
   *  message, so this is mostly a flood of pointer positions — hidden by
   *  default, counted rather than dropped, and one click from being shown. */

  /** How many records to ask for, and how much further back a click reaches.
   *  The daemon clamps at 500 whatever is asked. */
  const AUDIT_STEP = 100;
  const AUDIT_CEILING = 500;
  let auditLimit = AUDIT_STEP;
  let auditNoise = false;
  let auditTimer = null;

  /** Reads the tail.
   *
   *  A 401 hides the plate rather than sending the operator to the login page:
   *  this route is owner-only, so a person who has been granted a machine is
   *  refused it in the ordinary course of things, and logging them out for
   *  asking would be a fault they would report as the console throwing them out
   *  at random. A session that has genuinely expired is caught by the poll,
   *  which asks a route every caller may reach. */
  async function refreshAudit() {
    let reply;
    try { reply = await api(`/api/audit?limit=${auditLimit}`); }
    catch { return; }
    state.audit = reply.status === 200 && reply.body && Array.isArray(reply.body.records)
      ? reply.body : null;
    renderAudit();
  }

  /** Keeps the trail current while, and only while, a keyboard is live —
   *  which is the one time it is changing and the one time its reader is most
   *  entitled to watch it change. */
  function scheduleAudit() {
    clearInterval(auditTimer);
    auditTimer = null;
    if (!driving()) return;
    auditTimer = setInterval(() => {
      if (!document.hidden && driving()) refreshAudit();
    }, AUDIT_INTERVAL);
  }

  function renderAudit() {
    const panel = $("audit");
    panel.hidden = !state.audit;
    if (panel.hidden) return;
    const tail = state.audit;
    const records = tail.records.filter((record) => record && typeof record === "object");
    const shown = auditNoise ? records : records.filter((record) => !isPointerNoise(record));

    $("au-note").textContent = trailNote(tail, records.length - shown.length);
    // The label names what the button will do, so it needs no pressed state —
    // a toggle that both changes its label and claims to be pressed is a
    // control a reader has to decode twice.
    $("au-noise").textContent = auditNoise ? "HIDE POINTER" : "SHOW POINTER";
    $("au-more").hidden = auditLimit >= AUDIT_CEILING || records.length < auditLimit;

    const list = $("au-list");
    list.textContent = "";
    for (const record of shown) list.append(auditRow(record));
  }

  /** One record, built element by element.
   *
   *  Every cell is filled through `textContent` and never through `innerHTML`.
   *  That is not the house style being applied uniformly — it is the specific
   *  defence this plate needs: `detail` is influenced by whoever drove the
   *  machine, and an audit trail that rendered its subject's markup would be an
   *  audit trail its subject could forge. The daemon's parser refuses a line
   *  whose escaping does not decode, so a forged record arrives here as one
   *  field of one real record; this is what keeps it looking like one. */
  function auditRow(record) {
    const row = document.createElement("li");
    const refused = record.outcome === "refuse";
    row.className = refused ? "trailrow refused" : "trailrow";

    const when = document.createElement("span");
    when.className = "when";
    when.textContent = auditWhen(record.at);

    const lamp = document.createElement("span");
    setLamp(lamp, auditLamp(record.outcome));

    const who = document.createElement("span");
    who.className = "who";
    who.textContent = typeof record.who === "string" && record.who !== "" ? record.who : "—";

    const what = document.createElement("span");
    what.className = "what";
    // Every field is treated as possibly absent: the daemon's parser refuses a
    // malformed line outright, but a record from a *newer* writer is admitted
    // with the fields this build knows, and a missing one must read as a dash
    // rather than as the word "undefined".
    const capability = typeof record.capability === "string" ? record.capability : "—";
    const target = typeof record.target === "string" && record.target !== "" ? record.target : "";
    what.textContent = target ? `${capability} · ${target}` : capability;

    const said = document.createElement("span");
    said.className = "said";
    // The ellipsis is the daemon's `detailTruncated`: a stump presented as the
    // whole value would be a record that reads as complete and is not.
    const detail = auditDetail(record.detail) + (record.detailTruncated ? " …" : "");
    said.textContent = refused && record.reason && record.reason !== "-"
      ? `${detail} · refused: ${record.reason}` : detail;

    row.append(when, lamp, who, what, said);
    return row;
  }

  /* ── wiring ───────────────────────────────────────────────────────── */

  $("login-form").addEventListener("submit", submitLogin);
  $("login-passkey").addEventListener("click", passkeyLogin);
  $("pk-register").addEventListener("click", registerPasskey);
  $("logout").addEventListener("click", logout);
  offerPasskeyLogin();
  $("notice-dismiss").addEventListener("click", () => { state.notice = null; renderNotice(); });

  $("add-service").addEventListener("click", openBlank);
  $("d-edit").addEventListener("click", () => {
    if (state.spec && state.spec.name === state.selected) openEdit(state.spec);
  });
  $("d-start").addEventListener("click", () => act("start"));
  $("d-stop").addEventListener("click", () => act("stop"));
  $("d-restart").addEventListener("click", () => act("restart"));
  $("d-deploy").addEventListener("click", deployNow);
  $("d-uninstall").addEventListener("click", showConfirm);
  $("d-confirm-cancel").addEventListener("click", hideConfirm);
  $("d-confirm-input").addEventListener("input", () => {
    $("d-confirm-go").disabled = $("d-confirm-input").value !== state.selected;
  });
  $("d-confirm-go").addEventListener("click", () => {
    if ($("d-confirm-input").value === state.selected) uninstall(state.selected);
  });

  $("service-form").addEventListener("submit", submitForm);
  $("f-cancel").addEventListener("click", closeForm);
  $("fw-reconcile").addEventListener("click", reconcileFirewall);

  /* The files plate. */

  $("fs-up").addEventListener("click", () => openDirectory(parentPath(state.dir)));
  $("fs-reload").addEventListener("click", () => {
    treeChildren.delete(state.dir);
    refreshShares();
    refreshListing();
    refreshTree();
  });
  $("fs-mkdir").addEventListener("click", () => {
    const row = $("fs-mkdir-row");
    const opening = row.hidden;
    closeStorageForms();
    row.hidden = !opening;
    if (opening) { $("fs-mkdir-name").value = ""; $("fs-mkdir-name").focus(); }
    render();
  });
  $("fs-mkdir-go").addEventListener("click", makeDirectory);
  $("fs-mkdir-cancel").addEventListener("click", () => { closeStorageForms(); render(); });
  $("fs-mkdir-name").addEventListener("keydown", (event) => {
    if (event.key === "Enter") { event.preventDefault(); makeDirectory(); }
    else if (event.key === "Escape") { event.preventDefault(); closeStorageForms(); render(); }
  });

  $("fs-move-go").addEventListener("click", commitMove);
  $("fs-move-cancel").addEventListener("click", () => { closeStorageForms(); render(); });
  $("fs-move-path").addEventListener("keydown", (event) => {
    if (event.key === "Enter") { event.preventDefault(); commitMove(); }
    else if (event.key === "Escape") { event.preventDefault(); closeStorageForms(); render(); }
  });

  $("fs-confirm-input").addEventListener("input", () => {
    $("fs-confirm-go").disabled = !condemned || $("fs-confirm-input").value !== condemned.name;
  });
  $("fs-confirm-go").addEventListener("click", () => {
    if (!condemned) return;
    if (condemned.kind === "directory" && $("fs-confirm-input").value !== condemned.name) return;
    deleteEntry(condemned);
  });
  $("fs-confirm-cancel").addEventListener("click", () => { closeStorageForms(); render(); });

  $("fs-upload").addEventListener("click", () => $("fs-file").click());
  $("fs-file").addEventListener("change", () => {
    const chosen = $("fs-file").files;
    if (chosen && chosen.length > 0) startUploads(Array.from(chosen));
    // Cleared so that choosing the same file twice in a row still fires.
    $("fs-file").value = "";
  });
  $("fs-transfer-clear").addEventListener("click", clearFinishedUploads);

  // The sort belongs to the operator: the server answers in its own display
  // order and this re-sorts what arrived rather than asking for it again.
  for (const [id, column] of [["fs-sort-name", "name"], ["fs-sort-size", "size"], ["fs-sort-modified", "modified"]]) {
    $(id).addEventListener("click", () => {
      if (sortColumn === column) sortAscending = !sortAscending;
      else { sortColumn = column; sortAscending = column === "name"; }
      for (const other of ["fs-sort-name", "fs-sort-size", "fs-sort-modified"]) {
        $(other).removeAttribute("aria-sort");
      }
      $(id).setAttribute("aria-sort", sortAscending ? "ascending" : "descending");
      rowsDirty = true;
      render();
    });
  }
  $("fs-sort-name").setAttribute("aria-sort", "ascending");

  /* Drag and drop. Two entirely different drags land on the same field: files
     from the operating system, which are an upload, and a row from this
     listing, which is a move. They are told apart by what the drag carries —
     `Files` in its type list is the OS — and only the first one raises the
     veil, because a move already lights the row it is over. */
  const dropField = $("fs-drop");
  const carriesFiles = (event) => Boolean(event.dataTransfer)
    && Array.from(event.dataTransfer.types || []).includes("Files");
  dropField.addEventListener("dragenter", (event) => {
    if (!carriesFiles(event) || !shareWritable()) return;
    event.preventDefault();
    dropDepth += 1;
    $("fs-veil").hidden = false;
  });
  dropField.addEventListener("dragover", (event) => {
    if (!carriesFiles(event) || !shareWritable()) return;
    event.preventDefault();
    if (event.dataTransfer) event.dataTransfer.dropEffect = "copy";
  });
  dropField.addEventListener("dragleave", () => {
    if (dropDepth > 0) dropDepth -= 1;
    if (dropDepth === 0) $("fs-veil").hidden = true;
  });
  dropField.addEventListener("drop", (event) => {
    if (!carriesFiles(event)) return;
    event.preventDefault();
    dropDepth = 0;
    $("fs-veil").hidden = true;
    const dropped = event.dataTransfer ? event.dataTransfer.files : null;
    if (dropped && dropped.length > 0) startUploads(Array.from(dropped));
  });
  // A file dropped anywhere else on the page is the browser's default: it
  // navigates away from the console and opens the file. Refused everywhere,
  // because losing a half-typed form to a missed drag is a poor trade.
  for (const kind of ["dragover", "drop"]) {
    document.addEventListener(kind, (event) => {
      if (event.target instanceof Element && event.target.closest("#fs-drop")) return;
      if (!carriesFiles(event)) return;
      event.preventDefault();
    });
  }

  /* The desktop plate. */

  $("dv-connect").addEventListener("click", connectDesktop);
  $("dv-disconnect").addEventListener("click", () => closeDesktop("you disconnected"));
  $("dv-full").addEventListener("click", askFullFrame);
  $("dv-control").addEventListener("click", () => (driving() ? releaseControl() : takeControl()));
  $("dv-release").addEventListener("click", () => {
    releaseEverything();
    renderDesktop();
  });
  $("dv-reauth-go").addEventListener("click", () => proveWithPasskey());
  $("dv-reauth-pass-go").addEventListener("click", proveWithPassword);
  $("dv-reauth-pass").addEventListener("keydown", (event) => {
    if (event.key === "Enter") { event.preventDefault(); proveWithPassword(); }
    else if (event.key === "Escape") { event.preventDefault(); hideAuthorisation(); renderDesktop(); }
  });
  $("dv-reauth-cancel").addEventListener("click", () => {
    pendingWant = null;
    wantControl = false;
    hideAuthorisation();
    deskSaid = "The keyboard was not authorised, so this session watches and does not type.";
    renderDesktop();
  });

  // The clipboard switch changes what the *next* stream asks for, because the
  // capability set of a live one is fixed in its Hello. Turning it on while
  // driving therefore re-opens the stream — and re-opening it means proving who
  // is asking all over again, which is the correct price for widening a
  // session's reach onto somebody else's machine.
  $("dv-clip").addEventListener("change", () => {
    wantClipboard = $("dv-clip").checked;
    clipboardState = "off";
    if (driving()) openDesktop(wantedAbilities(), wantClipboard
      ? "opening the clipboard bridge" : "closing the clipboard bridge");
    else renderDesktop();
  });
  $("dv-paste").addEventListener("click", pasteToMachine);

  /* The input path. Bound once, and gated inside each handler on the two facts
     that make forwarding legitimate: the Hello granted a keyboard, and the
     viewport has the focus. */
  const frame = $("dv-frame");
  frame.addEventListener("keydown", onDeskKey);
  frame.addEventListener("keyup", onDeskKey);
  frame.addEventListener("focus", onDeskFocus);
  frame.addEventListener("blur", onDeskBlur);
  frame.addEventListener("pointermove", onDeskPointerMove);
  frame.addEventListener("pointerdown", onDeskPointerDown);
  frame.addEventListener("pointerup", onDeskPointerUp);
  frame.addEventListener("pointercancel", onDeskPointerUp);
  // Non-passive, because the whole point is to stop the page scrolling under a
  // wheel that belongs to the far machine.
  frame.addEventListener("wheel", onDeskWheel, { passive: false });
  // The far machine has its own context menu, and it arrives as a right button
  // like any other.
  frame.addEventListener("contextmenu", (event) => {
    if (driving() && desk.focused) event.preventDefault();
  });
  // The paste event fires only when the bridge is armed and the chord was *not*
  // intercepted — a browser extension's menu, for instance. It needs no
  // permission, which is why it is the fallback a refused `readText` points at.
  frame.addEventListener("paste", (event) => {
    if (!driving() || !bridging() || !wantClipboard) return;
    event.preventDefault();
    typeOnMachine(event.clipboardData ? event.clipboardData.getData("text/plain") : "");
  });
  // Taking the keyboard is a click that does nothing else: the pointer is
  // resting on whatever the far machine has under it, and a first click that
  // also pressed that would be a click nobody aimed.
  $("dv-focusveil").addEventListener("pointerdown", (event) => {
    event.preventDefault();
    event.stopPropagation();
    frame.focus();
  });

  /* The two ways a window loses the keyboard without the element losing focus,
     and both leave a modifier down on somebody else's machine if they are not
     handled: Cmd+Tab and Alt+Tab are acted on by the window manager at the
     key-*down* and their key-up is delivered somewhere else entirely. */
  window.addEventListener("blur", onDeskBlur);
  window.addEventListener("focus", () => {
    if (document.activeElement === frame) onDeskFocus();
  });

  // The viewport scales to whatever room the window leaves it, and the cursor
  // is positioned in those same scaled pixels, so the two must be measured
  // together or the pointer drifts off the thing it is pointing at.
  window.addEventListener("resize", measureViewport);

  /* The audit plate. */

  $("au-reload").addEventListener("click", refreshAudit);
  $("au-noise").addEventListener("click", () => { auditNoise = !auditNoise; renderAudit(); });
  $("au-more").addEventListener("click", () => {
    auditLimit = Math.min(AUDIT_CEILING, auditLimit + AUDIT_STEP);
    refreshAudit();
  });

  // The log toolbar: the stderr switch and the filter sieve.
  $("log-stderr").addEventListener("click", () => {
    stderrOnly = !stderrOnly;
    $("log-stderr").setAttribute("aria-pressed", stderrOnly ? "true" : "false");
    applyLogSieves();
  });
  $("log-filter").addEventListener("input", () => {
    clearTimeout(logQueryTimer);
    logQueryTimer = setTimeout(() => {
      logQuery = $("log-filter").value.trim();
      applyLogSieves();
    }, 120);
  });
  $("log-jump").addEventListener("click", () => {
    const scroll = $("log-scroll");
    logPinned = true;
    logUnseen = 0;
    scroll.scrollTop = scroll.scrollHeight;
    renderJump();
  });

  // The arrows walk the rail from anywhere that is not a field: the selection
  // is what moves, exactly as in the native console. Home and End jump to the
  // rail's ends.
  document.addEventListener("keydown", (event) => {
    if (state.view !== "console" || state.formOpen) return;
    // The arrows belong to the service rail everywhere except inside the two
    // plates that have a selection of their own: an arrow pressed on a file row
    // or a peer button must not quietly move the service the detail pane is
    // showing.
    if (event.target instanceof Element
      && event.target.closest("input, textarea, select, #storage, #desktop, #audit")) return;
    if (event.key === "ArrowUp") { event.preventDefault(); stepSelection(-1); }
    else if (event.key === "ArrowDown") { event.preventDefault(); stepSelection(1); }
    else if (event.key === "Home") { event.preventDefault(); stepSelection(-state.services.length); }
    else if (event.key === "End") { event.preventDefault(); stepSelection(state.services.length); }
  });

  // Caps Lock is named while the password is being typed, not after a refusal.
  for (const kind of ["keydown", "keyup"]) {
    $("login-password").addEventListener(kind, (event) => {
      if (typeof event.getModifierState === "function") {
        $("login-caps").hidden = !event.getModifierState("CapsLock");
      }
    });
  }
  $("login-password").addEventListener("blur", () => { $("login-caps").hidden = true; });

  // Pinned-to-bottom follows where the reader actually is, not a mode flag.
  $("log-scroll").addEventListener("scroll", () => {
    const scroll = $("log-scroll");
    const wasPinned = logPinned;
    logPinned = scroll.scrollTop + scroll.clientHeight >= scroll.scrollHeight - 4;
    if (logPinned) logUnseen = 0;
    if (logPinned !== wasPinned) renderJump();
  });

  // Back off while nobody is watching; catch up the moment they return. The
  // stream itself is left alone either way — it costs nothing while nothing
  // changes, and tearing it down for a hidden tab would mean a handshake and a
  // fresh ticket every time the operator alt-tabs.
  document.addEventListener("visibilitychange", () => {
    // A tab going into the background keeps its focused element, so a keyboard
    // held here would stay held on the far machine while nobody is looking at
    // it. Releasing on hide costs a click to resume and closes the last route
    // by which a key is left down on somebody else's computer.
    if (document.hidden) onDeskBlur();
    if (!document.hidden && state.view === "console") poll();
    scheduleLogs();
  });

  checkSession();
}
