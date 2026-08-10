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
 * Layout of this file:
 *   1. Pure functions ported from the native console (present, condition,
 *      duration, name checks, form parsing). No DOM.
 *   2. Self-tests: `node app.js` runs them and exits non-zero on failure.
 *   3. The application: state, polling, rendering. Browser only.
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

  if (failures > 0) { process.exitCode = 1; console.error(`${failures} failure(s)`); }
  else console.log("all self-tests passed");
} else {
  boot();
}

/* ── 3. The application ─────────────────────────────────────────────── */

/** Wires the page up and decides login vs console from the session. */
function boot() {

  /* How often the daemon is asked while the tab is watched / hidden, ms. */
  const POLL_FAST = 500;
  const POLL_SLOW = 5000;
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
  };

  const $ = (id) => document.getElementById(id);

  /* Poll bookkeeping: one loop, immediate re-poll after any command. */
  let pollTimer = null;
  let inFlight = false;
  let pollAgain = false;
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
      if (reply.status === 200) enterConsole(); else showLogin("", { keep: true });
    } catch {
      showLogin("cannot reach the server", { keep: true });
    }
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
    state.link = "connecting";
    state.services = [];
    state.selected = null;
    state.spec = null;
    state.firewall = null;
    state.notice = null;
    state.formOpen = false;
    state.passkeys = null;
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
    render();
    poll();
    // Outside the poll on purpose: passkeys change only through this page's
    // own register and remove buttons, which refresh the list themselves.
    refreshPasskeys();
  }

  async function submitLogin(event) {
    event.preventDefault();
    const note = $("login-note");
    note.hidden = true;
    $("login-submit").disabled = true;
    $("login-sweep").hidden = false;
    try {
      const reply = await api("/api/session", { method: "POST", body: { password: $("login-password").value } });
      if (reply.status >= 200 && reply.status < 300) { enterConsole(); return; }
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

  /** Unhides the login page's passkey button where a biometric (platform)
   *  authenticator actually exists — everywhere else the password stands alone. */
  function offerPasskeyLogin() {
    if (!window.PublicKeyCredential
      || typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
      return;
    }
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
      .then((available) => { $("login-passkey").hidden = !available; })
      .catch(() => { /* no authenticator, no button */ });
  }

  /** The biometric login: challenge → authenticator → assertion → session.
   *  A cancelled prompt says nothing; a refusal wears the password form's own
   *  quiet words, because the daemon's refusals are deliberately uniform. */
  async function passkeyLogin() {
    const note = $("login-note");
    note.hidden = true;
    $("login-passkey").disabled = true;
    try {
      const issued = await api("/api/webauthn/login/challenge", { method: "POST" });
      const challenge = issued.status === 200 && issued.body
        ? b64urlToBuf(issued.body.challenge) : null;
      if (!challenge) {
        note.hidden = false;
        note.textContent = issued.status === 429 ? "too many attempts, wait a minute" : "not accepted";
        return;
      }
      let credential;
      try {
        credential = await navigator.credentials.get({
          publicKey: {
            challenge,
            rpId: issued.body.rpId,
            // The point of the feature: the authenticator must verify the
            // person (biometric or PIN), not merely observe a touch.
            userVerification: "required",
            timeout: 60000,
          },
        });
      } catch { return; /* cancelled or refused at the authenticator */ }
      if (!credential) return;
      const answer = credential.response;
      const reply = await api("/api/webauthn/login", {
        method: "POST",
        body: {
          id: credential.id,
          clientDataJSON: bufToB64url(new Uint8Array(answer.clientDataJSON)),
          authenticatorData: bufToB64url(new Uint8Array(answer.authenticatorData)),
          signature: bufToB64url(new Uint8Array(answer.signature)),
        },
      });
      if (reply.status >= 200 && reply.status < 300) { enterConsole(); return; }
      note.hidden = false;
      note.textContent = reply.status === 429 ? "too many attempts, wait a minute" : "not accepted";
    } catch {
      note.hidden = false;
      note.textContent = "cannot reach the server";
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

  /** Registers this device's platform authenticator as a passkey: an
   *  authenticated-session-only act, so the password remains the root key. */
  async function registerPasskey() {
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
            // One operator, one fixed handle: re-registering a device replaces
            // its previous passkey instead of piling up copies.
            user: {
              id: new TextEncoder().encode("selfhost-operator"),
              name: "operator",
              displayName: "Operator",
            },
            pubKeyCredParams: [{ type: "public-key", alg: -7 }],
            authenticatorSelection: {
              authenticatorAttachment: "platform",
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
          label: deviceLabel(navigator.userAgent),
        },
      });
      if (reply.status === 401) { toLogin(); return; }
      if (reply.status >= 400) {
        notify("problem", (reply.body && reply.body.error) || `registration refused (${reply.status})`);
        return;
      }
      notify("done", "Passkey registered — this device's biometric now logs in");
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

  /** The PASSKEYS panel: hidden while the daemon lacks the feature, a listed
   *  device per row, and the register button only where registering can work. */
  function renderPasskeys() {
    const panel = $("passkeys");
    panel.hidden = state.passkeys === null;
    if (state.passkeys === null) return;
    const passkeys = state.passkeys;
    $("pk-count").textContent = String(passkeys.length);
    $("pk-register").hidden = !window.PublicKeyCredential;
    const note = $("pk-note");
    note.hidden = passkeys.length > 0;
    note.textContent = window.PublicKeyCredential
      ? "No passkeys yet. Register this device to log in with its biometric."
      : "No passkeys yet. Open the console on a device with a biometric authenticator to register one.";
    const rows = $("pk-list");
    rows.textContent = "";
    for (const entry of passkeys) {
      if (!usableCredentialId(entry.id)) continue;
      const row = document.createElement("li");
      const label = document.createElement("span");
      label.className = "pk-label";
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
      row.append(label, added, rule, remove);
      rows.append(row);
    }
  }

  /* ── polling ──────────────────────────────────────────────────────── */

  function schedule(delay) {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(poll, delay);
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
        const delay = pollAgain ? 0 : (document.hidden ? POLL_SLOW : POLL_FAST);
        pollAgain = false;
        schedule(delay);
      }
    }
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

    await Promise.all([refreshDefinition(), refreshLogs(), refreshFirewall()]);
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
    if (event.target instanceof Element && event.target.closest("input, textarea, select")) return;
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

  // Back off while nobody is watching; catch up the moment they return.
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden && state.view === "console") poll();
  });

  checkSession();
}
