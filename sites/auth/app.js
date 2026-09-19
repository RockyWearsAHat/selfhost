"use strict";

/* SELFHOST — public sign-in site.
 *
 * This page hosts exactly two ceremonies: logging in with the password, and
 * approving a SelfHost VPN desktop app's sign-in request. Both reuse the
 * admin console's own backend — the same `/api/session` and `/api/vpn/*`
 * routes `sites/console/app.js` calls — but this site is deliberately public
 * and ungated (see `crates/foundation/config`'s `Site::public_api_paths`),
 * so a first-time sign-in never depends on the console's own gated route
 * being installed first.
 *
 * No Touch ID / passkey button here: WebAuthn's relying-party id would have
 * to match this page's own hostname, and the console's passkeys are bound to
 * admin.rockywearsahat.com's origin — a browser refuses to run a ceremony
 * for a sibling subdomain's rpId. Passkey login stays inside the admin
 * console; a session opened here with the password carries into a
 * VPN-connect handoff exactly the same as one opened there with a passkey.
 *
 * The parts that are shared with `sites/console/app.js` (the transport, the
 * VPN-connect parsing/completion, the login form) are copied from there
 * verbatim. Keep it in step with that file's copy of the same functions. */

function boot() {
  const state = {
    view: "loading",   // "login" | "vpn-connect" | "signed-in"
    siteReturn: null,  // the gated Site URL a proxy redirect carried here as ?return=
    vpnConnect: null,  // {state, challenge, port} from a desktop app's redirect
  };

  const $ = (id) => document.getElementById(id);

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

  /* ── vpn device sign-in ───────────────────────────────────────────── */

  /** Parses a `#vpn-connect?state=...&challenge=...&port=...`
   *  link from the SelfHost VPN desktop app, or null if the fragment does
   *  not match.
   *
   *  A fragment on purpose: none of this is sent to the server or left in a
   *  log. `state` and `challenge` are the desktop app's own PKCE bookkeeping
   *  — this page only carries them to `/api/vpn/authorize` and back to the
   *  app's loopback callback. */
  function vpnConnectParams() {
    const match = /^#vpn-connect\?(.+)$/.exec(location.hash || "");
    if (!match) return null;
    const params = new URLSearchParams(match[1]);
    const forState = params.get("state");
    const challenge = params.get("challenge");
    const port = Number(params.get("port"));
    if (!forState || !challenge
      || !Number.isInteger(port) || port <= 0 || port > 65535) {
      return null;
    }
    return { state: forState, challenge, port };
  }

  /** Finishes a desktop app's sign-in against *this* browser session.
   *
   *  By the time this runs the reader is already authenticated — that is how
   *  execution got here, from `checkSession` after a valid session or from a
   *  fresh login — so approving the device is just minting a code against
   *  this session and handing it back to the app that asked for one. */
  async function completeVpnConnect() {
    const connect = state.vpnConnect;
    showView("vpn-connect");

    let reply;
    try {
      reply = await api("/api/vpn/authorize", {
        method: "POST",
        body: { codeChallenge: connect.challenge },
      });
    } catch { vpnConnectFailed("cannot reach the server"); return; }

    if (reply.status === 401) {
      // The session lapsed between the redirect landing and this call. Send
      // the reader to the ordinary door without dropping the app's request —
      // `state.vpnConnect` survives, so logging back in resumes the handoff
      // instead of stranding it on a dead screen.
      showLogin("sign in to approve this device", { keep: true });
      return;
    }
    if (reply.status !== 200 || !reply.body || typeof reply.body.code !== "string") {
      vpnConnectFailed((reply.body && reply.body.error) || "could not approve this device");
      return;
    }

    const callback = `http://127.0.0.1:${connect.port}/callback`
      + `?code=${encodeURIComponent(reply.body.code)}`
      + `&state=${encodeURIComponent(connect.state)}`;
    state.vpnConnect = null;
    location.href = callback;
  }

  /* ── site sign-in ─────────────────────────────────────────────────── */

  /** The URL a gated Site's proxy turned the reader away from, carried here
   *  as `?return=`, or null. Only its shape is checked here; whether it names
   *  a Site of this deployment, and whether this Person holds a Grant on it,
   *  is `/api/pass/authorize`'s to decide. */
  function siteReturnParam() {
    const wanted = new URLSearchParams(location.search).get("return");
    return wanted && wanted.startsWith("https://") ? wanted : null;
  }

  /** Signs this session's Person in to the Site they came from. The server
   *  answers with that Site's own `/.selfhost/pass` link, or a refusal. */
  async function completeSiteSignIn() {
    const wanted = state.siteReturn;
    showView("vpn-connect");
    $("vpn-connect-status").textContent = "Signing you in to the site.";

    let reply;
    try {
      reply = await api("/api/pass/authorize", { method: "POST", body: { return: wanted } });
    } catch { siteSignInFailed("cannot reach the server"); return; }

    if (reply.status === 401) {
      showLogin("sign in to open that site", { keep: true });
      return;
    }
    if (reply.status !== 200 || !reply.body || typeof reply.body.redirect !== "string") {
      siteSignInFailed((reply.body && reply.body.error) || "could not sign in to that site");
      return;
    }
    state.siteReturn = null;
    location.href = reply.body.redirect;
  }

  function siteSignInFailed(text) {
    $("vpn-connect-status").textContent = "You could not be signed in to that site.";
    const line = $("vpn-connect-note");
    line.textContent = text;
    line.hidden = false;
  }

  /** Says why the device could not be approved. */
  function vpnConnectFailed(text) {
    $("vpn-connect-status").textContent = "This device could not be signed in.";
    const line = $("vpn-connect-note");
    line.textContent = text;
    line.hidden = false;
  }

  /* ── session ──────────────────────────────────────────────────────── */

  /** Decides which view to open: whether a session cookie is accepted, and
   *  whether a desktop app is waiting on the other end of one.
   *
   *  The probe rides a slow tunnel: anything typed into the password field
   *  while it was in flight must survive the view settling. */
  async function checkSession() {
    const connect = vpnConnectParams();
    if (connect) {
      state.vpnConnect = connect;
      history.replaceState(null, "", location.pathname + location.search);
    }
    state.siteReturn = siteReturnParam();
    try {
      const reply = await api("/api/session");
      if (reply.status === 200) afterSignIn();
      else showLogin("", { keep: true });
    } catch {
      showLogin("cannot reach the server", { keep: true });
    }
  }

  /** What happens once a session is known good, whether from a cookie already
   *  on file or from a password just accepted: hand off to a waiting desktop
   *  app, or say there is nothing else to do here. */
  function afterSignIn() {
    if (state.vpnConnect) { completeVpnConnect(); return; }
    if (state.siteReturn) { completeSiteSignIn(); return; }
    showView("signed-in");
  }

  function showView(view) {
    state.view = view;
    $("view-login").hidden = view !== "login";
    $("view-vpn-connect").hidden = view !== "vpn-connect";
    $("view-signed-in").hidden = view !== "signed-in";
  }

  function showLogin(note, options = {}) {
    showView("login");
    const line = $("login-note");
    line.textContent = note;
    line.hidden = note === "";
    if (!options.keep) $("login-password").value = "";
    ($("login-email").value ? $("login-password") : $("login-email")).focus();
  }

  async function submitLogin(event) {
    event.preventDefault();
    const note = $("login-note");
    note.hidden = true;
    $("login-submit").disabled = true;
    $("login-sweep").hidden = false;
    try {
      const email = $("login-email").value.trim();
      const body = { password: $("login-password").value };
      if (email) body.email = email;
      const reply = await api("/api/session", { method: "POST", body });
      if (reply.status >= 200 && reply.status < 300) { afterSignIn(); return; }
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

  /* ── wiring ───────────────────────────────────────────────────────── */

  $("login-form").addEventListener("submit", submitLogin);

  // Caps Lock is named while the password is being typed, not after a refusal.
  for (const kind of ["keydown", "keyup"]) {
    $("login-password").addEventListener(kind, (event) => {
      if (typeof event.getModifierState === "function") {
        $("login-caps").hidden = !event.getModifierState("CapsLock");
      }
    });
  }
  $("login-password").addEventListener("blur", () => { $("login-caps").hidden = true; });

  checkSession();
}

boot();
