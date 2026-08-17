/*
  The reports account app.

  Served by crates/reports/src/service.rs as GET <route>/app.js — its own file rather than an
  inline <script>, so the page's Content-Security-Policy can refuse 'unsafe-inline'.

  Three rules hold everywhere in this file:

  1. Text reaches the DOM through textContent, never innerHTML. A URL reaches an href only
     through safeUrl(), which admits https:, http: and same-origin relative paths and
     nothing else — an attribute sink is exactly what a rule phrased as "never innerHTML"
     misses.
  2. The route this page is mounted at is read from the address bar, never hard-coded.
     <route> is configurable (Config::route, default /report) and the session cookie is
     scoped Path=<route>, so every call has to go back to the prefix we were served from.
  3. The server's two key-spelling conventions are read as the server spells them: /me and
     /capabilities are camelCase, the report objects from /mine are snake_case. Normalising
     them here would only hide the day one of them changes.
*/

(function () {
  "use strict";

  /* ── where we are ──────────────────────────────────────────────────────── */

  // /report/            -> /report
  // /report/index.html  -> /report
  // /report/verify?t=…  -> /report   (the server serves this shell for a browser Accept)
  var path = location.pathname.replace(/\/(index\.html|verify)$/, "").replace(/\/+$/, "");
  var routeBase = path;
  var query = new URLSearchParams(location.search);
  // The confirmation link the verification email carries is <route>/verify?token=… , which
  // the server answers with this same shell for a browser. A token in the query is taken as
  // "this is a confirmation link" wherever it appears, because a mail client that rewrites
  // the path should not turn a working link into a blank account page.
  var isVerifyLanding = query.has("token");

  var state = {
    caps: null,
    me: null,
    projects: [],
    reports: null,
    expanded: null,
    confirming: null,
    booted: false
  };

  /* ── tiny helpers ──────────────────────────────────────────────────────── */

  function el(id) { return document.getElementById(id); }

  function text(node, value) {
    if (!node) return;
    node.textContent = value === undefined || value === null ? "" : String(value);
  }

  function show(node, on) { if (node) node.hidden = !on; }

  function clear(node) { while (node && node.firstChild) node.removeChild(node.firstChild); }

  function make(tag, className, content) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (content !== undefined) node.textContent = String(content);
    return node;
  }

  /* Only these schemes ever reach an href. A javascript: or data: URL from anywhere —
     including from this box's own JSON — is dropped rather than rendered. */
  function safeUrl(value) {
    if (typeof value !== "string" || value === "") return null;
    var parsed;
    try { parsed = new URL(value, location.href); } catch (error) { return null; }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return null;
    return parsed.href;
  }

  function announce(message) { text(el("status"), message); }

  function plural(count, one, many) { return count === 1 ? one : many; }

  function whenText(iso) {
    if (!iso) return "";
    var when = new Date(iso);
    if (isNaN(when.getTime())) return String(iso);
    var seconds = Math.round((Date.now() - when.getTime()) / 1000);
    if (seconds < 45) return "just now";
    var minutes = Math.round(seconds / 60);
    if (minutes < 60) return minutes + " " + plural(minutes, "minute", "minutes") + " ago";
    var hours = Math.round(minutes / 60);
    if (hours < 24) return hours + " " + plural(hours, "hour", "hours") + " ago";
    var days = Math.round(hours / 24);
    if (days < 31) return days + " " + plural(days, "day", "days") + " ago";
    return when.toISOString().slice(0, 10);
  }

  function dateText(unixSeconds) {
    if (typeof unixSeconds !== "number" || !isFinite(unixSeconds)) return "unknown";
    return new Date(unixSeconds * 1000).toISOString().slice(0, 10);
  }

  /* ── the wire ──────────────────────────────────────────────────────────── */

  /* Every call answers the same shape, including when the box cannot be reached at all:
     status 0 stands for "the request never landed", so no caller has to think about
     rejected promises. */
  function api(path, options) {
    options = options || {};
    options.credentials = "same-origin";
    options.headers = options.headers || {};
    options.headers["Accept"] = "application/json";
    return fetch(routeBase + path, options).then(function (response) {
      var retryAfter = parseInt(response.headers.get("Retry-After") || "", 10);
      return response.json().catch(function () { return {}; }).then(function (body) {
        return {
          ok: response.ok,
          status: response.status,
          body: body || {},
          retryAfter: isFinite(retryAfter) ? retryAfter : null
        };
      });
    }, function () {
      return {
        ok: false,
        status: 0,
        body: { error: "could not reach the box — check your connection" },
        retryAfter: null
      };
    });
  }

  function post(path, payload) {
    return api(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload === undefined ? {} : payload)
    });
  }

  /* One place decides what a failed call means. A 401 on any authenticated route is a dead
     session, wherever it happened, and it puts the whole page back to signed-out with an
     explanation rather than leaving a half-signed-in view on screen. */
  function failure(result, fallback) {
    if (result.status === 401 && state.me) {
      sessionExpired();
      return null;
    }
    if (result.status === 429) {
      var wait = result.retryAfter;
      return wait ? "Too many attempts. Try again in " + countdownText(wait) + "."
        : "Too many attempts just now — wait a moment and try again.";
    }
    if (result.status === 0) return result.body.error;
    return (result.body && result.body.error) || fallback ||
      ("something went wrong (HTTP " + result.status + ")");
  }

  /* A 429 is the one refusal with a remedy attached: the box says in Retry-After exactly how
     long. The form goes quiet for that long and counts down out loud, rather than inviting a
     press that is guaranteed to be refused. The countdown is informational — it never removes
     anything from the page, and the form re-enables itself. */
  function holdFor(button, seconds, errorNode, noun) {
    var left = Math.max(1, Math.round(seconds));
    button.disabled = true;
    (function tick() {
      if (left <= 0) {
        button.disabled = false;
        text(errorNode, "You can try again now.");
        return;
      }
      text(errorNode, "Too many " + noun + ". Try again in " + countdownText(left) + ".");
      left -= 1;
      setTimeout(tick, 1000);
    })();
  }

  function countdownText(seconds) {
    var whole = Math.max(0, Math.round(seconds));
    var minutes = Math.floor(whole / 60);
    var rest = whole % 60;
    return minutes + ":" + (rest < 10 ? "0" : "") + rest;
  }

  /* A submit can never be pressed twice: the button says what it is doing, the fields go
     read-only, and re-entry is refused until the answer lands. */
  function busy(button, on, label) {
    if (!button) return;
    button.disabled = on;
    if (on) {
      button.setAttribute("aria-busy", "true");
      if (label) {
        button.dataset.idle = button.textContent;
        text(button, label);
      }
    } else {
      button.removeAttribute("aria-busy");
      if (button.dataset.idle) {
        text(button, button.dataset.idle);
        delete button.dataset.idle;
      }
    }
    var form = button.form;
    if (form) {
      Array.prototype.forEach.call(form.elements, function (field) {
        if (field !== button && field.tagName !== "BUTTON") field.readOnly = on;
      });
    }
  }

  function fieldError(errorNode, message, focusTarget) {
    text(errorNode, message || "");
    if (focusTarget) {
      focusTarget.setAttribute("aria-invalid", message ? "true" : "false");
      if (message) focusTarget.focus();
    }
  }

  /* ── views ─────────────────────────────────────────────────────────────── */

  function setView(name) {
    document.documentElement.dataset.view = name;
    var titles = {
      checking: "Reports account",
      anon: "Sign in — reports",
      in: "Your account — reports",
      verify: "Confirm your email — reports",
      unavailable: "Accounts are off — reports"
    };
    document.title = titles[name] || "Reports account";
  }

  function focusHeading(id) {
    var heading = el(id);
    if (heading && state.booted) heading.focus();
  }

  function banner(hostId, kind, message, actionLabel, action) {
    var host = el(hostId);
    if (!host) return;
    clear(host);
    var box = make("div", "banner" + (kind ? " " + kind : ""));
    var paragraph = make("p");
    paragraph.appendChild(make("span", null, message));
    box.appendChild(paragraph);
    if (actionLabel) {
      var actions = make("div", "banner-actions");
      var button = make("button", "btn", actionLabel);
      button.type = "button";
      button.addEventListener("click", function () { action(button); });
      actions.appendChild(button);
      box.appendChild(actions);
    }
    host.appendChild(box);
  }

  function sessionExpired() {
    state.me = null;
    whoLine();
    setView("anon");
    banner("anon-banner", "bad", "Your session expired. Sign in again — anything you had "
      + "typed into a report is still here.");
    var email = el("login-email");
    if (email) email.focus();
  }

  /* ── boot ──────────────────────────────────────────────────────────────── */

  function whoLine() {
    text(el("who"), state.me ? state.me.email : location.host);
  }

  function boot() {
    whoLine();
    // Under file:// — the frame harness — there is no host and the path is the checkout's,
    // which says nothing; on the box it is the address this app is actually mounted at.
    text(el("foot-route"), location.host ? location.host + (routeBase || "/") : "local preview");

    Promise.all([api("/capabilities"), api("/me")]).then(function (answers) {
      var caps = answers[0];
      var me = answers[1];

      if (caps.status === 404 && me.status === 404) {
        state.booted = true;
        setView("unavailable");
        return;
      }

      state.caps = caps.ok ? caps.body : defaultCaps();
      applyLimits();

      if (isVerifyLanding) {
        state.me = me.ok ? me.body : null;
        state.booted = true;
        setView("verify");
        return;
      }

      if (me.ok) {
        state.me = me.body;
        enterSignedIn();
      } else {
        state.me = null;
        setView("anon");
        renderAnon();
      }
      state.booted = true;
      reportSignInOutcome();
    });
  }

  /* If /capabilities is unreachable the page still has to draw something honest: assume the
     doors that always exist (password sign-in) and none of the ones that need configuration,
     so no button is offered that would answer 404. */
  function defaultCaps() {
    return {
      accounts: true,
      passkeys: false,
      oauthProviders: [],
      mailConfigured: false,
      limits: {}
    };
  }

  function limits() { return (state.caps && state.caps.limits) || {}; }

  function applyLimits() {
    var bounds = limits();
    [["register-password", "passwordMin", "passwordMax"],
     ["password-new", "passwordMin", "passwordMax"]].forEach(function (spec) {
      var input = el(spec[0]);
      if (!input) return;
      if (bounds[spec[1]]) input.minLength = bounds[spec[1]];
      if (bounds[spec[2]]) input.maxLength = bounds[spec[2]];
    });
    [["file-title-input", "titleMax"], ["file-detail", "detailMax"],
     ["file-repro", "reproMax"]].forEach(function (spec) {
      var input = el(spec[0]);
      if (input && bounds[spec[1]]) input.maxLength = bounds[spec[1]];
    });
    countAll();
  }

  /* The OAuth landing: the callback redirects here with one of a fixed set of codes, never
     with a provider error string, so every case below is one this page chose to write. */
  function reportSignInOutcome() {
    var failed = query.get("signin_error");
    if (failed) {
      var sentences = {
        expired: "That sign-in attempt expired before it came back. Start it again.",
        provider_unreachable: "The sign-in provider could not be reached from this box.",
        unavailable: "Sign-in through a provider is not available on this box right now.",
        email_conflict: "That address already belongs to an account here, and the provider "
          + "did not confirm it. Sign in with your password instead.",
        unknown_provider: "That sign-in provider is not configured on this box."
      };
      banner(state.me ? "in-banner" : "anon-banner", "bad",
        sentences[failed] || "That sign-in did not complete.");
    } else if (query.has("signedin") && state.me) {
      announce("Signed in.");
    }
    if (query.has("signedin") || failed) {
      history.replaceState(null, "", location.pathname + location.hash);
    }
  }

  /* ── signed out ────────────────────────────────────────────────────────── */

  function renderAnon() {
    whoLine();
    var caps = state.caps || defaultCaps();
    show(el("passkey-login"), !!caps.passkeys && !!window.PublicKeyCredential);
    show(el("passkey-register"), !!caps.passkeys && !!window.PublicKeyCredential);

    var providers = Array.isArray(caps.oauthProviders) ? caps.oauthProviders : [];
    var row = el("oauth-row");
    var host = el("oauth-buttons");
    clear(host);
    show(row, providers.length > 0);
    providers.forEach(function (name) {
      var button = make("button", "btn", "Continue with " + titleCase(name));
      button.type = "button";
      button.addEventListener("click", function () {
        // A top-level navigation, never a fetch and never a popup: this origin refuses to be
        // framed, and the provider will not answer a cross-origin XHR anyway.
        location.assign(routeBase + "/oauth/" + encodeURIComponent(name) + "/start");
      });
      host.appendChild(button);
    });
  }

  function titleCase(name) {
    if (typeof name !== "string" || !name) return "";
    return name.charAt(0).toUpperCase() + name.slice(1);
  }

  function signIn(event) {
    event.preventDefault();
    var button = el("login-submit");
    var email = el("login-email").value.trim();
    var password = el("login-password").value;
    fieldError(el("login-error"), "", el("login-email"));
    if (!email || !password) {
      fieldError(el("login-error"), "Both an email address and a password are needed.",
        el("login-email"));
      return;
    }
    busy(button, true, "Signing in…");
    post("/login", { email: email, password: password }).then(function (result) {
      busy(button, false);
      if (result.status === 429 && result.retryAfter) {
        holdFor(button, result.retryAfter, el("login-error"), "sign-in attempts");
        return;
      }
      if (!result.ok) {
        fieldError(el("login-error"), failure(result, "sign-in failed"), el("login-password"));
        return;
      }
      el("login-password").value = "";
      afterSignIn();
    });
  }

  function register(event) {
    event.preventDefault();
    var button = el("register-submit");
    var email = el("register-email").value.trim();
    var password = el("register-password").value;
    var bounds = limits();
    var least = bounds.passwordMin || 8;
    fieldError(el("register-error"), "", el("register-email"));
    if (!email) {
      fieldError(el("register-error"), "An email address is needed.", el("register-email"));
      return;
    }
    if (password.length < least) {
      fieldError(el("register-error"),
        "A password must be at least " + least + " characters.", el("register-password"));
      return;
    }
    busy(button, true, "Registering…");
    post("/register", { email: email, password: password }).then(function (result) {
      busy(button, false);
      if (result.status === 429 && result.retryAfter) {
        holdFor(button, result.retryAfter, el("register-error"), "attempts");
        return;
      }
      if (!result.ok) {
        fieldError(el("register-error"), failure(result, "registration failed"),
          el("register-email"));
        return;
      }
      el("register-password").value = "";
      announce("Account created.");
      afterSignIn();
    });
  }

  function afterSignIn() {
    // A session mint answers {"signedIn":true} and nothing else — who we are is a second
    // question, and only /me answers it.
    return api("/me").then(function (result) {
      if (!result.ok) {
        setView("anon");
        return;
      }
      state.me = result.body;
      enterSignedIn();
      focusHeading("in-title");
    });
  }

  /* ── signed in ─────────────────────────────────────────────────────────── */

  function enterSignedIn() {
    setView("in");
    renderAccount();
    renderVerifyBanner();
    openPane(paneFromHash(), true);
    loadProjects();
  }

  function paneFromHash() {
    var wanted = (location.hash || "").replace("#", "");
    return ["file", "mine", "account", "download"].indexOf(wanted) >= 0 ? wanted : "file";
  }

  function openPane(name, quiet) {
    ["file", "mine", "account", "download"].forEach(function (pane) {
      var node = el("pane-" + pane);
      if (node) node.classList.toggle("on", pane === name);
    });
    Array.prototype.forEach.call(document.querySelectorAll(".rail button"), function (button) {
      if (button.dataset.pane === name) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    });
    if (location.hash !== "#" + name) history.replaceState(null, "", "#" + name);
    if (name === "mine" && state.reports === null) loadMine();
    if (name === "download") loadDownload();
    if (!quiet) {
      var heads = { file: "file-title", mine: "mine-title", account: "account-title",
        download: "download-title" };
      focusHeading(heads[name]);
    }
  }

  function renderVerifyBanner() {
    var host = el("in-banner");
    if (!state.me || state.me.emailVerified) { clear(host); return; }
    if (state.caps && state.caps.mailConfigured) {
      banner("in-banner", "", "Confirm " + state.me.email + " to prove the address is "
        + "reachable. Nothing on this account is blocked until you do.", "Resend the link",
        function (button) {
          busy(button, true, "Sending…");
          post("/verify/resend").then(function (result) {
            busy(button, false);
            if (result.ok && result.body.alreadyVerified) {
              announce("That address is already confirmed.");
              refreshMe();
              return;
            }
            if (result.ok) {
              banner("in-banner", "good", "A fresh link is on its way to " + state.me.email + ".");
              announce("Verification link sent.");
              return;
            }
            banner("in-banner", "bad", failure(result, "the link could not be sent") || "");
          });
        });
    } else {
      banner("in-banner", "", "This box has no outbound mail configured, so no confirmation "
        + "link can be sent. Nothing on this account is blocked by it.");
    }
  }

  function refreshMe() {
    return api("/me").then(function (result) {
      if (result.ok) {
        state.me = result.body;
        renderAccount();
        renderVerifyBanner();
      } else if (result.status === 401) {
        sessionExpired();
      }
      return result;
    });
  }

  /* ── account pane ──────────────────────────────────────────────────────── */

  function renderAccount() {
    var me = state.me;
    if (!me) return;
    whoLine();
    text(el("account-email"), me.email);
    text(el("account-id"), me.id);
    text(el("account-plan"), me.plan || "free");
    text(el("account-created"), dateText(me.createdUnix));

    var verified = el("account-verified");
    clear(verified);
    verified.appendChild(make("span", me.emailVerified ? "chip ok" : "chip warn",
      me.emailVerified ? "confirmed" : "unconfirmed"));

    var hasPassword = me.hasPassword === true;
    text(el("password-title"), hasPassword ? "Change password" : "Set a password");
    text(el("password-submit"), hasPassword ? "Change password" : "Set password");
    text(el("password-note"), hasPassword
      ? "One field. The live session is the proof — there is no old-password box."
      : "This account has no password yet, so it can only be reached the way it was made. "
        + "Setting one adds the ordinary door.");

    var caps = state.caps || defaultCaps();
    var passkeys = Array.isArray(me.passkeys) ? me.passkeys : [];
    show(el("passkeys-block"), !!caps.passkeys);
    var perAccount = limits().passkeysPerAccount;
    text(el("passkeys-count"), perAccount ? passkeys.length + " of " + perAccount
      : String(passkeys.length));
    var list = el("passkeys-list");
    clear(list);
    if (passkeys.length === 0) {
      list.appendChild(make("li", "empty", "No passkey on this account yet."));
    }
    passkeys.forEach(function (passkey) {
      var row = make("li", "entry");
      var head = make("div", "entry-head");
      var left = make("div");
      left.appendChild(make("p", "entry-title", passkey.label || "unnamed device"));
      var meta = make("div", "entry-meta");
      meta.appendChild(make("span", "id", String(passkey.id || "").slice(0, 16) + "…"));
      meta.appendChild(make("span", null, "added " + dateText(passkey.createdUnix)));
      left.appendChild(meta);
      head.appendChild(left);
      row.appendChild(head);
      list.appendChild(row);
    });
    show(el("passkey-add"), !!caps.passkeys && !!window.PublicKeyCredential);

    var linked = Array.isArray(me.oauthProviders) ? me.oauthProviders : [];
    var providers = Array.isArray(caps.oauthProviders) ? caps.oauthProviders : [];
    show(el("linked-block"), providers.length > 0 || linked.length > 0);
    var linkedHost = el("linked-list");
    clear(linkedHost);
    providers.forEach(function (name) {
      if (linked.indexOf(name) >= 0) {
        linkedHost.appendChild(make("span", "chip ok", titleCase(name) + " — linked"));
        return;
      }
      var button = make("button", "btn", "Link " + titleCase(name));
      button.type = "button";
      button.addEventListener("click", function () {
        location.assign(routeBase + "/oauth/" + encodeURIComponent(name) + "/start");
      });
      linkedHost.appendChild(button);
    });
    linked.forEach(function (name) {
      if (providers.indexOf(name) < 0) {
        linkedHost.appendChild(make("span", "chip", titleCase(name) + " — linked"));
      }
    });
  }

  function setPassword(event) {
    event.preventDefault();
    var button = el("password-submit");
    var input = el("password-new");
    var value = input.value;
    var least = limits().passwordMin || 8;
    fieldError(el("password-error"), "", input);
    if (value.length < least) {
      fieldError(el("password-error"), "A password must be at least " + least + " characters.",
        input);
      return;
    }
    busy(button, true, "Saving…");
    post("/me/password", { password: value }).then(function (result) {
      busy(button, false);
      if (!result.ok) {
        fieldError(el("password-error"), failure(result, "the password was not changed"), input);
        return;
      }
      input.value = "";
      announce("Password saved. Every other session was signed out.");
      banner("in-banner", "good", "Password saved. Every other device was signed out; this "
        + "one is on a fresh session.");
      refreshMe();
    });
  }

  /* ── file a report ─────────────────────────────────────────────────────── */

  function loadProjects() {
    api("/projects").then(function (result) {
      state.projects = (result.ok && Array.isArray(result.body.projects))
        ? result.body.projects : [];
      var picker = el("file-project");
      clear(picker);
      state.projects.forEach(function (key) {
        var option = make("option", null, key);
        option.value = key;
        picker.appendChild(option);
      });
      var fresh = make("option", null, "Something else…");
      fresh.value = "__new";
      picker.appendChild(fresh);
      if (state.projects.length === 0) picker.value = "__new";
      pickerChanged();
    });
  }

  function pickerChanged(fromReader) {
    var picker = el("file-project");
    var isNew = picker.value === "__new";
    show(el("file-newproject-field"), isNew);
    if (isNew && fromReader === true) el("file-newproject").focus();
  }

  var PROJECT_KEY = /^[a-z0-9](?:[a-z0-9._-]{0,38}[a-z0-9])?$/;

  function normaliseKey(value) {
    return String(value).trim().toLowerCase().replace(/\s+/g, "-");
  }

  function countAll() {
    [["file-title-input", "file-title-counter"], ["file-detail", "file-detail-counter"],
     ["file-repro", "file-repro-counter"]].forEach(function (pair) {
      count(el(pair[0]), el(pair[1]));
    });
  }

  function count(input, counter) {
    if (!input || !counter) return;
    var max = input.maxLength;
    if (!max || max < 0) { text(counter, ""); return; }
    var used = input.value.length;
    if (used < max * 0.8) { text(counter, ""); counter.classList.remove("near"); return; }
    text(counter, used + " / " + max);
    counter.classList.toggle("near", used > max * 0.95);
  }

  function fileReport(event) {
    event.preventDefault();
    var button = el("file-submit");
    var errorNode = el("file-error");
    var picker = el("file-project");
    var project = picker.value === "__new" ? normaliseKey(el("file-newproject").value)
      : picker.value;
    fieldError(errorNode, "");

    if (!project) {
      fieldError(errorNode, "Name the project this is about.",
        picker.value === "__new" ? el("file-newproject") : picker);
      return;
    }
    if (!PROJECT_KEY.test(project)) {
      fieldError(errorNode, "A project key is 1 to 40 characters of a–z, 0–9, dot, underscore "
        + "or dash, beginning and ending with a letter or digit.", el("file-newproject"));
      return;
    }

    var title = el("file-title-input").value.trim();
    var detail = el("file-detail").value.trim();
    if (!title) {
      fieldError(errorNode, "A title is required: one line naming what went wrong.",
        el("file-title-input"));
      return;
    }
    if (!detail) {
      fieldError(errorNode, "Detail is required: what you did, what you expected, what "
        + "happened instead.", el("file-detail"));
      return;
    }

    var kind = "bug";
    Array.prototype.forEach.call(document.getElementsByName("kind"), function (radio) {
      if (radio.checked) kind = radio.value;
    });

    var payload = { kind: kind, title: title, detail: detail };
    [["repro", "file-repro"], ["route", "file-route"], ["tool", "file-tool"],
     ["platform", "file-platform"], ["workspace", "file-workspace"]].forEach(function (pair) {
      var value = el(pair[1]).value.trim();
      if (value) payload[pair[0]] = value;
    });

    // The service selector is the first BARE query word — /report?dx, never ?project=dx.
    busy(button, true, "Filing…");
    api("?" + encodeURIComponent(project), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    }).then(function (result) {
      busy(button, false);
      if (!result.ok) {
        fieldError(errorNode, failure(result, "the report was not filed"), el("file-title-input"));
        return;
      }
      showFiled(result.body);
    });
  }

  function showFiled(body) {
    var known = body.known === true;
    var box = el("file-result");
    text(el("file-result-title"), known
      ? "Already known — sighting " + body.sightings
      : "Filed as " + body.filed);
    text(el("file-result-note"), known
      ? "This is the same defect as " + body.filed + " in " + body.project
        + ", so it counts as another sighting rather than a second report. That is a good "
        + "outcome: it is how a defect earns its priority."
      : "Against " + body.project + ". It is on the board now.");
    show(box, true);
    box.classList.add("primary");
    state.reports = null;
    el("file-form").reset();
    countAll();
    pickerChanged();
    announce(known ? "Already known — another sighting recorded." : "Report filed.");
    el("file-result-title").scrollIntoView({ block: "nearest" });
    state.lastFiled = body.filed;
  }

  /* ── your reports ──────────────────────────────────────────────────────── */

  function loadMine() {
    var list = el("mine-list");
    text(el("mine-error"), "");
    text(el("mine-note"), "Reading the ledger…");
    api("/mine").then(function (result) {
      if (!result.ok) {
        text(el("mine-note"), "");
        var message = failure(result, "your reports could not be read");
        if (message) text(el("mine-error"), message);
        return;
      }
      state.reports = Array.isArray(result.body.reports) ? result.body.reports : [];
      renderMine();
    });
  }

  function renderMine() {
    var list = el("mine-list");
    clear(list);
    var reports = state.reports || [];
    if (reports.length === 0) {
      text(el("mine-note"), "");
      var empty = make("li", "empty");
      empty.appendChild(make("p", null, "Nothing filed from this account yet."));
      var go = make("button", "btn", "File your first report");
      go.type = "button";
      go.addEventListener("click", function () { openPane("file"); });
      empty.appendChild(go);
      list.appendChild(empty);
      return;
    }
    text(el("mine-note"), reports.length + " " + plural(reports.length, "report", "reports")
      + " filed from this account. A report that was closed or removed is not listed.");
    reports.forEach(function (report) { list.appendChild(entryRow(report)); });
  }

  function entryRow(report) {
    var row = make("li", "entry");
    var id = String(report.id || "");

    var head = make("button", "entry-head");
    head.type = "button";
    head.setAttribute("aria-expanded", state.expanded === id ? "true" : "false");
    var left = make("div");
    left.appendChild(make("p", "entry-title", report.title || "(no title)"));
    var meta = make("div", "entry-meta");
    meta.appendChild(make("span", "id", id));
    meta.appendChild(make("span", "chip", report.kind || "report"));
    meta.appendChild(make("span", null, report.project || ""));
    if (report.sightings > 1) {
      meta.appendChild(make("span", "chip count", report.sightings + " sightings"));
    }
    if (report.delivered) meta.appendChild(make("span", "chip ok", "delivered"));
    var when = make("time", null, whenText(report.last_at));
    if (report.last_at) {
      when.setAttribute("datetime", report.last_at);
      when.title = report.last_at;
    }
    meta.appendChild(when);
    left.appendChild(meta);
    head.appendChild(left);
    head.appendChild(make("span", "entry-caret", "\u203A"));
    head.addEventListener("click", function () {
      state.expanded = state.expanded === id ? null : id;
      renderMine();
      var reopened = document.querySelector('[data-entry="' + cssEscape(id) + '"]');
      if (reopened) reopened.focus();
    });
    head.dataset.entry = id;
    row.appendChild(head);

    if (state.expanded === id) row.appendChild(entryBody(report));
    return row;
  }

  function cssEscape(value) { return String(value).replace(/["\\]/g, "\\$&"); }

  function entryBody(report) {
    var body = make("div", "entry-body");

    if (report.detail) {
      body.appendChild(make("h4", null, "Detail"));
      body.appendChild(make("p", null, report.detail));
    }
    if (report.repro) {
      body.appendChild(make("h4", null, "Reproduction"));
      body.appendChild(make("p", null, report.repro));
    }
    if (report.route) {
      body.appendChild(make("h4", null, "Route"));
      body.appendChild(make("p", "mono", report.route));
    }
    body.appendChild(make("h4", null, "First seen"));
    body.appendChild(make("p", null, whenText(report.first_at) + " · " + (report.first_at || "")));

    var seen = Array.isArray(report.seen) ? report.seen : [];
    if (seen.length > 0) {
      body.appendChild(make("h4", null, "Sightings"));
      var timeline = make("ul", "timeline");
      seen.forEach(function (sighting) {
        var item = make("li");
        var when = make("time", null, sighting.at || "");
        if (sighting.at) when.setAttribute("datetime", sighting.at);
        item.appendChild(when);
        [sighting.tool, sighting.platform, sighting.workspace, sighting.source]
          .filter(Boolean)
          .forEach(function (part) { item.appendChild(make("span", null, part)); });
        if (sighting.detail) item.appendChild(make("span", null, sighting.detail));
        timeline.appendChild(item);
      });
      body.appendChild(timeline);
    }

    if (state.confirming === report.id) {
      body.appendChild(withdrawConfirm(report));
    } else {
      var actions = make("div", "actions");
      var withdraw = make("button", "btn-danger", "Withdraw this report");
      withdraw.type = "button";
      withdraw.addEventListener("click", function () {
        state.confirming = report.id;
        renderMine();
        var confirmButton = el("withdraw-yes");
        if (confirmButton) confirmButton.focus();
      });
      actions.appendChild(withdraw);
      body.appendChild(actions);
    }
    return body;
  }

  function withdrawConfirm(report) {
    var box = make("div", "confirm");
    box.setAttribute("role", "group");
    box.setAttribute("aria-label", "Confirm withdrawal");
    var line = make("p");
    line.appendChild(make("span", null, "Withdraw “" + (report.title || "this report") + "” ("));
    line.appendChild(make("span", "mono", report.id));
    line.appendChild(make("span", null, ")? It is deleted from this box, not hidden."));
    box.appendChild(line);

    var actions = make("div", "actions");
    var yes = make("button", "btn-danger", "Withdraw it");
    yes.type = "button";
    yes.id = "withdraw-yes";
    yes.addEventListener("click", function () {
      busy(yes, true, "Withdrawing…");
      post("/mine/withdraw", { project: report.project, id: report.id }).then(function (result) {
        busy(yes, false);
        var gone = result.ok && typeof result.body.withdrawn === "string";
        if (gone || result.status === 404) {
          state.confirming = null;
          state.reports = (state.reports || []).filter(function (other) {
            return other.id !== report.id;
          });
          renderMine();
          announce(gone ? "Withdrawn." : "That report is already gone.");
          return;
        }
        text(el("mine-error"), failure(result, "the report could not be withdrawn") || "");
      });
    });
    var no = make("button", "btn-quiet", "Keep it");
    no.type = "button";
    no.addEventListener("click", function () {
      state.confirming = null;
      renderMine();
      var head = document.querySelector('[data-entry="' + cssEscape(report.id) + '"]');
      if (head) head.focus();
    });
    actions.appendChild(yes);
    actions.appendChild(no);
    box.appendChild(actions);

    box.addEventListener("keydown", function (event) {
      if (event.key === "Escape") { no.click(); }
    });
    return box;
  }

  /* ── download ──────────────────────────────────────────────────────────── */

  function loadDownload() {
    var actions = el("download-actions");
    clear(actions);
    clear(el("download-clone"));
    text(el("download-error"), "");
    text(el("download-setup"), "");
    text(el("download-note"), "Fetching the current link…");

    api("/download").then(function (result) {
      if (!result.ok) {
        text(el("download-note"), "");
        var message = failure(result, "the download link is not available right now");
        if (message === null) return;
        text(el("download-error"), message);
        var retry = make("button", "btn", "Try again");
        retry.type = "button";
        retry.addEventListener("click", loadDownload);
        el("download-actions").appendChild(retry);
        return;
      }
      var body = result.body;
      text(el("download-note"), "The source of everything running on this box, straight from "
        + "the repository it self-updates from.");

      var href = safeUrl(body.downloadUrl);
      if (href) {
        var link = document.createElement("a");
        link.className = "btn-primary as-link";
        link.href = href;
        link.rel = "noopener noreferrer";
        link.textContent = "Download the " + (body.branch || "main") + " archive";
        el("download-actions").appendChild(link);
      }

      var repository = safeUrl(body.repository);
      if (repository) {
        var clone = make("div", "cmd");
        clone.appendChild(make("code", null, "git clone " + repository
          + (body.branch ? " --branch " + body.branch : "")));
        var copy = make("button", "btn-quiet", "Copy");
        copy.type = "button";
        copy.addEventListener("click", function () {
          copyText("git clone " + repository + (body.branch ? " --branch " + body.branch : ""),
            copy);
        });
        clone.appendChild(copy);
        el("download-clone").appendChild(clone);
      }

      text(el("download-setup"), body.setup || "");
    });
  }

  function copyText(value, button) {
    if (!navigator.clipboard) { announce("Copying is not available in this browser."); return; }
    navigator.clipboard.writeText(value).then(function () {
      var was = button.textContent;
      text(button, "Copied");
      announce("Copied.");
      setTimeout(function () { text(button, was); }, 1200);
    }, function () {
      announce("Copying was refused by the browser.");
    });
  }

  /* ── confirm an email address ──────────────────────────────────────────── */

  function confirmEmail() {
    var button = el("verify-confirm");
    var token = query.get("token") || "";
    if (!token) {
      text(el("verify-error"), "This link carries no token. Ask for a fresh one.");
      return;
    }
    busy(button, true, "Confirming…");
    post("/verify/confirm", { token: token }).then(function (result) {
      busy(button, false);
      if (result.ok && result.body.verified) {
        text(el("verify-title"), "Email confirmed");
        text(el("verify-note"), "That address is proven reachable. Nothing else to do here.");
        var actions = el("verify-actions");
        clear(actions);
        var go = make("button", "btn-primary", "Continue to your account");
        go.type = "button";
        go.addEventListener("click", function () { location.assign(routeBase + "/"); });
        actions.appendChild(go);
        announce("Email confirmed.");
        return;
      }
      text(el("verify-error"), failure(result, "this link is invalid or has expired") || "");
      var actions = el("verify-actions");
      clear(actions);
      var next = make("button", "btn", state.me ? "Send me a fresh link" : "Sign in to ask for a new link");
      next.type = "button";
      next.addEventListener("click", function () {
        if (!state.me) { location.assign(routeBase + "/"); return; }
        busy(next, true, "Sending…");
        post("/verify/resend").then(function (resent) {
          busy(next, false);
          if (resent.ok && resent.body.alreadyVerified) {
            text(el("verify-error"), "");
            text(el("verify-note"), "That address is already confirmed.");
            return;
          }
          text(el("verify-note"), resent.ok ? "A fresh link is on its way."
            : (failure(resent, "the link could not be sent") || ""));
        });
      });
      actions.appendChild(next);
    });
  }

  /* ── passkeys ──────────────────────────────────────────────────────────── */

  function fromBase64Url(value) {
    var padded = String(value).replace(/-/g, "+").replace(/_/g, "/");
    while (padded.length % 4) padded += "=";
    var raw = atob(padded);
    var bytes = new Uint8Array(raw.length);
    for (var index = 0; index < raw.length; index += 1) bytes[index] = raw.charCodeAt(index);
    return bytes;
  }

  function toBase64Url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var index = 0; index < bytes.length; index += 1) {
      binary += String.fromCharCode(bytes[index]);
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function deviceLabel() {
    var agent = navigator.userAgent || "";
    if (/iPhone|iPad/.test(agent)) return "iPhone or iPad";
    if (/Macintosh/.test(agent)) return "this Mac";
    if (/Windows/.test(agent)) return "this Windows PC";
    if (/Android/.test(agent)) return "this Android device";
    return "this browser";
  }

  function passkeyRegister(email, button, errorNode) {
    busy(button, true, "Waiting for the device…");
    post("/passkey/register/start", email ? { email: email } : {}).then(function (start) {
      if (!start.ok) {
        busy(button, false);
        text(errorNode, failure(start, "a passkey could not be registered") || "");
        return;
      }
      var userId = new Uint8Array(16);
      (window.crypto || {}).getRandomValues && window.crypto.getRandomValues(userId);
      return navigator.credentials.create({
        publicKey: {
          challenge: fromBase64Url(start.body.challenge),
          rp: { id: start.body.rpId, name: location.host },
          user: {
            id: userId,
            name: email || (state.me && state.me.email) || "account",
            displayName: email || (state.me && state.me.email) || "account"
          },
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: { userVerification: "required", residentKey: "required" },
          timeout: 60000
        }
      }).then(function (credential) {
        return post("/passkey/register/finish", {
          id: credential.id,
          algorithm: -7,
          publicKey: toBase64Url(credential.response.getPublicKey
            ? credential.response.getPublicKey() : new ArrayBuffer(0)),
          clientDataJSON: toBase64Url(credential.response.clientDataJSON),
          authenticatorData: toBase64Url(credential.response.getAuthenticatorData
            ? credential.response.getAuthenticatorData() : new ArrayBuffer(0)),
          label: deviceLabel()
        }).then(function (finish) {
          busy(button, false);
          if (!finish.ok) {
            text(errorNode, failure(finish, "that passkey could not be verified") || "");
            return;
          }
          announce("Passkey registered.");
          if (state.me) refreshMe(); else afterSignIn();
        });
      }, function (error) {
        busy(button, false);
        text(errorNode, error && error.name === "NotAllowedError"
          ? "The device did not confirm. Nothing was changed."
          : "This browser could not complete the passkey ceremony.");
      });
    });
  }

  function passkeyLogin(button, errorNode) {
    busy(button, true, "Waiting for the device…");
    post("/passkey/login/start").then(function (start) {
      if (!start.ok) {
        busy(button, false);
        text(errorNode, failure(start, "no passkey could be used here") || "");
        return;
      }
      return navigator.credentials.get({
        publicKey: {
          challenge: fromBase64Url(start.body.challenge),
          rpId: start.body.rpId,
          userVerification: "required",
          timeout: 60000
        }
      }).then(function (assertion) {
        return post("/passkey/login/finish", {
          id: assertion.id,
          clientDataJSON: toBase64Url(assertion.response.clientDataJSON),
          authenticatorData: toBase64Url(assertion.response.authenticatorData),
          signature: toBase64Url(assertion.response.signature)
        }).then(function (finish) {
          busy(button, false);
          if (!finish.ok) {
            text(errorNode, failure(finish, "that passkey could not be verified") || "");
            return;
          }
          afterSignIn();
        });
      }, function (error) {
        busy(button, false);
        text(errorNode, error && error.name === "NotAllowedError"
          ? "The device did not confirm. Nothing was changed."
          : "This browser could not complete the passkey ceremony.");
      });
    });
  }

  /* ── wiring ────────────────────────────────────────────────────────────── */

  function wire() {
    el("login-form").addEventListener("submit", signIn);
    el("register-form").addEventListener("submit", register);
    el("password-form").addEventListener("submit", setPassword);
    el("file-form").addEventListener("submit", fileReport);
    el("file-project").addEventListener("change", function () { pickerChanged(true); });
    el("mine-refresh").addEventListener("click", loadMine);
    el("verify-confirm").addEventListener("click", confirmEmail);

    el("passkey-login").addEventListener("click", function () {
      passkeyLogin(el("passkey-login"), el("login-error"));
    });
    el("passkey-register").addEventListener("click", function () {
      var email = el("register-email").value.trim();
      if (!email) {
        fieldError(el("register-error"), "An email address is needed first.",
          el("register-email"));
        return;
      }
      passkeyRegister(email, el("passkey-register"), el("register-error"));
    });
    el("passkey-add").addEventListener("click", function () {
      passkeyRegister(null, el("passkey-add"), el("passkey-error"));
    });

    el("account-id-copy").addEventListener("click", function () {
      copyText(state.me ? state.me.id : "", el("account-id-copy"));
    });

    el("file-result-again").addEventListener("click", function () {
      show(el("file-result"), false);
      el("file-title-input").focus();
    });
    el("file-result-see").addEventListener("click", function () {
      state.expanded = state.lastFiled || null;
      state.reports = null;
      openPane("mine");
    });

    el("logout-button").addEventListener("click", function () {
      var button = el("logout-button");
      busy(button, true, "Signing out…");
      post("/logout").then(function () {
        busy(button, false);
        state.me = null;
        state.reports = null;
        setView("anon");
        renderAnon();
        clear(el("anon-banner"));
        announce("Signed out.");
        el("login-email").focus();
      });
    });

    Array.prototype.forEach.call(document.querySelectorAll(".rail button"), function (button) {
      button.addEventListener("click", function () { openPane(button.dataset.pane); });
    });

    [["file-title-input", "file-title-counter"], ["file-detail", "file-detail-counter"],
     ["file-repro", "file-repro-counter"]].forEach(function (pair) {
      var input = el(pair[0]);
      input.addEventListener("input", function () { count(input, el(pair[1])); });
    });

    window.addEventListener("hashchange", function () {
      if (document.documentElement.dataset.view === "in") openPane(paneFromHash(), true);
    });

    // A tab left open for hours is the ordinary case, and a dead session should be found by
    // the page rather than by the next thing the reader tries to do.
    var hiddenSince = 0;
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) { hiddenSince = Date.now(); return; }
      if (state.me && hiddenSince && Date.now() - hiddenSince > 60000) refreshMe();
    });
  }

  wire();
  boot();
})();
