/*
  The offline stand-in for the box, shared by every frame.

  A state file (scripts/ui-frames/states/<name>.js) sets window.__STATE before this runs:

    window.__STATE = {
      hash: "#mine",                       // optional: which pane to open
      search: "?token=abc",                // optional: rewrites location.search for the app
      routes: {
        "GET /capabilities": {status: 200, body: {...}},
        "GET /me":           {status: 401, body: {error: "sign in first"}},
        "POST ?selfhost":    {status: 200, body: {...}},
      }
    }

  Matching is by method plus the tail of the request path, never by an absolute path: under
  file:// the app derives a different routeBase than it does in production, and a frame that
  matched absolute paths would silently stub nothing and photograph an error state.
*/

(function () {
  "use strict";

  var state = window.__STATE || {};
  var routes = state.routes || {};

  if (state.hash) {
    try { history.replaceState(null, "", location.pathname + location.search + state.hash); }
    catch (error) { /* file:// refuses replaceState in some builds; the hash is optional */ }
  }

  function key(method, url) {
    var text = String(url);
    var mark = text.indexOf("?");
    var query = mark >= 0 ? text.slice(mark) : "";
    var path = mark >= 0 ? text.slice(0, mark) : text;
    // The app's own route base is a prefix we do not know here; keep the last two segments,
    // which is what every route in this API is spelled with (/me, /passkey/login/start).
    var parts = path.split("/").filter(Boolean);
    var tail = parts.slice(-3).join("/");
    return { method: method, tail: tail, query: query };
  }

  function find(method, url) {
    var probe = key(method, url);
    var names = Object.keys(routes);
    for (var index = 0; index < names.length; index += 1) {
      var name = names[index];
      var space = name.indexOf(" ");
      var wantedMethod = name.slice(0, space);
      var wantedPath = name.slice(space + 1);
      if (wantedMethod !== probe.method) continue;
      if (wantedPath.charAt(0) === "?") {
        if (probe.query.indexOf(wantedPath) === 0) return routes[name];
        continue;
      }
      var wantedTail = wantedPath.split("/").filter(Boolean).join("/");
      if (probe.tail === wantedTail || probe.tail.slice(-wantedTail.length) === wantedTail) {
        return routes[name];
      }
    }
    return null;
  }

  window.fetch = function (url, options) {
    options = options || {};
    var method = (options.method || "GET").toUpperCase();
    var answer = find(method, url);
    // A route declared "pending" never answers, which is how the boot state — the one the
    // reader sees while /capabilities and /me are still in flight — is photographed.
    if (answer && answer.pending) return new Promise(function () {});
    if (!answer) {
      answer = { status: 404, body: { error: "no such endpoint" } };
    }
    var headers = answer.headers || {};
    return Promise.resolve({
      ok: answer.status >= 200 && answer.status < 300,
      status: answer.status,
      headers: { get: function (name) { return headers[name] || null; } },
      json: function () { return Promise.resolve(answer.body || {}); }
    });
  };
})();
