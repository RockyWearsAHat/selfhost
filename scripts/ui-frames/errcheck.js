/*
  The console watcher, injected alongside a frame's fixtures.

  A screenshot cannot fail: a page whose script threw on the first line still photographs
  beautifully, because the markup is all there and only the behaviour is gone. So every state
  is also loaded with this in front of it, which records anything the page throws — including
  a rejected promise nobody handled — and writes the verdict into the footer, where a DOM dump
  can read it as text rather than as pixels.
*/

window.__ERRORS = [];

window.addEventListener("error", function (event) {
  window.__ERRORS.push(String(event.message) + " @" + (event.filename || "") + ":"
    + (event.lineno || ""));
});

window.addEventListener("unhandledrejection", function (event) {
  window.__ERRORS.push("unhandled rejection: " + String(event.reason));
});

window.addEventListener("load", function () {
  setTimeout(function () {
    var foot = document.getElementById("foot-route");
    if (!foot) return;
    foot.textContent = window.__ERRORS.length
      ? "JS ERRORS: " + window.__ERRORS.join(" | ")
      : "no js errors";
  }, 400);
});
