#!/usr/bin/env python3
"""inject.py <page.html> <out.html> <stub.js>...  — build a frame-able copy of the app.

The page under test talks to a live box. A frame has to be offline and byte-identical run
to run, so this writes a copy of the page beside the original (relative URLs to app.css and
app.js therefore resolve exactly as in production) with, inserted immediately after <head>
and therefore before the page's own deferred script:

  * a freeze stylesheet — every animation and transition off, caret hidden. Without it the
    entry animations and the caret blink land in a different phase on every run and no two
    PNGs match.
  * the theme choice, when THEME=dark|light is set. The app's dark tokens are also reachable
    through prefers-color-scheme, but headless Chrome always prefers light, so an explicit
    data-theme is the only way to photograph the dark scheme.
  * each stub script in the order given: the shared fetch stub library, then the one file
    that describes the state being photographed.
"""

import os
import pathlib
import re
import sys

FREEZE = """<style>
*, *::before, *::after {
  animation: none !important;
  transition: none !important;
  caret-color: transparent !important;
}
</style>"""

page = pathlib.Path(sys.argv[1])
out = pathlib.Path(sys.argv[2])
stubs = [pathlib.Path(p) for p in sys.argv[3:]]

theme = os.environ.get("THEME", "").strip()
head = [FREEZE]
if theme in ("dark", "light"):
    head.append(
        "<script>document.documentElement.setAttribute('data-theme','%s');</script>" % theme
    )
for stub in stubs:
    head.append("<script>\n" + stub.read_text(encoding="utf-8") + "\n</script>")

html = page.read_text(encoding="utf-8")
match = re.search(r"<head[^>]*>", html, re.I)
block = "\n".join(head)
if match:
    html = html[: match.end()] + "\n" + block + html[match.end():]
else:
    html = block + "\n" + html
out.write_text(html, encoding="utf-8")
print("injected %s -> %s" % (", ".join(s.name for s in stubs), out))
