# Private agent artifacts

The fixed loader installs a same-origin service worker which applies a native
Connection-Allowlist to its controlled page. After a browser behavior check,
it runs single-file HTML apps in an opaque child for the private agent page at
private-agent.dstack.soc1024.com. Chromium 152 or newer is required.

Run with `deno run --allow-net server.ts 8789`. The loader is `/loader.html`.
