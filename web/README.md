# Embedded management console

`veilink/web.Handler()` serves `/` and `/static/`. All HTML, CSS and JavaScript are embedded with the Go standard library; no frontend build or npm dependency is needed. Mount behind `httpapi.New` to use the real same-origin API. Open `web/templates/index.html` in BrowserPreview for the login layout; without the backend it intentionally reports an API connection/JSON error and never seeds operational data.

## API alignment

- Session/login: `GET /api/session`, `POST /api/login` → `{csrf}`; `POST /api/logout`.
- Mutations send `X-CSRF-Token`; all fetches use `credentials: same-origin` and `cache: no-store`.
- Nodes: list/create/update/delete, separate revoke and enrollment actions. Enrollment tokens are generated only on explicit confirmation, shown in the dialog once, then removed from the DOM on close; never persisted in browser storage.
- Bindings: list/create/delete. Published API has no update endpoint, so the UI explicitly describes delete/recreate rather than pretending to support updates.
- Mappings: list/create/update/delete. Enable/disable uses full mapping `PUT`, followed by reload.
- Audit: `GET /api/audit`, `{at, action, object}` records.
- No server `online` boolean exists. “近期在线” is an explicitly labeled local estimate: non-revoked node whose Unix-second `last_seen` is within the last 90 seconds. Refresh is manual. Clock skew can affect this estimate; configuration revisions and failures are shown independently. No service-reachability or traffic metrics are invented.

## Verification

`go test ./web`, `go vet ./web`, and `node --check web/static/app.js` pass. Handler tests cover embedded assets, content types, HTML security/cache headers, 404, 405 and HEAD.

BrowserPreview was opened on `web/templates/index.html`. Its tool reports opening/live reload but exposes no screenshot, DOM or interactions to this agent. Playwright was not installed in Node or Python and no Chromium/Chrome/Playwright executable was found on PATH. Consequently visual, responsive, keyboard, reduced-motion and real-browser API-flow checks remain **unverified**, not claimed as passed.

Recommended browser acceptance: login; create both node roles; generate/close a token; bind nodes; create/edit/disable/delete a mapping; delete dependencies before nodes; revoke a node; view audit; verify expired session, port conflict and disconnected backend messages. Repeat at 390px width, tab through controls and dialogs, and enable reduced motion. Use real backend data or explicitly labeled test fixtures, never production demo records.
