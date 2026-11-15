# Stage 11B Implementation Review: Devices Dashboard Interface

**Status: READY FOR INDEPENDENT REVIEW. Not approved. Not deployed. Stage
11C/11D/11E not begun.**

**Repository:** https://github.com/yossigo88-cyber/kosherguard-platform
**Working branch:** `stage-9b-deployment-preparation`
**Starting SHA (approved):** `fe07b0cd8199167e691a707de9d6284296de5f24`
**Main (verified unchanged before work):** `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`
**Final SHA:** the branch HEAD at this report's commit; the completion
message records it. The last commit touching any code, test, or other
documentation file is `f17cb6ba472954a8c446f5d1dbfed43a56778b0d`. The
fresh-clone verification in section 10 ran on a clone of the final
branch and was verified file-identical to the tested implementation
tree.

Stage 11B replaces the Devices placeholder with a complete device-registry
management interface. It is a frontend-only stage: no backend file,
schema, API contract, authentication, session, or publication behavior
was changed.

## 1. Starting and final SHA

See the header. Branch and starting HEAD were verified before editing
(`git checkout stage-9b-deployment-preparation`; `git log -1` =
`fe07b0cd...`; `git ls-remote origin main` = `5f75d213...`).

## 2. Exact changed files

1. `dashboard/static/app.js` - the Devices list page, Register Device
   modal, `#/devices/<id>` details page (overview/edit, bindings,
   assignment, effective-policy status, state controls, audit history),
   and a router extension that parses `#/devices/<id>`. All other
   routes render through the same `ROUTES` table unchanged.
2. `dashboard/static/styles.css` - Stage 11B styles appended: state
   badge variant, disabled-button states, binding rows, effective-status
   grid, width utility classes, responsive table-to-card rules at
   max-width 900px, and a narrow-phone topbar rule (max-width 480px).
3. `dashboard/tests/test_devices_ui.mjs` (new) - 22 Node `node:test`
   UI tests driving the real `app.js` in a vm with a minimal DOM/fetch
   shim. No external dependencies.
4. `dashboard/tests/test_devices_frontend.py` (new) - 7 pytest checks:
   mandated honest wording present, the UI never sends `identity_class`,
   no token/MDM offers, responsive CSS rules present, index.html shell
   unchanged, `node --check` on app.js, and the Node UI suite (the two
   Node-dependent tests skip explicitly if Node is absent).
5. `dashboard/README.md` - Stage 11B section; honest test counts
   (252 -> 276 pytest tests) and Node UI test instructions.
6. `docs/reviews/STAGE_11B_IMPLEMENTATION_REVIEW.md` (new) - this file.

`dashboard/static/index.html` was NOT modified (no change was genuinely
necessary: the shell, modal host, and script/style links already support
everything). No file under `dashboard/src/`, `filtering-engine/`,
`deploy/`, or any schema/migration was modified.

## 3. Features implemented

- Devices list (`#/devices`): heading and description, the API's honest
  registry note as a banner, Register Device button, debounced search
  (name/description), state filter, responsive table (cards on phones).
  Columns: name + entry-kind badge + description, type/OS, state badge,
  assigned policy (or "Default policy"), binding count and kinds,
  management status, last-seen ("Not tracked - last-seen reporting is a
  future stage"), Open action. Loading, empty (with next-step guidance),
  and error states handled.
- Register Device modal: name (required), description, device type
  (backend's suggested set), OS, notes, optional initial policy
  assignment (picker from `GET /api/policies`), optional initial
  bindings (multiple rows; IPv4 address or IPv6 /64 prefix). Every
  binding area carries the exact mandated label "Network/group
  binding — routing hint only, not verified device identity." plus the
  shared-address explanation. No token registration is offered;
  token_hash is named as reserved. Server validation errors display in
  the modal; success is claimed only after the API confirms (then the
  UI opens the new entry).
- Device details (`#/devices/<id>`): overview (all fields, Edit modal
  via PUT), network bindings (type, canonical value, identity class,
  created date, active/retired status; add and retire-with-confirmation),
  policy assignment (current policy, version at assignment, current
  version, assigned by/at, picker, Assign, Unassign with confirmation,
  assignment history table), effective-policy status card (section 7
  below), state controls (Set active / Set inactive / Disable / Remove,
  each behind a confirmation dialog; removal dialog explains soft
  removal and that no physical device is wiped), and per-device audit
  history. After every successful action the page reloads from the
  server.
- Router: `#/devices/<id>` parsed with the existing hash-router
  architecture; unknown hashes still fall back to Overview; all
  pre-existing routes render identically.

## 4. API endpoints used (all existing Stage 11A contracts, unchanged)

- `GET /api/devices?search=&state=`, `POST /api/devices`
- `GET /api/devices/<id>`, `PUT /api/devices/<id>`
- `POST /api/devices/<id>/state`
- `POST /api/devices/<id>/associations`,
  `DELETE /api/devices/<id>/associations/<aid>`
- `POST /api/devices/<id>/assign-policy` (`{policy_id}` and
  `{policy_id: null}`)
- `GET /api/devices/<id>/effective-policy`, `GET /api/devices/<id>/audit`
- `GET /api/policies` (assignment pickers)

## 5. Screens and workflows

List, registration, details (overview/edit, bindings, assignment,
effective status, state controls, activity). Every workflow exercises
only the endpoints above through the existing `api()` helper, preserving
session and CSRF behavior (`X-KosherGuard-Request` header, same-origin
credentials). Expired sessions keep the existing 401 -> login-view flow.

## 6. Responsive / mobile behavior

Verified with a real headless Chrome (google-chrome, `--headless=new`)
against the real dashboard server on localhost with synthetic test
fixtures only. Page-level horizontal overflow was measured as
`document.scrollingElement.scrollWidth <= window.innerWidth`:

| Screen | 1280px | 390px | 375px | 320px |
| --- | --- | --- | --- | --- |
| Devices list | NO-OVERFLOW | NO-OVERFLOW | NO-OVERFLOW | NO-OVERFLOW |
| Device details | NO-OVERFLOW | NO-OVERFLOW | NO-OVERFLOW | NO-OVERFLOW |
| Register modal | n/a | NO-OVERFLOW | - | - |
| Overview (unrelated) | - | - | NO-OVERFLOW | - |
| Policies (unrelated) | - | - | NO-OVERFLOW | - |
| Publication (unrelated) | - | NO-OVERFLOW | - | - |

Two issues were found by this pixel verification and fixed inside
styles.css only:

1. At 320-375px the pre-existing topbar (username + Sign out) extended
   past the viewport on every page. Fix: at max-width 480px, tighter
   topbar padding/gaps and the username text hidden (Sign out remains;
   the username is still shown on the Settings page). Re-verified:
   unrelated pages render unchanged and NO-OVERFLOW at 375/390.
2. New Stage 11B form controls initially used inline `style=`
   attributes; the server's strict `style-src 'self'` CSP blocks inline
   styles. All Stage 11B controls now use CSS classes (`.w-240`,
   `.w-170`, `.w-150`, `.actions-start`). Remaining CSP console notes
   come from pre-existing inline styles on older pages (e.g. Policies
   search input, Settings cards); they predate Stage 11B, behave as
   before, and are listed here as a known pre-existing limitation, not
   silently changed (fixing them is outside this stage's file scope).

Mobile layout: at max-width 900px, tables become stacked cards; each
cell is labeled from its `data-label` (no horizontal scrolling of the
page; `.table-wrap` keeps `overflow-x: auto` as a fallback).

## 7. Assigned vs published vs enforced honesty

The effective-policy card renders three labeled cells exactly from the
`GET /api/devices/<id>/effective-policy` response:

- **Assigned** - the saved assignment (policy name, version at
  assignment, current version) or "Default policy". When
  `assigned_applies_to_live_queries` is false, a warning badge states
  the entry's state means live queries receive the default policy.
- **Published** - the API returns `published: null` in Stage 11A; the
  UI shows "Unavailable" plus the server's `published_note` verbatim
  ("device assignments are not part of published configuration
  generations until Stage 11D..."). This is a documented API
  limitation, not a backend change.
- **Enforced** - with no connected engine the API returns
  `"unavailable"`; the UI shows "Unavailable" plus the exact mandated
  sentence "Enforcement unavailable — no connected filtering engine has
  confirmed this policy." `stale` and `rejected` render as warning and
  danger badges respectively. The ONLY green path is a server-provided
  enforcement object (revision, generation, confirmed_at), rendered as
  "Confirmed by engine" with its `covers` note. Nothing infers
  enforcement from assignment or publication.

Node tests pin all of these, including "no badge-ok in the enforced
cell when the server reports unavailable/stale".

## 8. Security and escaping checks

- Every server value renders through the existing `escapeHtml`; Node
  tests feed `<img src=x onerror=...>` and `<script>` through device
  fields, list rows, audit entries and assert the escaped form renders.
- The UI never sends `identity_class` (pinned by a pytest check); it
  never offers token credentials, enrollment, or remote actions
  (pinned by a pytest check scanning app.js).
- Consequential actions (retire binding, unassign, every state change,
  remove) require the existing `confirmDialog`; Node tests assert no
  API call happens before confirmation.
- No credentials or secrets are stored anywhere client-side; nothing is
  written to local storage.
- Server errors display as the server's `{"error"}` message text only.
- The 409 tighten-only verdict is displayed verbatim (Node test pins
  the exact server string). No JavaScript policy comparator exists.
- Event handlers attach to freshly rendered nodes per render; the
  router and boot listeners register once. No duplicate handlers
  accumulate when navigating (covered by re-render tests).

## 9. Tests run and exact results

All commands from a working tree of the branch at the implementation
commit (and repeated on the fresh clone in section 10):

- `node --check dashboard/static/app.js` - clean.
- `node --test dashboard/tests/test_devices_ui.mjs` - **22 passed, 0
  failed** (two runs: after implementation, and again after the CSS
  class refactor; both 22/22).
- `cd dashboard && python3 -m pytest tests/test_devices_frontend.py -q`
  - **7 passed**.
- `cd dashboard && python3 -m pytest tests/test_devices.py
  tests/test_device_assignment.py tests/test_policy_mutation_tighten_only.py
  tests/test_devices_frontend.py -q` - **111 passed** (56.80s).
- `cd dashboard && python3 -m pytest tests/ -q --ignore=<the four
  files above>` - **165 passed** (106.01s). Dashboard total: **276
  passed across two invocations**. No existing test was modified.
- `cd filtering-engine && python3 -m pytest tests -q` - **209 passed,
  3 warnings** (57.87s) on rerun.
- `python3 -m py_compile dashboard/src/server.py dashboard/src/store.py
  dashboard/src/db.py dashboard/src/engine_bridge.py
  dashboard/tests/test_devices_frontend.py dashboard/tests/conftest.py`
  - exit 0.

### Failures and reruns (recorded, not hidden)

- Engine suite, first attempt in the working tree: **2 failed, 207
  passed** (56.02s). Captured name: `tests/test_dns_service.py::
  test_root_domain_query_refused` failing with `OSError`. The second
  failure's name was NOT captured (only the tail of that run's output
  was printed before it scrolled; the output was not redirected to a
  file). That is an evidence gap, stated plainly: the second failing
  test name and error are unknown, and no cause is inferred here. The
  immediate rerun passed 209. No engine file was changed in Stage 11B.
  Stage 11A's review (section 9.5) documents prior flaky engine tests
  in this same suite; whether the two failures here are the same tests
  is NOT claimed. This is not a clean-baseline claim.
- The first pixel-verification pass found the topbar overflow and the
  inline-style CSP issue described in section 6; both were fixed and
  re-verified before this report.

## 10. Fresh-clone verification

Completed after every commit above landed. A fresh single-branch clone
of the final branch was verified `diff -r`-identical to the tested
implementation tree (only `.pytest_cache` artifact directories
differed). All suites were re-run on the clone:

- Dashboard pytest: 98 passed + 178 passed = **276 passed** across two
  invocations (split only to fit execution time limits).
- Node UI suite: **22 passed, 0 failed**.
- `python3 -m py_compile dashboard/src/server.py
  dashboard/src/store.py` and `node --check
  dashboard/static/app.js`: clean.
- Engine suite, first run on the clone: **208 passed, 1 error**
  (57.51s): setup of `tests/test_reload.py::
  test_failed_reload_does_not_stop_service` raised `OSError: [Errno
  98] Address already in use` on a TCP socket bind - the same
  intermittent socket-bind failure class seen in the working-tree first
  attempt (section 9). Isolated rerun of `tests/test_reload.py`: **27
  passed**. Across runs, all 209 engine tests pass. No engine file was
  changed in Stage 11B; this is environmental, recorded, and not
  hidden.

## 11. Stage 11A backend files not modified

`git diff fe07b0c..<implementation> -- dashboard/src filtering-engine
deploy` is empty. Verified on the working tree and the fresh clone.

## 12. No deployment, merge, main update, or external access

- No commit touched `main` (verified `git ls-remote origin main` =
  `5f75d213...` before and after).
- No merge, no force-push, no history rewrite; commits are additive on
  `stage-9b-deployment-preparation`.
- No deployment; no Oracle, Render, DNS, or production access; no
  external server was contacted. All UI verification ran against a
  localhost-only test server with a throwaway SQLite database and
  synthetic fixtures; no real device records exist.
- No frameworks, build systems, package managers, or external runtime
  dependencies were introduced (the Node test shim is hand-rolled; the
  UI itself uses the existing vanilla architecture). Nothing was
  purchased.

## Known limitations (documented, not worked around)

- The API does not report per-assignment publication state in Stage
  11A (`published: null`); the UI says "Unavailable" with the server's
  reason instead of inventing data. This is Stage 11D scope.
- `last_seen_at` is never populated in Stage 11A; the UI says "Not
  tracked" and names the future stage (11E).
- Older dashboard pages carry pre-existing inline `style=` attributes
  that the strict CSP does not apply (visual niceties only; unchanged
  behavior, outside this stage's file scope).
