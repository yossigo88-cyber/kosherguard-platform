# Stage 10 Technical Roadmap - KosherGuard Platform

**Status: audit and planning only. No application code was written, nothing
was deployed, nothing was merged, and `main` is untouched.**

**Repository:** https://github.com/yossigo88-cyber/kosherguard-platform
**Working branch:** `stage-9b-deployment-preparation`
**Starting HEAD (verified live with `git ls-remote` before this audit):**
`35b1e2f5e756e67636ec39c24b35ef057017a444`
**Main (verified live, unchanged):** `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`

Every claim below was checked against the actual source in this repository
at the starting HEAD, not against the READMEs alone.

---

## 1. Executive summary

The platform today has three solid, tested pieces that do not yet form a
product: a working DNS filtering engine (`filtering-engine/`, 119 tests), an
admin dashboard (`dashboard/`, 131 tests) that manages policies in its own
SQLite database, and reviewed-but-never-deployed deployment assets
(`deploy/`, `docs/deployment/`). The critical finding of this audit:

**The dashboard and the filtering engine share CODE, but not DATA.** The
dashboard imports the engine's policy validator and evaluator
(`dashboard/src/engine_bridge.py`) and uses them to validate policy input
and to answer "what would the engine decide?" test queries. But the running
DNS filtering service reads a static policy JSON file and a static category
JSON file once at startup (`filtering-engine/src/dns_service.py`, `--policy`
and `--categories` arguments) and never reloads them. **No policy change
made in the dashboard ever reaches a running filtering engine.** There is
no export, no sync, no reload mechanism anywhere in the repository.

Also missing for the charter product: policy versioning (policies are
updated in place; the audit log records actions but not policy content, so
"what did the policy look like yesterday?" is unanswerable and rollback is
impossible), and any device registry (no devices table exists; the
dashboard's `/api/config` honestly reports `devices_connected: false`).
Everything Apple-MDM remains blocked on the four missing prerequisites
documented in Stage 6 (`docs/MDM_ENROLLMENT_AND_PUSH.md`), all of which are
still missing.

**Recommended Stage 10: close the dashboard-to-engine loop without any
Apple dependency** - policy versioning with history and rollback in the
dashboard, a validated atomic export from dashboard data to engine
configuration, and a fail-safe hot-reload in the DNS service. Every piece
is fully implementable and testable today, locally, for free. Device
registry architecture follows in Stage 11; real MDM work stays blocked on
Apple.

## 2. Current verified architecture

```
                          THIS REPOSITORY TODAY
+-----------------------------+        +-------------------------------+
| dashboard/                  |        | filtering-engine/             |
| stdlib HTTP server (127.0.0.1|        | dns_service.py: UDP+TCP DNS   |
| only, behind Caddy in the   |        | filtering service. At STARTUP |
| deployment plan)            |        | loads --policy FILE and       |
|  - session auth (cookies,   |        | --categories FILE, builds one |
|    lockout, 12-char min)    |        | PolicyEngine + CategoryDB and |
|  - SQLite (WAL): admins,    |        | never reloads them.           |
|    sessions, categories,    |        | policy_engine.py: validation  |
|    domains, policies, audit |        | + precedence (explicit allow, |
|  - CRUD APIs + import +     |        | explicit block, category      |
|    /api/policies/<id>/test  |        | block, category allow,        |
|    (in-process evaluation)  |        | default); subdomain matching. |
+--------------+--------------+        | category_db.py: JSON dataset  |
               |                       | + validated JSONL import CLI. |
               | imports as CODE only  +-------------------------------+
               v (engine_bridge.py: validate_policy, PolicyEngine,
                 validate_domain/validate_category, CategoryDB.merge_records)
               DASHBOARD DATA NEVER FLOWS TO A RUNNING ENGINE
```

Deployment assets (`deploy/`, `docs/deployment/`): runbook, pre-launch
checklist, Caddy reverse-proxy example, hardened systemd unit (UMask=0077,
StateDirectoryMode=0700), and hardened backup/restore scripts
(failure-safe atomic publication, collision-safe concurrent backups,
guarded restore). Verified by tests; never run on a live server.

## 3. Complete feature inventory with statuses

| Feature | Status | Evidence |
| --- | --- | --- |
| Policy evaluation engine (precedence, subdomain matching, startup validation) | IMPLEMENTED, tested | `filtering-engine/src/policy_engine.py`; engine tests |
| Category database (JSON store, validated JSONL import) | IMPLEMENTED, tested | `filtering-engine/src/category_db.py` |
| DNS filtering service (UDP+TCP, sinkhole blocks, upstream forwarding, EDNS caps, structured decision logs, worker pool, request bounds) | IMPLEMENTED, tested locally; never deployed | `filtering-engine/src/dns_service.py`; engine tests |
| Engine policy/category hot reload | **DOES NOT EXIST** | `dns_service.py` lines ~744-775: config loaded once in `main()` |
| Dashboard auth (sessions, lockout, password rules, audit) | IMPLEMENTED, tested | `dashboard/src/auth.py`, `server.py` |
| Dashboard hardening (connection bounds, header/body timeouts, total request deadline, CSRF header, body limits, cookie deployment guard) | IMPLEMENTED, tested | `dashboard/src/server.py`; Stage 9A work |
| Dashboard CRUD: categories, domains, policies | IMPLEMENTED, tested | `dashboard/src/store.py` (673 lines), `server.py` routes |
| Domain import via engine's own importer | IMPLEMENTED, tested | `store.py import_domains` uses `CategoryDB.merge_records` |
| In-dashboard policy test query (real engine decision) | IMPLEMENTED, tested | `store.py test_domain`, `/api/policies/<id>/test` |
| Audit log of admin actions | IMPLEMENTED (actions only, NO content snapshots) | `audit_log` table, `store.py audit/list_audit` |
| Policy versioning / history / rollback | **DOES NOT EXIST** | policies updated in place (`update_policy`); no snapshot anywhere |
| Dashboard-to-engine data path (export/sync) | **DOES NOT EXIST** | no writer of engine config anywhere in `dashboard/` |
| Browser interface (static, vanilla JS) | IMPLEMENTED | `dashboard/static/` |
| Deployment assets (runbook, checklist, Caddy, systemd, backup/restore) | PREPARED, reviewed, NOT live-tested | `deploy/`, `docs/deployment/` |
| Actual deployment / hosting | **DOES NOT EXIST** | nothing is deployed; no hosting account |
| Device registry / device identity | **DOES NOT EXIST** | no devices table; `/api/config` reports `devices_connected: false` |
| MDM server, enrollment, APNs push, command queue, device responses | **DOES NOT EXIST, BLOCKED** | Stage 6 document; 4/4 prerequisites missing |
| App restrictions, push-triggered updates, recovery after reset | **DOES NOT EXIST, BLOCKED** | charter components 4, 6, 7; all MDM-dependent |

## 4. Dashboard-to-engine integration findings

What exists (genuine, verified):

1. `dashboard/src/engine_bridge.py` puts `filtering-engine/src` on
   `sys.path` and re-exports the engine's validators and `PolicyEngine`,
   so the dashboard and engine can never disagree about what a valid
   domain, category, or policy structure is.
2. Every policy created or edited in the dashboard is validated through
   the engine's real `validate_policy()` (`store.py _validate_policy_payload`).
3. `/api/policies/<id>/test` evaluates a domain with the real
   `PolicyEngine` against dashboard data (`store.py test_domain`).

What does NOT exist (the gap):

1. **No export.** Nothing in `dashboard/` produces the two files the
   engine consumes (`policy JSON`, `categories JSON`). The engine's input
   files and the dashboard's database are unrelated datastores.
2. **No reload.** `dns_service.py` loads both files once in `main()`
   (lines ~744-775). No SIGHUP handler, no file watching, no API. A
   policy change requires a process restart even if the files change.
3. **No publication concept.** The dashboard has `policies.enabled`, but
   nothing defines which policy is THE active one for the engine, and no
   device/policy assignment exists (no devices at all).
4. Consequence: an operator can manage policies in the dashboard forever
   and the filtering service will enforce the startup files unchanged.
   The two halves of the platform are connected by code reuse only.

## 5. MDM prerequisite and dependency matrix

From Stage 6 (`docs/MDM_ENROLLMENT_AND_PUSH.md`), re-confirmed unchanged:

| # | Prerequisite | Status today | Gates |
| --- | --- | --- | --- |
| 1 | Apple MDM vendor selection + Vendor CSR Signing Certificate | NOT OBTAINED (never requested; needs a paid Developer Program account - an explicit owner decision) | APNs push certificate, any customer-facing MDM |
| 2 | APNs push certificate + private key | NOT AVAILABLE (flows from #1) | push-triggered updates |
| 3 | Apple Business organization (ADE) | NOT AVAILABLE ("Not Qualified" + account conflict, unresolved with Apple Support) | supervised enrollment, non-removable management |
| 4 | Approved test iPhone | NOT CONFIRMED | any real-device testing |

Dependency matrix (what each charter component needs):

| Charter component | Buildable/testable WITHOUT Apple prerequisites? | Blocks on |
| --- | --- | --- |
| Central server (policy/device state, APIs) | YES - entirely | nothing |
| Admin dashboard | YES - exists today | nothing |
| Website/category filtering ENGINE | YES - exists today | nothing |
| Dashboard-to-engine delivery loop | YES - this is the Stage 10 recommendation | nothing |
| Device registry + identity DATA architecture | YES, as data + API design, honestly labeled unmanaged | nothing (but no real device function) |
| Device enrollment | NO | prerequisites 1, 3, 4 + public HTTPS hosting |
| App restrictions | NO (supervised-only MDM payloads) | prerequisites 1, 3, 4 |
| Push-triggered policy updates | NO | prerequisites 1, 2, 4 |
| Recovery after device reset | NO (it IS re-enrollment via ADE) | prerequisites 1, 3, 4 |

No fake MDM functionality may be built: nothing may claim a device is
enrolled, managed, or receiving remote updates when it is not.

## 6. Technical problems and risks discovered

1. **The integration gap itself (highest risk):** the platform's two
   halves are disconnected at runtime. Any demo that "manages filtering
   from the dashboard" today would be theater unless the engine is
   restarted with hand-written files. Stage 10 must close this.
2. **No policy versioning:** `update_policy` overwrites rules in place.
   A bad edit is unrecoverable, and the audit log cannot answer "what
   changed" - it stores action strings, not policy content. For a
   filtering product, an accidentally widened allow is a safety incident
   with no rollback path.
3. **Engine restart requirement:** without reload support, policy
   publication means restarting the DNS service - a filtering gap window
   and an operational hazard. A restart-with-bad-config also kills
   filtering entirely unless validation happens BEFORE the swap.
4. **Category data is a toy:** the engine ships a small TEST dataset
   (`data/categories.test.json`, honestly labeled) and the dashboard's
   categories are labels with manually entered domains. Real coverage
   needs a licensed dataset or sustained curation; this is a content
   problem, not a code problem, and it must never be papered over.
5. **Single-admin model with no password recovery** (documented
   limitation): acceptable now, risky for any real deployment.
6. **Deployment assets unproven:** the unit, Caddy config, and backup
   schedule have never run on a live server; first deployment is its own
   verified step (pre-launch checklist), not an assumption.
7. **Engine suite has a known timing flake**
   (`test_truncated_udp_upstream_large_answer_complete_over_tcp_downstream`,
   one failure in a full run, passing in isolation and on reruns). Not a
   blocker; must stay honestly reported.
8. **Apple risk is binary and outside our control:** vendor selection may
   never be granted (A10: Apple selects at its discretion and can revoke
   at any time). The architecture must keep delivering value with zero
   Apple capability - which the Stage 10/11 plan does.

## 7. Recommended Stage 10 scope

**Stage 10: "Policy control plane - versioned policies and a live,
fail-safe dashboard-to-engine delivery loop."** No Apple dependency, no
deployment dependency, fully testable locally.

1. **Policy versioning in the dashboard.** Every create/update/
   enable/disable/delete writes an immutable `policy_versions` snapshot
   row (full normalized engine-format content, version number, admin,
   timestamp, optional note). New API: list versions, view a version,
   roll back (creates a NEW version copying the old content). Audit
   entries gain the version number. Existing rows migrate to version 1.
2. **Engine configuration export.** A dashboard-side exporter that turns
   the designated active policy plus the dashboard's domains/categories
   into the engine's exact two JSON documents, validated through
   `engine_bridge` (`validate_policy`, `CategoryDB`), written atomically
   (temp file + rename, 0600/0700, matching the Stage 9B patterns) to a
   configured output directory. Available as both an API action
   (audited) and a CLI for the systemd unit's deployment shape.
3. **Fail-safe hot reload in `dns_service`.** SIGHUP (and/or a
   `--watch` poll interval) re-reads and fully validates both files and
   atomically swaps the live `PolicyEngine`/`CategoryDB`. An invalid new
   file is rejected loudly and the engine keeps serving the last good
   configuration - a bad publication can never take filtering down.
4. **End-to-end proof:** an automated test that changes a policy through
   the dashboard API, exports, reloads a real running DNS service, and
   verifies real DNS answers change - then rolls back and verifies the
   answers change back. This is the first test in the repository where
   dashboard data actually filters DNS traffic.

## 8. Proposed later stages, in order

- **Stage 11 - Device registry and per-device policy architecture (no
  MDM).** `devices` table (name, stable server-assigned identity,
  assigned policy, honest `management_status: unmanaged`), registry API
  + UI, and per-client policy selection in the DNS service keyed on
  client address (the only device signal available without MDM), with
  tests. Explicitly no enrollment, no push, no claims of management -
  this builds the data model the MDM layer will later populate.
- **Stage 12 - First real deployment (owner decision: hosting).** Run
  the checklist on a real server: dashboard behind Caddy, engine
  published by the Stage 10 loop, backups scheduled and copied off-site,
  restore drill. This validates every Stage 9B asset in the real world.
- **Stage 13 - Apple prerequisites campaign (owner decisions + money).**
  Apple Developer Program enrollment, MDM vendor selection request,
  Apple Business support case, test-device designation. Document Apple's
  answers either way.
- **Stage 14+ - MDM implementation, strictly after prerequisites.**
  Enrollment endpoint + ACME/SCEP identity, check-in/command protocol
  with per-device queues and recorded responses, APNs push client,
  restrictions/app payloads, recovery flow - exactly the Stage 6 target
  architecture, populating the Stage 11 registry. Each sub-step ships
  only when it can be tested against the real test device.

## 9. Exact files likely to change in Stage 10

- `dashboard/src/db.py` - `policy_versions` table + migration of existing
  policies to version 1.
- `dashboard/src/store.py` - snapshot writes in every policy mutation;
  version list/get/rollback operations; the exporter
  (`export_engine_config`) building and validating the two JSON
  documents.
- `dashboard/src/server.py` - new routes:
  `GET /api/policies/<id>/versions`,
  `GET /api/policies/<id>/versions/<n>`,
  `POST /api/policies/<id>/rollback`,
  `POST /api/export` (audited).
- `dashboard/static/app.js` (+ possibly `index.html`, `styles.css`) -
  versions/history view, rollback button, export/publish action.
- `dashboard/src/engine_bridge.py` - likely unchanged (it already exports
  everything needed); touched only if the exporter needs one more
  re-export.
- `filtering-engine/src/dns_service.py` - reload on SIGHUP (and/or
  `--watch` interval), validation-first atomic swap, clear logging of
  accepted/rejected configurations.
- `filtering-engine/tests/test_dns_service.py` (or a new
  `test_reload.py`) - reload behavior incl. rejecting invalid config and
  keeping the last good one.
- `dashboard/tests/` - new test module(s): versioning/rollback,
  exporter correctness against the engine's own validators, and the
  end-to-end dashboard -> export -> reload -> DNS-answer-change test.
- `deploy/kosherguard-dashboard.service` + `docs/deployment/RUNBOOK.md` -
  export output directory, reload signal wiring, engine service unit (a
  second unit may appear: `deploy/kosherguard-engine.service`).
- `README.md`, `dashboard/README.md`, `filtering-engine/README.md` -
  accurate scope and test counts, as every stage requires.

## 10. Acceptance criteria and automated tests required

Stage 10 is done only when ALL of these hold:

1. Every policy mutation creates an immutable version snapshot; rollback
   produces a new version with the exact prior content (tests: create,
   edit, disable, roll back, verify content and audit entries).
2. The exporter's output passes the engine's own `validate_policy()` and
   `CategoryDB.load()` - proven by loading the exported files with the
   real engine code in a test.
3. Export writes are atomic (temp + rename) with 0600 files in a 0700
   directory, verified by tests like the Stage 9B permission tests.
4. `dns_service` accepts a reload signal, swaps config without dropping
   in-flight queries, rejects an invalid new config loudly, and keeps
   serving the last good one (tests with real UDP/TCP queries before,
   during, and after reloads - good and bad).
5. End-to-end test: policy change via dashboard API -> export -> reload
   -> real DNS responses reflect the new policy; rollback -> responses
   revert. No sleeps for synchronization (bounded polling on the DNS
   answer itself, per the project's testing rules).
6. Full dashboard suite, full engine suite, and `bash -n` all pass on
   the development tree and on a fresh anonymous clone; counts in the
   READMEs match reality; per-run results reported honestly (including
   any flake).

## 11. Explicitly out of scope until Apple prerequisites exist

- Device enrollment of any kind (profile serving, ADE, Configurator
  flows).
- APNs push integration and push-triggered updates.
- MDM check-in/command protocol, command queues, device response
  recording against real devices.
- App restrictions and any supervised-only payload.
- Recovery-after-reset flows (they ARE re-enrollment).
- Any claim that a device is enrolled, managed, or receiving remote
  updates. The Stage 11 registry stores device RECORDS with an honest
  `unmanaged` status only.
- Purchasing anything (Apple Developer Program, hosting) without an
  explicit owner decision.

## 12. What counts as a functioning KosherGuard product

Realistic, staged definition:

1. **After Stage 10:** an operator edits filtering policy in the
   dashboard; every change is versioned, audited, and reversible; the
   running DNS filtering service enforces the published policy within
   seconds, without restart, and can never be taken down by a bad
   publication. Any device (or test client) pointing its DNS at the
   service is filtered by current dashboard state. This is a REAL,
   demonstrable filtering control plane - no Apple anything.
2. **After Stage 11 + 12:** per-device policy assignment (by client
   identity available without MDM), a deployed instance with verified
   backups, and a registry ready to receive real device identities.
3. **Full charter product (requires Apple):** devices enrolled with
   trusted identities through the documented flow, policies pushed via
   APNs and confirmed by recorded device responses, supported app
   restrictions, and recovery after reset. This remains gated on the
   four prerequisites in section 5, and nothing before it will pretend
   otherwise.

---

*Prepared as the Stage 10 planning deliverable. No Stage 10
implementation has begun; it waits for independent review and approval
of this roadmap.*
