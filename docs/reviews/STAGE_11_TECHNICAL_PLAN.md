# Stage 11 Technical Plan: Device Registry and Per-Device Policies

**Status: planning only. No application code was written, nothing was
deployed, no database or server was modified, nothing was merged, and
`main` is untouched. This document waits for independent review and
explicit approval before any Stage 11 implementation begins.**

**Repository:** https://github.com/yossigo88-cyber/kosherguard-platform
**Working branch:** `stage-9b-deployment-preparation`
**Branch HEAD at inspection:** `7c42dc31dbd041afc31b45b0292c6fd068543b55`
(verified 2026-11-15 by reading the branch tree through the GitHub API;
every file reference below was read at that commit)
**Main (unchanged):** `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`

This plan follows the Stage 10 Technical Roadmap
(`docs/reviews/STAGE_10_TECHNICAL_ROADMAP.md`, section 8), which already
reserved Stage 11 for "device registry and per-device policy architecture
(no MDM)". It also preserves the Stage 6 constraint
(`docs/MDM_ENROLLMENT_AND_PUSH.md`): all four Apple MDM prerequisites are
still missing, so nothing here may claim enrollment, management, push, or
control of any real device.

---

## 1. Existing architecture findings (verified against actual source)

### 1.1 What exists today

**Filtering engine (`filtering-engine/`)**

- `src/policy_engine.py`: a single `PolicyEngine` built from one policy
  JSON document. Rule precedence (highest first): explicit allowlist,
  explicit blocklist, category block, category allow, default policy.
  Subdomain matching (`domain_matches`). `validate_policy()` rejects any
  malformed rule at load time; a malformed rule is never silently
  ignored. Policies are pure data.
- `src/category_db.py`: category database (domain -> category set),
  validated JSON import (`merge_records`).
- `src/dns_service.py`: UDP + TCP DNS service. One engine instance
  serves **all** clients identically. Key facts for Stage 11:
  - `handle_packet(data, downstream_udp=False)` receives **no client
    identity**. The client address exists only in the socket loops
    (`_serve` for UDP receives `(data, client)`; TCP workers hold the
    connection) and is deliberately discarded: the decision log never
    records client IPs ("Privacy by design" in the module docstring).
  - Stage 10 hot reload: `reload_from_paths()` builds a complete
    replacement engine from `current/policy.json` +
    `current/categories.json`, validates it with the engine's own
    validators, verifies the generation manifest's content hashes, and
    only then swaps one immutable `self.engine` reference. A rejected
    configuration never becomes active; the last good one keeps
    serving. Reload triggers: SIGHUP or the `--watch` poll.
  - `--status-file` writes `engine-status.json` (paths, hashes,
    generation, reload count, last error) after every load attempt.
- `tests/`: 146 tests passing as of the Stage 10.5 review run.

**Dashboard (`dashboard/`)**

- `src/server.py`: stdlib `ThreadingHTTPServer`. Every `/api/*` route
  except `POST /api/login` and `GET /api/health` requires a valid
  session (`_admin(conn)`); every state-changing request requires the
  `X-KosherGuard-Request` header (CSRF defense together with the
  SameSite=Strict session cookie). Body size caps, request deadlines,
  strict CSP, no stack traces to clients.
- `src/auth.py`: PBKDF2-HMAC-SHA256 password hashing (200k iterations),
  server-side session rows (12 h lifetime), in-memory login limiter
  (5 failures -> 60 s lockout).
- `src/db.py`: SQLite (WAL, foreign keys ON). Tables: `admins`,
  `sessions`, `categories`, `domains`, `domain_categories`, `policies`,
  `policy_domains`, `policy_categories`, `audit_log`, and the Stage 10
  additions `policy_versions` (immutable append-only snapshots),
  `publication_state` (single row: `selected_policy_id`,
  `active_revision`), `config_revisions` (immutable per-publication
  snapshots with content hashes). Migrations run idempotently in
  `init_db()`.
- `src/store.py`: all writes go through `Store` with engine-side
  validation (`engine_bridge.py` re-exports the engine's own
  validators). Selected-for-publication invariant: a policy that is
  selected for publication cannot be disabled or deleted; every such
  check runs inside a `BEGIN IMMEDIATE` write transaction
  (`_write_txn`) so check and mutation are atomic. **No devices table
  exists.** `overview_counts()` returns the hardcoded honest value
  `"devices": 0`.
- `src/publishing.py`: generation-based publication. One publication
  generation = `policy.json` (the single selected policy) +
  `categories.json` + `manifest.json` (revision, SHA-256 hashes),
  written atomically, re-verified from disk, activated by an atomic
  `current` symlink swap, serialized by flock. 0700 directories, 0600
  files.
- `src/engine_bridge.py`: puts `filtering-engine/src` on `sys.path` and
  re-exports the engine's validators and `PolicyEngine`. The dashboard
  never ships its own policy logic.
- `static/app.js` + `index.html`: vanilla-JS hash router with a
  sidebar. A `devices` route **already exists as an honest
  placeholder** ("No devices are connected..."), and an `applications`
  route similarly reserves future MDM capability. The Devices section
  in the sidebar is therefore not new navigation; Stage 11 replaces the
  placeholder content.
- `/api/config` honestly reports `devices_connected: false,
  mdm_operational: false`.
- `tests/`: 165 tests passing as of the Stage 10.5 review run.

**Deployment state (from `docs/reviews/STAGE_10_5_STAGING_REVIEW.md`)**

- Oracle staging (https://129-158-203-53.sslip.io/) runs the
  **dashboard only**. No DNS engine process runs there; nothing proves
  or implies dashboard-to-engine connectivity in staging. Publication
  (`KG_PUBLISH_DIR`) is not configured on that deployment.
- The duplicate Render service `srv-dbsv0smi0phs73e7qpb0` is SUSPENDED
  (not deleted), so branch commits currently trigger no deploys
  anywhere; Oracle has no automatic deployment by design.
- The original paid KosherGuard site, server, and DNS are separate and
  untouched.

### 1.2 The gap Stage 11 closes

Today one published policy applies to every DNS client identically.
There is no device record, no device identity, and no way to give two
clients different filtering. The charter's per-device control
(`docs/PROJECT_CHARTER.md`, components 1-2) needs: a registry of
devices, a reliable identity signal, per-device policy assignment, and
an engine that resolves "which device is asking" before "what does the
policy say".

### 1.3 Constraints inherited from earlier stages

1. No fake MDM: device records must carry an honest management status;
   nothing may claim a device is enrolled, managed, or receiving remote
   updates (Stage 10 roadmap, section 11).
2. Preserve Stage 10's versioning and publication safeguards exactly:
   immutable policy versions, generation publication, fail-safe reload.
   Stage 11 extends that pipeline; it must not create a second,
   conflicting policy system.
3. The engine's privacy-by-design decision logging (no client IPs in
   logs) stays the default; any last-seen feature must be designed to
   honor it (section 7.5).
4. Validation stays single-sourced: dashboard and engine keep sharing
   the engine's own validators through `engine_bridge.py`.

---

## 2. Device registry design

### 2.1 Registry concepts

A **device** is a durable administrative record. It is never identified
by its current IP address. Each device gets a server-assigned integer
ID (SQLite autoincrement, never reused) and a human-chosen unique name.
All mutable network facts (current IPv4, IPv6 prefix, future MAC or
token) live in a separate **identifier** table so they can change,
accumulate history, and be retired without touching the device record.

States (`devices.state`, CHECK constraint):

| State | Meaning | Engine effect |
| --- | --- | --- |
| `active` | In normal use | Assignment (if any) applies to matching identifiers |
| `inactive` | Temporarily out of use (e.g. device away) | Treated like no assignment: fallback policy applies |
| `disabled` | Administratively turned off | Fallback policy applies; identifiers kept for audit |
| `removed` | Soft-deleted | Identifiers retired, assignment history kept, record never hard-deleted in Stage 11 |

Removal is always soft: `state = 'removed'`, all identifiers retired
(`retired_at` set), active assignment deactivated. Reactivation moves a
`removed` or `disabled` device back to `active` with a fresh audit
entry; identifiers are re-added explicitly, never silently resurrected,
so a new physical device that inherits an old IP cannot accidentally
inherit the old device's policy.

### 2.2 Fields

`devices`: `id`, `name` (unique, 1-80 chars, no control characters -
same `_check_text` rules as policies), `description`, `device_type`
(free text from a suggested set: `iphone`, `ipad`, `android`, `mac`,
`windows`, `linux`, `router`, `other`), `os` (free text, e.g.
`iOS 18.1`), `state`, `management_status` (always `unmanaged` in Stage
11 - honest labeling required by Stage 6), `created_at`,
`registered_at`, `updated_at`, `last_seen_at` (nullable; see 7.5),
`notes` (admin-only free text, max 1000 chars).

### 2.3 Audit history

Every registry mutation writes to the existing `audit_log` table with
actions `device.create`, `device.update`, `device.state`,
`device.identifier.add`, `device.identifier.retire`,
`device.policy.assign`, `device.policy.unassign`, each with a detail
string naming the device and the change (never any credential). The
per-device history view is a filtered read of `audit_log` plus the
assignment-history table (4.3).

---

## 3. Device identification: investigation and recommendation

The question: when a DNS query arrives, how does the engine know which
registry device sent it?

### 3.1 What signal the current system actually has

The KosherGuard engine is a DNS service. Clients reach it over UDP/TCP
port 53 (or DoH/DoT in the future). In the current code
(`dns_service.py`), the only per-query signal that exists at all is the
**source IP address** at the socket layer; it is deliberately not used
or logged today. Everything else (MAC, hostname, device certificate)
either never reaches a DNS server or does not exist yet.

### 3.2 Evaluation of the candidate methods

| Method | Available now? | Reliability | Verdict |
| --- | --- | --- | --- |
| Static IPv4 | Yes, where the network assigns one | High while the assignment holds; meaningless if it changes | **Primary signal for Stage 11**, administrator-maintained |
| DHCP address changes | n/a (a failure mode, not a method) | An IP-based mapping silently breaks or, worse, transfers a policy to a different device | Mitigate: recommend router DHCP reservations (owner-side, outside this repo); surface `last_seen` staleness; identifier history makes the change auditable |
| IPv6 addresses / privacy addresses | Yes, if the network uses IPv6 | Stable prefix (`/64`) usually identifies one device's network segment; privacy extension addresses rotate inside it | **Supported at `/64` granularity**, documented as segment-level, not exact-device |
| MAC addresses | **No** | Invisible beyond the local link: a DNS packet carries no MAC. iOS also randomizes per-network MACs | **Rejected** for a DNS-based engine; recorded for completeness |
| Device credentials / tokens | Not in the current plain-DNS service | Strong when it exists (per-device DoH/DoT path or query-name token, e.g. `abcd123.dns.kosherguard...`) | **Reserved for a future stage**: needs a public DoH/DoT endpoint and per-device secrets; real design sketched in 7.6 |
| MDM-based identity (UDID, identity certificate) | **No** - all 4 Apple prerequisites missing (Stage 6) | Strongest: device-bound certificate, survives IP changes | **Reserved for the MDM stage**; registry schema already carries the hook (9) |

### 3.3 Recommendation

**Stage 11 identifies devices by administrator-maintained source-IP
mappings (IPv4 exact addresses, IPv6 /64 prefixes) attached to stable
server-assigned device IDs.** This is the only identification method
the current filtering engine can actually observe, it requires no Apple
capability, no new network service, and no device-side software.

It must be documented honestly, in the UI and the README, as
**best-effort and not a security boundary**: it depends on the local
network's address assignment discipline, it cannot survive a DHCP
change by itself, and a device on a mapped address gets that address's
policy. The registry's identifier history, staleness surfacing, and
explicit re-verification workflow make that limitation visible instead
of silent. Token-based (DoH/DoT) and MDM-based identity are the
designed-for upgrades, in that order.

---

## 4. Per-device policy assignment design

### 4.1 Model

- One device has **at most one active assignment** at a time
  (enforced by a partial unique index, section 6).
- Different devices may hold different policies; any number of devices
  may share one policy.
- A device with no active assignment, or in `inactive`/`disabled`/
  `removed` state, is served by the **default policy** - the policy
  already selected for publication in Stage 10's `publication_state`.
  This preserves today's behavior exactly for every client until an
  administrator assigns otherwise (safe fallback, owner to confirm in
  12.1).
- Reassigning = deactivate the current assignment row, insert a new
  one, in the same `BEGIN IMMEDIATE` transaction that verifies the
  target policy exists and is enabled. The assignment records the
  policy's **current version number at assignment time** for display
  ("device X runs policy Y, assigned at v7"); enforcement always uses
  the latest published version, so policy rollback and edits flow to
  every assigned device through the unchanged Stage 10 machinery.

### 4.2 Interaction with Stage 10 safeguards (no second policy system)

- The Stage 10 `publication_state.selected_policy_id` keeps its exact
  meaning: the **default** policy. Stage 11 adds per-device overrides
  on top; it does not replace or duplicate the selection pointer.
- The selected-for-publication invariant is extended, not duplicated:
  a policy cannot be disabled or deleted while it is selected for
  publication **or referenced by any active assignment**. Both checks
  run under the same `_write_txn` write lock.
- Policy versioning is unchanged: every policy mutation snapshots an
  immutable version. Assignments reference policies by ID and display
  the version recorded at assignment; rollback of a policy is
  independent of which devices use it.
- Publication remains one explicit, audited action producing one
  immutable `config_revisions` row - now covering a multi-document
  generation (section 7).

### 4.3 Assignment history

`device_policy_assignments` rows are never updated in place except for
the `active` flag flip; they are never deleted while the device exists.
This gives per-device policy history (which policy, which version at
assignment, by whom, when, until when) without touching the policy's
own version history.

### 4.4 Disable / re-enable a device

`device.state = 'disabled'` immediately excludes the device's
assignment from the next published generation (identifiers stay
attached for audit). Re-enabling restores it. Nothing is published
implicitly: like every Stage 10 change, an assignment or state change
becomes effective only after an explicit publish, and the dashboard's
existing `unpublished_changes` indicator covers it (7.3).

---

## 5. Dashboard experience plan

The current UI is a vanilla-JS hash-router SPA (`static/app.js`,
routes in the `ROUTES` object; sidebar links with `data-route`). A
`devices` route already exists as a placeholder. Stage 11 replaces it
and adds detail routes, reusing existing patterns: `api()` helper,
`escapeHtml`, `confirmDialog`, `#modal`, debounced search inputs.

1. **Sidebar**: "Devices" entry already present; no navigation change.
2. **Device list** (`#/devices`): table with name, type/OS, state
   badge (active/inactive/disabled/removed), assigned policy name (or
   "Default policy"), last seen (or "never observed"), search box
   (name/description) and state filter - the same search/filter shape
   as the existing Policies and Domains pages. "Register device"
   button.
3. **Register workflow**: modal or sub-page collecting name
   (required), description, device type, OS, initial identifiers
   (optional; validated by kind), and optional initial policy
   assignment. Validation errors shown in place, as on existing forms.
4. **Device details page** (`#/devices/<id>`): all fields; identifiers
   list with add/retire actions; current effective policy card
   (assigned policy name + version at assignment, or "Default policy");
   assignment interface (policy picker populated from
   `GET /api/policies`, with the test-query link to the existing
   `/api/policies/<id>/test` flow); state actions
   (disable/re-enable/remove) behind `confirmDialog`; audit history
   (per-device filtered entries).
5. **Edit workflow**: name/description/type/OS/notes edits on the
   details page.
6. **Status indicators**: state badges; an "unpublished changes" hint
   consistent with the Publication page when assignments changed since
   the last publish; a staleness hint when `last_seen_at` is old for
   an `active` device (possible sign of a DHCP change).
7. **Honesty**: the page header keeps the existing honest note that no
   MDM enrollment exists and `management_status` is `unmanaged` for
   every device.

---

## 6. Database schema and security

New tables (Stage 11 migration, idempotent in `init_db()`, same style
as `SCHEMA_STAGE10`):

```sql
CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  device_type TEXT NOT NULL DEFAULT 'other',
  os TEXT NOT NULL DEFAULT '',
  state TEXT NOT NULL DEFAULT 'active'
    CHECK (state IN ('active','inactive','disabled','removed')),
  management_status TEXT NOT NULL DEFAULT 'unmanaged'
    CHECK (management_status IN ('unmanaged','enrolled')),
  notes TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  registered_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS device_identifiers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL REFERENCES devices(id),
  kind TEXT NOT NULL CHECK (kind IN ('ipv4','ipv6_prefix','mac','token_hash')),
  value TEXT NOT NULL,
  created_at TEXT NOT NULL,
  retired_at TEXT
);
-- One live identifier value maps to at most one device (anti-impersonation).
CREATE UNIQUE INDEX IF NOT EXISTS uq_live_identifier
  ON device_identifiers (kind, value) WHERE retired_at IS NULL;

CREATE TABLE IF NOT EXISTS device_policy_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL REFERENCES devices(id),
  policy_id INTEGER NOT NULL REFERENCES policies(id),
  policy_version_at_assignment INTEGER NOT NULL,
  assigned_by TEXT NOT NULL,
  assigned_at TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
-- At most one active assignment per device.
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_assignment
  ON device_policy_assignments (device_id) WHERE active = 1;
```

Security properties:

- **Unique constraints**: device names unique; one live identifier
  value belongs to one device (partial unique index); one active
  assignment per device (partial unique index). SQLite enforces these
  even under concurrency, backed by the same `BEGIN IMMEDIATE` write
  transactions Stage 10 uses.
- **Foreign keys**: identifiers and assignments reference `devices` and
  `policies`; `PRAGMA foreign_keys = ON` is already set. Deletion is
  soft (state), so no cascading delete of history.
- **Transactional assignment**: reassignment checks policy existence +
  enabled state and swaps rows inside one `_write_txn`.
- **Authorization**: every `/api/devices*` route goes through the
  existing `self._admin(conn)` session check; there is no
  unauthenticated device endpoint, and `GET /api/health` stays minimal.
- **CSRF**: every mutation keeps requiring `X-KosherGuard-Request: 1`
  (existing `_require_csrf_header`), unchanged.
- **Audit logging**: every mutation audited (2.3); audit details never
  contain credentials.
- **Impersonation protection**: the live-identifier uniqueness index
  prevents two devices from claiming the same address at once; retiring
  is explicit; identifier history makes a stolen mapping visible. The
  plan does not pretend IP identity is proof of device identity (3.3);
  stronger proof is exactly what the future token/MDM identity kinds
  are for.
- **Credential storage**: Stage 11 stores no device secrets (IP
  mappings are not secrets). The `token_hash` identifier kind is
  reserved: when token identity lands, only a SHA-256 hash is stored,
  the raw token is shown once at creation, and rotation creates a new
  identifier row while retiring the old one. **No device secret is ever
  returned by any API response or written to any log.**

---

## 7. Filtering engine integration

### 7.1 Publication format extension (one generation, more documents)

Today's generation is `policy.json` + `categories.json` +
`manifest.json`. Stage 11 publishes:

```
<publish-root>/generations/<revision>/
  policies/<policy_id>.json     one validated document per published policy
  categories.json               unchanged semantics (enabled categories only)
  devices.json                  identity map + default policy pointer
  manifest.json                 extended: hash of EVERY file in the generation
```

`devices.json`:

```json
{
  "default_policy_id": 3,
  "devices": {
    "ipv4:192.168.1.50": {"device_id": 1, "policy_id": 5},
    "ipv6:2001:db8:1:2::/64": {"device_id": 1, "policy_id": 5}
  },
  "_meta": {"source": "kosherguard-dashboard", "revision": 12}
}
```

Only identifiers of `active` devices with an active assignment are
exported. The dashboard builds every policy document through the same
`_export_documents` path and validates each with the engine's own
`validate_policy()` before anything is written. The publisher's atomic
protocol is unchanged - temp files, re-read and re-verify from disk,
atomic `current` symlink swap, flock - only the per-generation file set
grows, and `manifest.json` covers every file (the current two-file
manifest schema gains a `files`/`hashes` map; old two-file generations
remain valid and verifiable).

### 7.2 Engine loading and decision path

- `load_validated_engine()` gains a sibling
  `load_validated_engine_set()` returning one immutable **engine set**:
  `{default: PolicyEngine, per_policy: {policy_id: PolicyEngine},
  device_map: {...}}`. Validation is all-or-nothing: any invalid
  document rejects the whole generation, exactly like today.
- `DNSFilteringService.engine` becomes one immutable reference to the
  engine set, swapped wholesale by the unchanged reload path (SIGHUP /
  `--watch`). One query still reads the reference exactly once.
- **Client identity threading**: `_serve` (UDP) and `_serve_tcp_conn`
  pass the already-available client address into
  `handle_packet(data, client_addr=None, ...)`. Resolution: exact IPv4
  match, else IPv6 `/64` prefix match, else default policy. Resolution
  is a dict lookup - no per-query database or file access.
- **Unknown or unregistered devices** get the default policy (the
  Stage 10 selected policy). No query is ever dropped for lack of a
  device record.
- **Last-known-good retention** is the existing Stage 10 behavior,
  unchanged: an invalid new generation is rejected loudly and the
  previous engine set keeps serving.
- **Backward compatibility**: a legacy two-file generation (no
  `devices.json`) still loads; every client gets the default policy.
  The engine never requires the dashboard to upgrade in lockstep.

### 7.3 Publication flow from the dashboard

`publish_config()` extends `_export_documents` to emit the policy
documents for the default policy **and every policy referenced by an
active assignment on an active device**, plus `devices.json`. Content
hashes for the whole set land in `config_revisions` (schema gains hash
columns for the device map, or a single combined hash - decided at
implementation, recorded in the revision row either way).
`config_status()` compares a fresh in-memory export with the active
revision, so assignment changes light up the existing
`unpublished_changes` indicator. Rollback (`rollback_config`) works
unchanged: the stored revision snapshot now includes `devices.json`
and all policy documents.

### 7.4 Deployment note

The Oracle staging VM currently runs the dashboard only, with no DNS
engine and no `KG_PUBLISH_DIR`. Stage 11 implementation is developed
and tested locally exactly like Stage 10 (the e2e test runs a real DNS
service in-process). Running an engine on staging is a separate owner
decision (12.2), not part of this plan's code.

### 7.5 Last-seen reporting without logging client IPs

The engine's decision log stays IP-free. To populate
`devices.last_seen_at`, the engine keeps an in-memory map
`device_id -> last query monotonic time` (IDs only, no addresses) and
includes it in the existing `--status-file` output. The dashboard
already reads `engine-status.json`; a small merge step lifts those
timestamps into `devices.last_seen_at` when the dashboard and engine
share a host. Where they do not share a host (current staging),
last_seen is honestly reported as unavailable. No client IP is ever
written to any file or log by this design.

### 7.6 Future token identity (sketch, not Stage 11 scope)

A DoH/DoT endpoint can carry per-device identity in the path or
hostname (`/dns-query/<device-token>`). The engine would resolve token
-> device via the `token_hash` identifier kind. This requires a public
TLS endpoint, per-device secret generation and rotation, and rate
limiting; it is the natural Stage 12+ upgrade and the schema already
has its hook.

---

## 8. API endpoint designs

All under the existing session + CSRF rules; JSON in/out; errors as
`{"error": ...}` via `StoreError`, exactly like the existing routes.

| Method + path | Purpose |
| --- | --- |
| `GET /api/devices?search=&state=` | List devices with state, assigned policy name, last_seen |
| `POST /api/devices` | Register a device (name, description, type, os, notes, optional identifiers, optional policy_id) |
| `GET /api/devices/<id>` | Device detail: fields, identifiers, active assignment, policy history |
| `PUT /api/devices/<id>` | Edit name/description/type/os/notes |
| `POST /api/devices/<id>/state` | `{state: active\|inactive\|disabled\|removed}` transition with validation |
| `POST /api/devices/<id>/identifiers` | Add identifier `{kind, value}` (engine-validated format per kind) |
| `DELETE /api/devices/<id>/identifiers/<iid>` | Retire an identifier (sets `retired_at`) |
| `GET /api/devices/<id>/effective-policy` | Resolved view: assigned policy (name, current version, version at assignment) or default policy, plus why |
| `POST /api/devices/<id>/assign-policy` | `{policy_id}` transactional assignment (4.1); `{policy_id: null}` unassigns |
| `GET /api/devices/<id>/audit` | Per-device audit entries (filtered `audit_log` read) |

`GET /api/overview` replaces the hardcoded `"devices": 0` with real
counts by state. `/api/config` keeps `devices_connected: false` and
`mdm_operational: false` until MDM exists; it gains
`devices_registered: <count>` as an honest registry count.

---

## 9. Future Apple integration

The registry is designed to be populated by the Stage 6 architecture
(`docs/MDM_ENROLLMENT_AND_PUSH.md`) without rework:

- `devices.management_status` moves from `unmanaged` to `enrolled` only
  through the real enrollment flow, after the four Apple prerequisites
  exist. No other path sets it.
- New identifier kinds slot into `device_identifiers` without schema
  change: `token_hash` (7.6) and later MDM identity (UDID / identity
  certificate fingerprint). The engine's resolution order extends from
  IP-based to certificate-based per query channel.
- Apple Business Manager / ADE enrollment would create device records
  during activation (Stage 6 flow step 2), attaching MDM identity to
  the same registry; APNs push would later trigger policy-delivery
  confirmations recorded against `device_id`.
- Per-device MDM commands (profiles, restrictions) will reference the
  same `devices.id`, so dashboard audit history covers DNS-policy and
  MDM actions on one device record.
- **Nothing in Stage 11 configures, requests, or assumes MDM, APNs, or
  Apple Business Manager.** The Apple prerequisites campaign remains a
  separate owner decision (Stage 10 roadmap, Stage 13).

---

## 10. Testing strategy and failure scenarios

New tests follow the existing suites' patterns (stdlib `unittest`/
pytest style, real components, bounded polling instead of sleeps).
Target files: `dashboard/tests/test_devices.py`,
`dashboard/tests/test_device_assignment.py`,
`filtering-engine/tests/test_multi_policy.py`,
`dashboard/tests/test_end_to_end.py` (extended).

| Scenario (owner's list) | Planned test |
| --- | --- |
| Duplicate device registration | `POST /api/devices` with an existing name -> 409; duplicate live identifier -> 409 |
| Invalid device identity | Bad IPv4/IPv6/token format rejected with field-named errors; unknown kind rejected |
| Device IP changes | Retire old identifier, add new; engine serves new address after republish; old address falls back to default policy; history shows the change |
| Device policy reassignment | Assignment swap is atomic; concurrent reassignments serialize (unique index + write lock); effective-policy reflects the latest assignment |
| Disabled and removed devices | Disabled/removed devices' identifiers are excluded from the next generation; engine serves them the default policy; reactivation restores assignment |
| Unauthorized device-management requests | Every `/api/devices*` route: 401 without session, 403 without CSRF header; no route leaks another admin's data |
| Concurrent policy changes | Two requests assigning policies / editing a policy race; `_write_txn` + unique indexes guarantee one consistent winner; disable/delete of an assigned policy refused (409) under the same lock |
| Invalid publication | Hand-corrupted policy document in a generation -> publish fails, revision marked failed, previous generation still current; engine reload rejects it and keeps last-known-good |
| Engine restart and reload | Restart with a valid multi-policy generation; SIGHUP/watch reload swaps the whole engine set atomically; in-flight queries finish on the old set; mixed-validity generation rejected wholesale |
| Database failures | Device queries with a corrupt/locked DB surface 500/`{"error"}` without stack traces; `/api/health` reports 503 |
| Rollback | Policy rollback flows to assigned devices after republish; configuration rollback restores an earlier complete generation including `devices.json`; assignment history itself is never rewritten |
| Privacy | Decision log contains no client IP after all engine changes; status file carries device IDs and timestamps only |

Full existing suites must keep passing unchanged; README test counts
updated honestly, including any flake.

---

## 11. Implementation phases and dependencies

Planning only - no phase has begun. Suggested breakdown, each phase
independently reviewable and shippable on this branch:

- **11A - Registry data model + API.** Migration, `Store` methods,
  routes, audit actions, tests. No engine change; nothing published
  changes. Depends on: nothing.
- **11B - Dashboard UI.** Device list, detail page, register/edit/
  assign workflows, replacing the placeholder `renderDevices()`.
  Depends on 11A.
- **11C - Engine multi-policy support.** `load_validated_engine_set`,
  client-address threading, per-client resolution, backward
  compatibility, engine tests. Depends on: nothing (independent of
  11A/11B, merges before 11D).
- **11D - Publication extension + end-to-end.** Multi-document
  generations, manifest extension, dashboard export, `config_status`
  coverage, rollback coverage, e2e DNS-answer test (two simulated
  client IPs, different policies). Depends on 11A + 11C.
- **11E - Last-seen reporting + documentation.** Status-file device
  timestamps, dashboard merge, READMEs, runbook notes. Depends on 11D.

Files expected to change (implementation stage only, after approval):
`dashboard/src/db.py`, `store.py`, `server.py`,
`dashboard/static/app.js` (+ `index.html`, `styles.css`),
`dashboard/tests/*`, `filtering-engine/src/dns_service.py` (+
possibly a new `engine_set.py`), `filtering-engine/tests/*`,
`README.md`, `dashboard/README.md`, `filtering-engine/README.md`.
`engine_bridge.py` and `auth.py` likely unchanged.

---

## 12. Risks and unresolved decisions (need the owner's call)

1. **Unknown-device fallback policy.** Recommendation: keep today's
   behavior - unknown/unregistered/disabled devices get the policy
   selected for publication (the default). Alternative: a strict
   block-all fallback for unknown devices. This changes real filtering
   behavior for any new device on the network, so it needs an explicit
   decision.
2. **Engine on staging.** The Oracle staging VM runs no DNS engine.
   Testing Stage 11 end to end on staging would require deploying the
   engine there (free, but a deployment change and a public DNS
   surface). Recommend keeping the engine local-test-only until a
   Stage 12 deployment decision.
3. **IPv6 granularity.** Recommendation: `/64` prefix matching.
   Trade-off: privacy addresses rotate inside the prefix, so a shared
   home prefix maps all IPv6 devices alike unless separate prefixes
   exist. Confirm inclusion.
4. **DHCP discipline is owner-side.** IP-based identity is only as
   stable as the network's address assignment. Router DHCP reservations
   for managed devices are recommended but are the owner's home-router
   configuration, outside this repository.
5. **Token/DoH identity timing.** Real per-device credentials need a
   public DoH/DoT endpoint. Recommended as a later stage; confirm it
   stays out of Stage 11.
6. **IP identity is not a security boundary.** Accept and document
   (recommended), or wait for token/MDM identity before offering
   per-device policies at all (slower, safer). This plan recommends
   accepting it with honest labeling.

---

## 13. Acceptance criteria for Stage 11

Stage 11 is complete only when ALL hold:

1. Registry CRUD, states, identifiers, and assignment APIs work with
   authorization, CSRF, validation, uniqueness, and audit coverage,
   proven by the new dashboard tests.
2. The engine resolves per-client policies by IPv4 and IPv6 `/64`,
   serves unknown clients the default policy, rejects invalid
   generations wholesale, keeps last-known-good, and preserves legacy
   two-file generations - proven by engine tests.
3. One explicit publish produces one immutable multi-document
   generation; `config_status` detects unpublished assignment changes;
   rollback restores complete historical generations - proven by
   publication tests.
4. End-to-end: assignment via the dashboard API -> publish -> real DNS
   answers from two simulated client identities differ as configured;
   reassignment and rollback change the answers back.
5. No client IP appears in any log or status file; no device secret
   appears in any API response, log, or audit entry.
6. Every device record honestly reports `management_status:
   unmanaged`; nothing claims enrollment, push, or remote management.
7. Full dashboard and engine suites pass on a fresh clone; README
   counts match reality; `main` remains untouched throughout.

---

*Prepared as the Stage 11 planning deliverable. No Stage 11
implementation has begun; it waits for independent review and explicit
approval.*
