# Stage 11 Technical Plan: Device Registry and Per-Device Policies

**Status: planning only. No application code was written, nothing was
deployed, no database or server was modified, nothing was merged, and
`main` is untouched. This document waits for independent review and
explicit approval before any Stage 11 implementation begins.**

**Repository:** https://github.com/yossigo88-cyber/kosherguard-platform
**Working branch:** `stage-9b-deployment-preparation`
**Plan content review baseline:** `7f87c415ccef8aa2ebb87900302da9f32ecd33db`
(the current branch HEAD is tracked by GitHub and is intentionally not
embedded in this document, because this document changes when committed;
the source files referenced below were re-read at
`f4f8492d7f7e22058da018b4cd66b55c769978ea` and are unchanged at the
review baseline, because every commit after
`f4f8492d7f7e22058da018b4cd66b55c769978ea` touched only this document)
**Main (unchanged):** `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`

This plan follows the Stage 10 Technical Roadmap
(`docs/reviews/STAGE_10_TECHNICAL_ROADMAP.md`, section 8), which already
reserved Stage 11 for "device registry and per-device policy architecture
(no MDM)". It also preserves the Stage 6 constraint
(`docs/MDM_ENROLLMENT_AND_PUSH.md`): all four Apple MDM prerequisites are
still missing, so nothing here may claim enrollment, management, push, or
control of any real device.

Revision note (2026-11-15, second commit): the device-identification
analysis was tightened after review. The first revision treated IPv6 /64
prefixes as near-device identity; that was wrong, because a /64 is
normally shared by every device on a network segment. This revision
strictly separates **network/group bindings** (what the current engine
can observe) from **authenticated per-device identity** (what the
current engine cannot observe), and gates secure per-device enforcement
on an authenticated transport or device channel.

Revision note (2026-11-15, fourth commit): the section 4.5 comparator
was replaced with the feasible-signature method after review found the
wholly-independent-boolean formulation would reject even a policy
compared with itself (an unrealizable signature such as "matches B's
blocklist but not A's identical blocklist" counted against the pair).
The feasible-signature method is exact for the rule structure -
equivalent and demonstrably stricter policies pass - and deliberately
conservative only over category-database contents.

Revision note (2026-11-15, fifth commit): final documentation
corrections from independent review, applied here. (1) This final
cleanup removes the self-referential branch-HEAD metadata: earlier
revisions of the header embedded a commit hash presented as the branch
HEAD under review, but any such hash goes stale as soon as the document
is committed, so the header now records a plan content review baseline
and leaves branch-HEAD tracking to GitHub. (2) Section 6.2 now defines
the IPv4-compatible IPv6 rejection precisely (only `::/64` is reachable
under the exact-/64 rule, and it is rejected because it contains the
entire deprecated IPv4-compatible block) and the planned test matrix
covers the IPv4-compatible forms and boundary cases, not only
IPv4-mapped. No comparator, schema, phase, or other architectural
decision changed.

Revision note (2026-11-15, third commit): independent review requested
four corrections, all applied in this revision and summarized in
section 0: (1) association identity classes are now enforced by
database CHECK constraints, not only API validation (6.1); (2) network
addresses are canonicalized before storage, duplicate checking, and
publication, with exact rules and planned tests (6.2); (3) the
tighten-only rule for unauthenticated network bindings is now a
mandatory security requirement with a deterministic, testable
comparison method (4.5), replacing its earlier framing as an optional
owner decision; (4) assigned, published, and enforced policy are now
three formally distinct states (4.6), so a saved assignment is never
implied to be active on an engine.

---

## 0. Corrections applied in this revision (2026-11-15)

This revision applies the four corrections from independent review.
Each is summarized here with a pointer to its full specification.

1. **Identity classes are enforced in the database, not only in the
   API.** `device_associations` gains a CHECK constraint permitting
   exactly three (kind, identity_class) pairs: `ipv4` ->
   `network_binding`, `ipv6_prefix` -> `network_binding`,
   `token_hash` -> `credential`. The database itself rejects any other
   combination, even if a future bug bypasses API validation. API
   validation stays (the server derives `identity_class` from `kind`
   and never accepts it from clients); the CHECK constraint is the
   backstop. Future credential kinds are added only through a
   deliberate table-rebuild schema migration. Full specification:
   section 6.1.
2. **Network addresses are canonicalized.** Every binding value is
   parsed and stored in exactly one canonical form before duplicate
   checking and before publication; malformed addresses, unexpected
   prefix lengths, and ambiguous input are rejected. Duplicate
   detection operates on canonical values only, and published
   generations carry only canonical keys. Full specification and
   planned tests: section 6.2.
3. **Tighten-only is a mandatory security rule with a defined
   comparison.** A policy assigned to a device reached through an
   unauthenticated network binding must never be less restrictive than
   the default policy. "Less restrictive" is decided by a
   deterministic, testable comparison derived from the engine's actual
   decision semantics (section 4.5) - never by policy names, labels,
   or category counts. The check runs server-side at assignment, when
   the default policy selection changes, and at publication; failure
   rejects the operation. This resolves former open decision 12.6:
   tighten-only is no longer optional.
4. **Assigned, published, and enforced are three distinct states.**
   The dashboard defines and displays them separately (section 4.6):
   an assignment saved in the database (assigned), an assignment
   contained in the latest successfully published immutable generation
   (published), and a policy confirmed loaded by a running engine
   through its own status output (enforced). Publication alone never
   implies enforcement; with no engine connected - the current Oracle
   staging truth - enforcement is reported as unavailable, never as
   active.

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
  - Plain DNS only: `filtering-engine/README.md` lists DNS-over-HTTPS /
    DNS-over-TLS listeners as deliberately out of scope today.
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
- The reviewed engine deployment unit (`deploy/kosherguard-engine.service`)
  listens on `127.0.0.1:5353` (loopback); no reviewed deployment exposes
  the DNS service to any network.
- The duplicate Render service `srv-dbsv0smi0phs73e7qpb0` is SUSPENDED
  (not deleted), so branch commits currently trigger no deploys
  anywhere; Oracle has no automatic deployment by design.
- The original paid KosherGuard site, server, and DNS are separate and
  untouched.

**Topology evidence for the target product
(`docs/GENTECH_TECHNICAL_INVESTIGATION.md`)**

- Section 2/164: the intended filtering delivery for iPhones is the
  iOS DNS Settings payload pointing at a **DoH/DoT resolver KosherGuard
  operates** - i.e. a hosted resolver, not a resolver on the home
  network.
- Section 9: network-based alternatives are documented honestly: home
  router DNS filtering "only protects the home network and is trivially
  bypassed by cellular"; a self-hosted filtered resolver is the
  preferred direction.
- Consequence, spelled out in section 3 below: in the charter's own
  target topology, clients reach the resolver from behind home NAT or
  carrier networks, so a source IP address generally cannot pick out
  one device.

### 1.2 The gap Stage 11 closes

Today one published policy applies to every DNS client identically.
There is no device record, no device association of any kind, and no
way to give two clients different filtering. The charter's per-device
control (`docs/PROJECT_CHARTER.md`, components 1-2) needs: a registry
of devices, an association between live queries and registry entries,
per-device policy assignment, and an engine that resolves "which
policy applies to this query" before "what does the policy say".

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
5. **New for this revision:** no document, API, UI string, or log may
   present a source-IP address or prefix as an authenticated device
   identity. Network bindings and identities are different things and
   are named differently everywhere.

---

## 2. Device registry design

### 2.1 Registry concepts

A **device** is a durable administrative record. It is never identified
by its current IP address. Each device gets a server-assigned integer
ID (SQLite autoincrement, never reused) and a human-chosen unique name.

The registry attaches two strictly different kinds of association to a
device, and the schema (section 6) keeps them apart:

- **Network bindings** (`ipv4`, `ipv6_prefix`): claims of the form
  "queries from this address or prefix should receive this device's
  policy". A binding is a routing hint for policy selection. It is NOT
  an identity, NOT authentication, and NOT proof that a specific
  physical device sent a query. Multiple devices can share one binding
  (NAT, shared /64); the binding then behaves as a **group binding**
  applying one policy to the whole group.
- **Identity credentials** (`token_hash` now as a reserved kind; MDM
  identity later): proof-bearing associations. Only a credential can
  back per-device enforcement that must be trusted.

States (`devices.state`, CHECK constraint):

| State | Meaning | Engine effect |
| --- | --- | --- |
| `active` | In normal use | Bindings and assignment (if any) apply |
| `inactive` | Temporarily out of use (e.g. device away) | Treated like no assignment: fallback policy applies |
| `disabled` | Administratively turned off | Fallback policy applies; bindings kept for audit |
| `removed` | Soft-deleted | Bindings retired, assignment history kept, record never hard-deleted in Stage 11 |

Removal is always soft: `state = 'removed'`, all bindings retired
(`retired_at` set), active assignment deactivated. Reactivation moves a
`removed` or `disabled` device back to `active` with a fresh audit
entry; bindings are re-added explicitly, never silently resurrected, so
a new device that inherits an old address cannot silently inherit the
old device's policy.

### 2.2 Fields

`devices`: `id`, `name` (unique, 1-80 chars, no control characters -
same `_check_text` rules as policies), `description`, `device_type`
(free text from a suggested set: `iphone`, `ipad`, `android`, `mac`,
`windows`, `linux`, `router`, `network`, `other`), `os` (free text,
e.g. `iOS 18.1`), `state`, `management_status` (always `unmanaged` in
Stage 11 - honest labeling required by Stage 6), `created_at`,
`registered_at`, `updated_at`, `last_seen_at` (nullable; see 7.5),
`notes` (admin-only free text, max 1000 chars).

A registry entry may also represent a **network or group** (for example
"Home Wi-Fi") when a binding is knowingly shared; `device_type`
`router`/`network` exists so such entries are named honestly instead of
pretending to be one device.

### 2.3 Audit history

Every registry mutation writes to the existing `audit_log` table with
actions `device.create`, `device.update`, `device.state`,
`device.binding.add`, `device.binding.retire`,
`device.policy.assign`, `device.policy.unassign`, each with a detail
string naming the device and the change (never any credential). The
per-device history view is a filtered read of `audit_log` plus the
assignment-history table (4.3).

---

## 3. Device identification: investigation and recommendation

The question: when a DNS query arrives, how does the engine know which
registry entry should govern it?

### 3.1 What signal the current system actually has

The KosherGuard engine is a plain-DNS service. Clients reach it over
UDP/TCP. In the current code (`dns_service.py`), the only per-query
signal that exists at all is the **source IP address** at the socket
layer; it is deliberately not used or logged today. There is no
client-authenticating handshake in plain DNS. Everything stronger
(MAC, hostname, device certificate, per-client credential) either never
reaches a DNS server or does not exist in this codebase yet.

### 3.2 Topology evidence and what it implies

Per-device distinction by source IP is only ever possible when the
resolver sits on the same local network as the devices AND addresses
are stable. The repository's own documents show that this is not the
target deployment:

- The charter's filtering delivery for iPhones is the iOS DNS Settings
  payload pointing at a hosted DoH/DoT resolver
  (`GENTECH_TECHNICAL_INVESTIGATION.md`, sections 2 and 9). A hosted
  resolver sees the client's **public** address: one shared home-NAT
  address for every device in the house, or a carrier-grade address on
  cellular that can change mid-session.
- The reviewed engine unit (`deploy/kosherguard-engine.service`) binds
  loopback only; no reviewed deployment exposes DNS to a network at
  all. Whether the first real resolver deployment is LAN-resident or
  hosted is an owner decision (12.3).

So a source address can mean three very different things, and the plan
must not conflate them:

| Observed source | What it actually denotes |
| --- | --- |
| LAN private IPv4 with a DHCP reservation, resolver on the same LAN | Usually one device, while the reservation holds |
| LAN IPv6 /64 prefix, resolver on the same LAN | The whole local segment - typically EVERY device in the home |
| Public IPv4 of a home connection, resolver hosted off-LAN | The whole household behind NAT |
| Public IPv4/IPv6 of a cellular connection | An arbitrary, rotating carrier address - not even a stable group |

### 3.3 Evaluation of the candidate methods

| Method | Available now? | What it can honestly be | Verdict |
| --- | --- | --- | --- |
| Static/reserved IPv4 | Yes, where the network assigns one | A **network binding**; per-device in effect ONLY under the LAN-resolver + reservation conditions of 3.2 | Supported as a binding, never as identity |
| DHCP address changes | n/a (a failure mode, not a method) | Drift silently misattributes traffic or transfers a policy to a different device | Mitigate: recommend router DHCP reservations (owner-side, outside this repo); staleness surfacing; binding history for audit |
| IPv6 /64 prefix | Yes, if the network uses IPv6 | A **segment/group binding**. One /64 is normally shared by every device on the network; it does not pick out an individual device | Supported only as a group binding; **not offered as individual-device identity** |
| IPv6 /128 (exact address) | Yes, in principle | Unreliable: iOS/macOS privacy extensions rotate temporary addresses deliberately | Rejected for bindings |
| MAC addresses | **No** | Invisible beyond the local link: a DNS packet carries no MAC. iOS also randomizes per-network MACs | **Rejected**; recorded for completeness |
| Device credentials / tokens | Not in the current plain-DNS service | The first **authenticated identity** available without Apple: a per-device DoH/DoT path or hostname token (e.g. `device-token.dns.example`) resolves token -> device; the TLS channel plus secret makes it proof-bearing | **Reserved for a future stage** (needs a public DoH/DoT endpoint, secret issuance and rotation); this is the recommended route to real per-device enforcement (7.6) |
| MDM-based identity (UDID, identity certificate) | **No** - all 4 Apple prerequisites missing (Stage 6) | Strongest: device-bound certificate, survives address changes | **Reserved for the MDM stage**; registry schema carries the hook (9) |

### 3.4 Conditions under which source-address bindings CANNOT satisfy per-device policies

Bindings fail the requested feature - reliably giving one specific
device its own policy - in each of these conditions:

1. **Hosted-resolver topology (the charter's target):** all devices
   behind one NAT present the same public address; cellular devices
   present rotating carrier addresses. Per-device distinction is
   impossible at the engine.
2. **Any shared address or prefix** (NAT, one home /64): one binding
   covers many devices. The result is a group policy, not a per-device
   policy, and the UI must say so.
3. **DHCP without reservations:** drift either loses the device or,
   worse, attaches its policy to a different device that received the
   old address.
4. **Untrusted users on the network:** source addresses are trivially
   spoofable - any client can configure a static address and inherit
   that address's policy. A child could claim a parent's address to
   receive a looser policy. Bindings alone can therefore never be the
   basis for granting a LESS restrictive policy. This is why the
   tighten-only rule (4.5) is mandatory: an unauthenticated binding
   may only apply a policy provably at least as restrictive as the
   default.
5. **VPNs and alternate resolvers on the device** bypass or re-source
   the traffic entirely.

In every one of these conditions the only correct engine behavior is:
apply the binding as a group/network convenience when it is
unambiguous, otherwise serve the default policy - and never claim a
specific device was identified.

### 3.5 Recommendation

**Stage 11 ships the registry, assignment model, dashboard, and engine
resolution keyed by explicitly-labeled NETWORK BINDINGS (reserved IPv4
addresses and, optionally, IPv6 /64 group prefixes). Secure per-device
enforcement - policy selection that may be trusted to apply to one
specific device - is gated on an authenticated transport or device
channel, which plain DNS does not provide.**

Concretely:

- Bindings are modeled, stored, displayed, and documented as
  network/group bindings. The words "identity", "authenticated", and
  "verified device" are reserved for the credential kinds.
- The recommended route to genuine per-device enforcement is a
  **token-authenticated DoH/DoT endpoint** (no Apple dependency; design
  sketch in 7.6), promoted to its own stage after Stage 11. MDM
  certificate identity remains the strongest long-term answer and stays
  blocked on the Apple prerequisites.
- Nothing in Stage 11's correctness depends on topology: bindings work
  the same whether they end up meaning "one device" or "one
  household"; the honest labeling is what changes.

This replaces the first revision's recommendation, which treated IPv6
/64 prefixes as near-device identity.

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
- Assignment is a property of the registry entry. Whether a live query
  actually receives that policy depends on how the query is associated
  (credential first, binding second, default last - section 7.2).

### 4.2 Interaction with Stage 10 safeguards (no second policy system)

- The Stage 10 `publication_state.selected_policy_id` keeps its exact
  meaning: the **default** policy. Stage 11 adds per-entry assignments
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

`device.state = 'disabled'` immediately excludes the device's bindings
and assignment from the next published generation (records stay
attached for audit). Re-enabling restores them. Nothing is published
implicitly: like every Stage 10 change, an assignment, binding, or
state change becomes effective only after an explicit publish, and the
dashboard's existing `unpublished_changes` indicator covers it (7.3).

### 4.5 The tighten-only security rule (mandatory; review correction 3)

**Rule.** A policy assigned to a device whose live associations are
unauthenticated network bindings must never weaken the default policy
(the Stage 10 `publication_state.selected_policy_id`). In Stage 11
every association is a network binding, so the rule applies to every
assignment. When authenticated credentials exist (7.6), devices
reached ONLY through credentials are exempt, because their policy
choice is backed by proof of identity.

This rule is a mandatory security requirement, not an owner option.
Review corrected the earlier framing, which had offered the override
direction as open decision 12.6. A source address is trivially
claimable (3.4 item 4), so a binding must never be a way to obtain
looser filtering.

**Why a real comparison, not labels.** Restrictiveness cannot be read
off policy names, descriptions, or rule counts: a policy named
"Strict" can allow what "Lenient" blocks, and a policy with more
blocked categories can still allow a specific domain through an
explicit allowlist entry (the allowlist beats a category block in the
engine's precedence). The comparison below is defined directly on the
engine's decision semantics in `filtering-engine/src/policy_engine.py`.

**Decision semantics (from `PolicyEngine.decide`).** For a domain `d`
under policy `P` the engine checks, in order: (1) explicit allowlist
match (the domain itself or any subdomain of a listed entry) -> allow;
(2) explicit blocklist match -> block; (3) any category of `d` in
`category_block` -> block; (4) any category of `d` in
`category_allow` -> allow; (5) `default_policy`. The decision
therefore depends on exactly four inputs: whether `d` matches the
allowlist (`al`), whether it matches the blocklist (`bl`), the
category set of `d` (`C`), and the policy's rule data. Both policies
in a comparison are evaluated against the same category universe, and
both are first normalized by the engine's own `validate_policy()`, so
comparison inputs are the exact data the engine would enforce.

**Comparison definition (feasible-signature method).** Let `U` be the
union of the four category rule lists of the two policies
(`category_allow` and `category_block` of each). Categories outside
`U` cannot fire a rule in either policy, so they cannot affect the
outcome.

A domain's decision depends on which of the four lists it matches. A
**match signature** is one of the 16 tuples `(alA, blA, alB, blB)` in
`{0,1}^4` recording whether a domain matches A's allowlist, A's
blocklist, B's allowlist, and B's blocklist. Because the two policies'
list contents differ, the per-policy booleans are NOT assumed equal or
correlated; instead the method determines, for each of the 16
signatures, whether any real domain can have it, using the actual
suffix semantics of `domain_matches` (an entry matches the domain
itself and every subdomain of it):

- A signature is **feasible** iff there is a choice of one entry from
  each list the signature requires a match in, with all chosen entries
  mutually suffix-comparable (each pair equal, or one a subdomain of
  the other), whose most specific (longest) entry `f` is neither equal
  to nor a subdomain of any entry of the lists the signature requires
  NO match in. The certificate is the domain `f` itself. If a
  required-match list is empty, the signature is infeasible. The
  all-zero signature (matches nothing) is always feasible: the domain
  space is infinite and finitely many suffix rules cannot cover it.
  This test is exact in both directions: a real domain's longest
  matching entries are always such a comparable choice with the
  domain itself in `f`'s suffix set, and any `f` passing the test is
  itself a domain with exactly that signature.
- **Fast path:** if the two normalized policy documents are identical
  (same default, same allowlist, same blocklist, same category rules),
  the candidate is equivalent by construction and allowed immediately.

Then:

```
A is AT LEAST AS RESTRICTIVE AS B
  <=>  for every FEASIBLE signature (alA, blA, alB, blB)
       and every C that is a subset of U:
       dec(B, alB, blB, C) = block  implies  dec(A, alA, blA, C) = block.
```

- **Sound:** every real domain has exactly one signature, and that
  signature is feasible, so the enumeration covers every real domain;
  a domain's decision under each policy equals `dec` of its signature
  and category set. A passing check therefore guarantees no domain is
  allowed by A that B blocks.
- **Admits equivalent and demonstrably stricter policies:** signatures
  whose per-policy halves cannot differ (identical or correlated
  lists) are infeasible and never cause false rejection. Identical
  policies pass, including block-all vs block-all, and a candidate
  whose blocking behavior is a strict superset of the default's
  passes. This replaces the first formulation of this section (wholly
  independent booleans), which review found would reject even a policy
  compared with itself.
- **Conservative on categories, deliberately:** `C` ranges over ALL
  subsets of `U`, so the result never depends on the CURRENT category
  database contents and never needs re-running when domain/category
  data changes (only on rule changes or default-policy changes -
  enforcement points 2 and 3 below). The price: a pair that is safe
  only because of today's category assignments (for example the
  candidate allows a category the database currently assigns to no
  domain) is rejected. Documented conservatism, not a bug.
- **Catches the dangerous cases:** a candidate allowlisting a domain
  the baseline blocks (signature with `alA=1`, `blB=1`, feasible via
  the shared suffix) is rejected; a candidate dropping a baseline
  blocklist entry is rejected whenever the dropped domain would become
  allowed; a candidate allowlisting a SUBDOMAIN of a
  baseline-blocklisted domain is rejected (suffix comparability makes
  that signature feasible - which matches the engine, whose allowlist
  really would win there).
- **Deterministic and bounded:** a pure function of the two normalized
  policy documents; same inputs, same answer. Work is bounded by
  (witness-entry choices per signature) x (16 signatures) x
  (2^|U| category subsets). Planned caps: `|U|` <= 20 referenced
  categories; any rule list > 500 entries, or a signature whose
  witness-choice product exceeds 100,000, makes the comparison
  infeasible to compute - every cap failure REJECTS the assignment
  (fail safe, never guessed).
- **Invalid input:** a policy that fails `validate_policy()` cannot be
  compared and is rejected.
- **Placement:** the comparator lives in the filtering engine package
  next to `policy_engine.py` and is re-exported through
  `engine_bridge.py`, keeping policy logic single-sourced (1.3 item
  4). The engine itself never runs the comparison; it only enforces
  published documents.

**Enforcement points (all server-side).**

1. **Assignment** (`POST /api/devices/<id>/assign-policy`): the check
   runs inside the same `_write_txn` as the assignment swap, comparing
   the candidate policy's current version against the current default
   policy's current version. Failure -> 409 naming the policy and the
   reason; no assignment row is written. The UI displays the server's
   verdict but never decides it.
2. **Default policy change** (`select_policy_for_publication`):
   changing the default changes the baseline every binding is measured
   against. The selection endpoint re-runs the check for every active
   assignment on a device with any live network binding, inside the
   same write transaction that moves the selection pointer; if any
   assignment would violate tighten-only, the selection change is
   refused (409) naming the conflicting devices and policies. A
   default-policy change can therefore never silently make an existing
   network binding less restrictive.
3. **Publication** (`publish_config`): assignments record the policy
   version at assignment, but enforcement uses the latest published
   version (4.1), and a policy can be edited between assignment and
   publish. The publish path therefore re-runs the check for every
   active binding-governed assignment against the freshly exported
   current versions BEFORE any file is written. A violation fails the
   whole publication: no generation is written, the previous
   generation stays current, and the failure is recorded on the
   revision row exactly like a validation failure today.
4. **Policy disable/delete/rollback** keep their Stage 10 invariants;
   the "referenced by an active assignment" check (4.2) is unchanged.

**If comparison ever becomes impossible.** The current policy model
supports the decidable comparison above, so custom policies on network
bindings remain allowed under it. If a future policy feature (for
example time-based rules) made decisions depend on inputs outside the
enumeration, the comparison must be redesigned first; until such a
safe mechanism exists, custom policies on network bindings are
DISABLED and every binding falls back to the default policy. This plan
does not claim that fallback is needed today.

**Planned tests** (listed in section 10): equivalent (identical rule
data) allowed, including block-all vs block-all; strict-superset
blocking allowed; correlated lists (shared allowlist/blocklist
entries) cause no false rejection; less restrictive rejected at
assignment, at default-policy change, and at publish; incomparable
policies (each blocks something the other allows) rejected; candidate
allowlisting a baseline-blocked domain rejected; candidate dropping a
baseline blocklist entry rejected when the domain would become
allowed; candidate allowlisting a subdomain of a baseline-blocked
domain rejected; invalid candidate rejected; category-precedence cases
(category allow vs category block; an explicit allowlist entry
overriding a category block; default allow vs default block interplay);
cap-exceeded fail-safe rejection.

### 4.6 Assigned vs published vs enforced policy (review correction 4)

The dashboard must never imply that an assignment is active on the DNS
engine merely because an administrator saved it. Three states are
defined and never conflated:

1. **Assigned** - the administrator's current intended assignment in
   the dashboard database: the active `device_policy_assignments`
   rows, plus the default policy pointer
   (`publication_state.selected_policy_id`). Saving an assignment
   changes nothing any engine does.
2. **Published** - the assignment contained in the latest successfully
   published immutable configuration generation: the
   `config_revisions` row with `status = 'published'` named by
   `publication_state.active_revision`, verifiable on disk through the
   publisher's `current()` (symlink target plus manifest hash
   re-verification). Publication remains the one explicit, audited
   Stage 10 action; its atomic multi-document generation protocol is
   unchanged.
3. **Enforced** - the policy a running filtering engine has CONFIRMED
   loaded, reported only from the engine's own status output. The
   engine's `--status-file` (`engine-status.json`, written atomically
   after every load attempt) records the active generation, revision,
   per-document SHA-256 hashes, reload count, `loaded_at`, and
   `last_error`; Stage 10's `Store.engine_status()` and
   `config_status()` already read and compare it when dashboard and
   engine share the publication root.

Rules:

- **Unpublished assignments are visibly marked.** The existing
  `unpublished_changes` mechanism (a fresh in-memory export hashed
  against the active revision's recorded hashes) extends to the
  multi-document generation, so assignment, binding, and device-state
  changes set it. The device list, the device page, and the
  Publication page show an "unpublished" badge until a publish
  succeeds.
- **Publication success is not enforcement.** A completed publish
  means a verified generation on disk. An engine loads it only on its
  next SIGHUP/`--watch` reload, can reject it (last-known-good
  retention), or can be stopped entirely. The dashboard never upgrades
  "published" to "enforced" on publish success alone.
- **Enforcement requires trustworthy status.** "Enforced" is reported
  only when the engine's status output exists AND identifies a loaded
  generation/revision whose content hashes match the active published
  revision's recorded hashes. The multi-document generation extends
  both the manifest and the status output to carry the hash of EVERY
  file (7.1), so the comparison covers `devices.json` and every policy
  document, not only the two Stage 10 files. A status that cannot
  identify its loaded revision is not evidence of enforcement.
- **No engine connected => unavailable, never active.** When the
  status file is absent or unreadable (`Store.engine_status()` returns
  None), enforcement is reported as "engine not connected /
  enforcement unavailable". This is the current Oracle staging truth:
  the VM runs the dashboard only, no filtering engine is connected,
  and nothing in the UI or API may present any policy as enforced
  there.
- **Stale or inconsistent status is reported honestly.** If the status
  names an older revision than the active one, or its hashes do not
  match the active revision, or `last_error` records a rejected reload
  after the last publish, the UI says so ("engine has not confirmed
  revision N; last confirmed revision M", or "engine rejected the
  latest generation") - never a green "active".
- **API shape.** `GET /api/devices/<id>/effective-policy` returns the
  three states distinctly, for example `{assigned: {policy,
  version_at_assignment} | "default", published: {revision,
  generation} | null, enforced: {revision, generation, confirmed_at} |
  "unavailable" | "stale" | "rejected"}`. `config_status()` gains a
  per-assignment view of the same three states; its existing
  `engine_matches_active_revision` comparison generalizes to the
  multi-document hash map.

**Planned tests** (listed in section 10): an assignment saved but not
published is marked unpublished; a successful publication with no
engine reports enforced = unavailable (never active); engine status
matching the active revision reports enforced; engine status on an
older revision reports stale; a missing status file reports
not-connected; a status whose `last_error` postdates the last publish
reports the rejection.

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
   "Default policy"), association summary ("2 bindings", "token",
   "none"), last seen (or "never observed"), search box
   (name/description) and state filter - the same search/filter shape
   as the existing Policies and Domains pages. "Register device"
   button.
3. **Register workflow**: modal or sub-page collecting name
   (required), description, device type, OS, optional initial bindings
   (validated per kind, each labeled "network binding - not device
   identity" in the form), and optional initial policy assignment.
   Validation errors shown in place, as on existing forms.
4. **Device details page** (`#/devices/<id>`): all fields; bindings
   list with add/retire actions, each row labeled with its kind and
   class (network binding vs credential); current effective policy
   card (assigned policy name + version at assignment, or "Default
   policy"); assignment interface (policy picker populated from
   `GET /api/policies`, with the test-query link to the existing
   `/api/policies/<id>/test` flow); state actions
   (disable/re-enable/remove) behind `confirmDialog`; audit history
   (per-device filtered entries).
5. **Edit workflow**: name/description/type/OS/notes edits on the
   details page.
6. **Status indicators**: state badges; an "unpublished changes" hint
   consistent with the Publication page when assignments or bindings
   changed since the last publish; the three-state
   assigned/published/enforced display of 4.6 on the device page's
   effective-policy card (enforcement shown as unavailable when no
   engine is connected); a staleness hint when `last_seen_at`
   is old for an `active` device (possible sign of a DHCP change);
   a group hint when a binding is known to cover multiple devices.
   Assignment attempts surface the server-side tighten-only verdict
   (4.5) verbatim; the UI never pre-judges the comparison.
7. **Honesty**: the page header keeps the existing honest note that no
   MDM enrollment exists, `management_status` is `unmanaged` for every
   device, and network bindings are labeled as not being device
   identity - including inline on the binding rows, not just in docs.

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

CREATE TABLE IF NOT EXISTS device_associations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id INTEGER NOT NULL REFERENCES devices(id),
  kind TEXT NOT NULL CHECK (kind IN ('ipv4','ipv6_prefix','token_hash')),
  -- network_binding: an address/prefix routing hint; never identity.
  -- credential: proof-bearing identity (token_hash; MDM kinds later).
  identity_class TEXT NOT NULL
    CHECK (identity_class IN ('network_binding','credential')),
  -- Database-enforced identity classes (6.1): the ONLY permitted
  -- (kind, identity_class) pairs. SQLite aborts any INSERT or UPDATE
  -- producing another combination, even if API validation is bypassed.
  CHECK (
    (kind = 'ipv4'        AND identity_class = 'network_binding') OR
    (kind = 'ipv6_prefix' AND identity_class = 'network_binding') OR
    (kind = 'token_hash'  AND identity_class = 'credential')
  ),
  -- Stored ONLY in canonical form (6.2); the unique index below is
  -- therefore also the canonical duplicate check.
  value TEXT NOT NULL,
  created_at TEXT NOT NULL,
  retired_at TEXT
);
-- One live association value maps to at most one device.
CREATE UNIQUE INDEX IF NOT EXISTS uq_live_association
  ON device_associations (kind, value) WHERE retired_at IS NULL;

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

### 6.1 Database-enforced identity classes (review correction 1)

The combined CHECK constraint above makes the permitted
(kind, identity_class) pairs a property of the database, not of any
application layer. Consequences:

- **Backstop, not replacement.** API validation stays: the server
  derives `identity_class` from `kind` (`ipv4`/`ipv6_prefix` ->
  `network_binding`; `token_hash` -> `credential`) and never accepts
  `identity_class` from the client, so legitimate users keep precise
  field-level errors. The CHECK constraint exists for the day a future
  code path forgets that rule: SQLite evaluates it on every INSERT and
  UPDATE and aborts the statement inside the same `_write_txn`
  transaction, so an invalid row can never be committed.
- **A binding can never become a credential by edit.** The CHECK
  covers UPDATEs too, so retire-and-replace remains the only path.
- **Adding a future credential kind is a deliberate migration.**
  SQLite cannot alter a CHECK constraint in place. A new kind (for
  example an MDM certificate fingerprint) is added by an explicit,
  separately reviewed migration in the `SCHEMA_STAGE*` style: create a
  replacement table whose CHECK names the existing pairs PLUS the new
  one, copy all rows, drop the old table, rename, and recreate the
  indexes - the standard safe SQLite table rebuild, with the foreign
  key pragma handled around it - plus migration tests proving existing
  rows survive and invalid combinations are still rejected. The
  migration must name the exact new pair; widening the constraint
  "for flexibility" is forbidden, because every new pair is a security
  statement about what counts as identity.

### 6.2 Canonical network addresses (review correction 2)

Every binding value is normalized to one canonical form BEFORE it is
checked for duplicates, stored, or published. One piece of code does
this everywhere: the canonicalizer lives in the filtering engine
package (next to `policy_engine.py`) and is re-exported through
`engine_bridge.py`, keeping validation single-sourced (1.3 item 4).
Both the dashboard (at write time) and the engine (at lookup time)
call the same function.

Rules (specified against Python's `ipaddress` module):

- **IPv4** (`kind = 'ipv4'`): parse with `ipaddress.IPv4Address` and
  store `str(address)` - canonical dotted-quad (`192.168.1.50`). The
  strict parser rejects leading zeros (`192.168.001.50`), non-dotted
  forms (single integers, hex, octal), out-of-range octets, prefix
  notation, and surrounding whitespace; rejected input is never
  silently repaired, the API error names the field.
- **IPv6 group prefix** (`kind = 'ipv6_prefix'`): parse with
  `ipaddress.IPv6Network(value, strict=True)`. The prefix length MUST
  be exactly 64 and the address part MUST be the network address
  (strict parsing rejects host bits, so `2001:db8::1/64` is rejected
  and the administrator writes `2001:db8::/64`). Store `str(network)`
  - the canonical compressed lowercase form with the normalized
  network address. Rejected: malformed addresses, any prefix length
  other than /64, zone IDs (`fe80::%eth0/64`), IPv4-mapped and
  IPv4-compatible forms (defined exactly in the next bullet), and
  empty or whitespace-padded input.
- **IPv4-mapped and IPv4-compatible rejection, defined exactly.** Two
  reserved spellings of IPv4 space may never become an `ipv6_prefix`
  binding, so IPv4 space has exactly one representation (`ipv4`) and
  cannot be duplicated through the IPv6 kind:
  - *IPv4-mapped* (RFC 4291 section 2.5.5.2): 80 zero bits, then
    `ffff`, then a 32-bit IPv4 address, in mixed (`::ffff:192.0.2.1`)
    or hex (`::ffff:c000:201`) spelling. In Python this is any address
    whose `IPv6Address.ipv4_mapped` is not `None`. Under the exact-/64
    requirement no mapped input can reach storage anyway: the `ffff`
    marker sits at bits 80-95, inside the host portion of a /64, so
    `IPv6Network(value, strict=True)` already rejects every mapped
    spelling as host-bits-set. The canonicalizer still checks
    `ipv4_mapped` explicitly, so the rule does not depend on that
    parser subtlety and the API error names the real reason.
  - *IPv4-compatible* (the deprecated RFC 4291 section 2.5.5.1 form):
    96 zero bits, then a 32-bit IPv4 address (`::192.0.2.1`, hex
    `::c000:201`). Python's `ipaddress` parses these as ordinary IPv6
    addresses and has no `ipv4_compatible` property, so the check is
    arithmetic: a parsed candidate is rejected when its address has
    the top 96 bits all zero (`int(address) < 2**32`). Because a
    strictly parsed /64 network address already has zero host bits,
    this rejects exactly one network, `::/64` - but that network
    contains the unspecified address `::`, the loopback `::1`, and the
    entire deprecated IPv4-compatible block `::/96`, so rejecting it
    closes the whole class. Individual compatible spellings with a
    nonzero low 32 bits (`::192.0.2.1/64`) also fail strict /64
    parsing as host-bits-set; either check rejecting is correct, and
    the API error names the field.
  - Boundary cases, pinned by the planned tests below: `::/64` is
    rejected in every spelling (`0:0:0:0:0:0:0:0/64`, mixed
    `::0.0.0.0/64`); `::1/64` and `::ffff:0.0.0.0/64` are rejected;
    the NAT64 well-known prefix `64:ff9b::/64` is NOT IPv4-compatible
    (its top 96 bits are nonzero) and stays acceptable as an ordinary
    /64; a mixed dotted-quad spelling of a non-reserved address
    (`2001:db8::0.0.0.0/64`) is not special-cased - it parses
    unambiguously and stores as canonical `2001:db8::/64`. None of
    this weakens canonicalization or the exact-/64 rule: every stored
    value is still `str()` of a strictly parsed /64 network.
- **Duplicate detection operates on canonical values only.** Only
  canonical strings are ever stored, so the partial unique index
  `uq_live_association (kind, value) WHERE retired_at IS NULL` IS the
  canonical duplicate check: two spellings of one network collide at
  insert time with a 409, never silently coexist.
- **Publication uses canonical keys.** `devices.json` binding keys are
  the stored canonical strings (7.1). The engine normalizes every
  observed source address with the same canonicalizer before lookup:
  an IPv4 source maps to its dotted-quad key; an IPv6 source maps to
  the `str()` of its /64 network. Lookup stays an exact string dict
  lookup with no per-query parsing ambiguity.

Planned tests (section 10): equivalent IPv6 spellings
(`2001:0DB8:0000:0000:0000:0000:0000:0000/64`, `2001:DB8::/64`,
`2001:db8:0:0::/64`) all store and publish as `2001:db8::/64`, and the
second spelling of the same network is rejected as a duplicate;
host-bits-set prefix (`2001:db8::1/64`) rejected; `/48`, `/128`, and
`/32` on the IPv6 kind rejected; malformed input (`2001:::0/64`)
rejected; zone ID rejected; IPv4-mapped rejected in both spellings
(mixed `::ffff:192.0.2.1/64`, hex `::ffff:c000:201/64`);
IPv4-compatible rejected: `::/64` in every spelling (`::/64`,
`0:0:0:0:0:0:0:0/64`, `::0.0.0.0/64`) is rejected even though
`IPv6Network('::/64', strict=True)` parses it cleanly, and
`::1/64`, `::192.0.2.1/64`, and hex `::c000:201/64` are rejected;
boundary cases pinned: NAT64 `64:ff9b::/64` accepted as an ordinary
/64, and `2001:db8::0.0.0.0/64` stores as canonical `2001:db8::/64`;
IPv4 normalization
(`192.168.1.50` stored unchanged; leading-zero `192.168.001.50`
rejected, not corrected); duplicate normalized IPv4 rejected; exported
`devices.json` contains only canonical keys; engine lookup matches a
source address inside a canonical /64 binding.

Security properties:

- **No shared binding is ever a unique identity**: the
  `identity_class` column is mandatory, its permitted combinations are
  enforced by the database CHECK constraint (6.1) - not only by API
  validation - and `ipv4`/`ipv6_prefix` associations can only exist as
  `network_binding`. API and UI copy reflects the class; a binding can
  never be upgraded to `credential` by editing - only retired and
  replaced.
- **Unique constraints**: device names unique; one live association
  value belongs to one device (partial unique index), so two registry
  entries cannot claim the same address at once; one active assignment
  per device (partial unique index). SQLite enforces these even under
  concurrency, backed by the same `BEGIN IMMEDIATE` write transactions
  Stage 10 uses.
- **Spoofing and misattribution stance**: bindings are convenience
  routing, not access control. The spoofing risk (3.4 item 4) is
  documented in the README and the UI, and the mandatory tighten-only
  rule (4.5) is the fail-safe: an unauthenticated binding can never
  grant a policy less restrictive than the default.
- **Foreign keys**: associations and assignments reference `devices`
  and `policies`; `PRAGMA foreign_keys = ON` is already set. Deletion
  is soft (state), so no cascading delete of history.
- **Transactional assignment**: reassignment checks policy existence +
  enabled state and swaps rows inside one `_write_txn`.
- **Authorization**: every `/api/devices*` route goes through the
  existing `self._admin(conn)` session check; there is no
  unauthenticated device endpoint, and `GET /api/health` stays minimal.
- **CSRF**: every mutation keeps requiring `X-KosherGuard-Request: 1`
  (existing `_require_csrf_header`), unchanged.
- **Audit logging**: every mutation audited (2.3); audit details never
  contain credentials.
- **Credential storage**: Stage 11 stores no device secrets (address
  bindings are not secrets). The `token_hash` kind is reserved: when
  token identity lands, only a SHA-256 hash is stored, the raw token is
  shown once at creation, and rotation creates a new association row
  while retiring the old one. **No device secret is ever returned by
  any API response or written to any log.**

---

## 7. Filtering engine integration

### 7.1 Publication format extension (one generation, more documents)

Today's generation is `policy.json` + `categories.json` +
`manifest.json`. Stage 11 publishes:

```
<publish-root>/generations/<revision>/
  policies/<policy_id>.json     one validated document per published policy
  categories.json               unchanged semantics (enabled categories only)
  devices.json                  association map + default policy pointer
  manifest.json                 extended: hash of EVERY file in the generation
```

`devices.json`:

```json
{
  "default_policy_id": 3,
  "bindings": {
    "ipv4:192.168.1.50": {"device_id": 1, "policy_id": 5, "class": "network_binding"},
    "ipv6:2001:db8:1:2::/64": {"device_id": 2, "policy_id": 7, "class": "network_binding"}
  },
  "credentials": {},
  "_meta": {"source": "kosherguard-dashboard", "revision": 12}
}
```

Only associations of `active` devices with an active assignment are
exported; `credentials` is empty in Stage 11 and reserved for token/MDM
identity. Every key in `bindings` is a canonical string produced by the
6.2 canonicalizer; no other spelling can appear in a generation. The dashboard builds every policy document through the same
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
  bindings: {...}, credentials: {...}}`. Validation is all-or-nothing:
  any invalid document rejects the whole generation, exactly like
  today.
- `DNSFilteringService.engine` becomes one immutable reference to the
  engine set, swapped wholesale by the unchanged reload path (SIGHUP /
  `--watch`). One query still reads the reference exactly once.
- **Resolution order** (strict): (1) authenticated credential, when
  that channel exists - not in Stage 11; (2) network binding - exact
  IPv4 match, else IPv6 /64 group-prefix match; (3) the default policy.
  A credential always beats a binding when both exist, because only the
  credential is proof-bearing.
- **Client address threading**: `_serve` (UDP) and `_serve_tcp_conn`
  pass the already-available client address into
  `handle_packet(data, client_addr=None, ...)`. Binding resolution is a
  dict lookup - no per-query database or file access. The observed
  address is canonicalized with the 6.2 canonicalizer first (IPv4 to
  its dotted-quad key, IPv6 to its /64 network key), so lookups always
  match stored canonical bindings.
- **Unknown or unregistered sources** get the default policy (the
  Stage 10 selected policy). No query is ever dropped for lack of a
  registry record.
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
columns for the association map, or a single combined hash - decided at
implementation, recorded in the revision row either way). Before any
file is written, the publish path re-runs the tighten-only check (4.5,
enforcement point 3) for every active binding-governed assignment
against the freshly exported versions; a violation fails the
publication, no generation is written, and the failure is recorded on
the revision row exactly like a validation failure today.
`config_status()` compares a fresh in-memory export with the active
revision, so assignment and binding changes light up the existing
`unpublished_changes` indicator, and it reports the three states of
4.6 - assigned (database), published (active revision on disk), and
enforced (engine status hash comparison), with the honest
not-connected, stale, and rejected substates. Rollback
(`rollback_config`) works unchanged: the stored revision snapshot now
includes `devices.json` and all policy documents.

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
last_seen is honestly reported as unavailable. Note: with group
bindings, "last seen" means "this binding was observed", not "this
physical device was observed"; the UI labels it accordingly. No client
IP is ever written to any file or log by this design.

### 7.6 Authenticated token identity (design sketch, not Stage 11 scope)

A DoH/DoT endpoint can carry per-device identity in the path or
hostname (`/dns-query/<device-token>`). The engine resolves token ->
device through the `token_hash` association kind (`identity_class =
'credential'`), and that resolution takes precedence over any binding
(7.2). This requires a public TLS DoH/DoT endpoint (the engine's
README currently lists DoH/DoT listeners as deliberately out of scope),
per-device secret generation, storage of hashes only, rotation, and
rate limiting. It has **no Apple dependency** - the iOS DNS Settings
payload can point a supervised device at a per-device DoH URL today -
so it is the recommended next stage after Stage 11 for genuine
per-device enforcement, and the schema and resolution order above are
designed so it drops in without reworking the registry. MDM
certificate identity later becomes one more credential kind on the
same path.

---

## 8. API endpoint designs

All under the existing session + CSRF rules; JSON in/out; errors as
`{"error": ...}` via `StoreError`, exactly like the existing routes.

| Method + path | Purpose |
| --- | --- |
| `GET /api/devices?search=&state=` | List devices with state, assigned policy name, association summary, last_seen |
| `POST /api/devices` | Register a device (name, description, type, os, notes, optional bindings, optional policy_id) |
| `GET /api/devices/<id>` | Device detail: fields, associations (kind + identity_class), active assignment, policy history |
| `PUT /api/devices/<id>` | Edit name/description/type/os/notes |
| `POST /api/devices/<id>/state` | `{state: active\|inactive\|disabled\|removed}` transition with validation |
| `POST /api/devices/<id>/associations` | Add association `{kind, value}`; server sets `identity_class` from kind (`ipv4`/`ipv6_prefix` => `network_binding` always); value canonicalized per 6.2 - malformed, ambiguous, or non-/64 input rejected (400), canonical duplicates rejected (409) |
| `DELETE /api/devices/<id>/associations/<aid>` | Retire an association (sets `retired_at`) |
| `GET /api/devices/<id>/effective-policy` | Resolved view: the association path that would apply and its class, plus the three distinct states of 4.6 - assigned policy (name, current version, version at assignment) or default policy; published revision/generation or null; enforced revision/generation or `unavailable`/`stale`/`rejected` |
| `POST /api/devices/<id>/assign-policy` | `{policy_id}` transactional assignment (4.1) with the mandatory server-side tighten-only check (4.5), 409 on violation; `{policy_id: null}` unassigns |
| `GET /api/devices/<id>/audit` | Per-device audit entries (filtered `audit_log` read) |

`GET /api/overview` replaces the hardcoded `"devices": 0` with real
counts by state. `/api/config` keeps `devices_connected: false` and
`mdm_operational: false` until MDM exists; it gains
`devices_registered: <count>` as an honest registry count. No response
ever labels a network binding as identity.

Two existing endpoints gain explicit duties under the corrections:
`POST /api/policies/<id>/select` (Stage 10's default-policy selection)
refuses (409) any selection change that would make an existing
network-binding assignment violate tighten-only (4.5, enforcement
point 2), and `GET /api/config/status` reports the
assigned/published/enforced states of 4.6 for the default policy and
every assignment.

---

## 9. Future Apple integration

The registry is designed to be populated by the Stage 6 architecture
(`docs/MDM_ENROLLMENT_AND_PUSH.md`) without rework:

- `devices.management_status` moves from `unmanaged` to `enrolled` only
  through the real enrollment flow, after the four Apple prerequisites
  exist. No other path sets it.
- New credential kinds slot into `device_associations` with
  `identity_class = 'credential'` without schema change: `token_hash`
  (7.6) first, then MDM identity (UDID / identity certificate
  fingerprint). The engine's resolution order already prefers
  credentials over bindings, so an enrolled device keeps its policy on
  any network, any address.
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
| Duplicate device registration | `POST /api/devices` with an existing name -> 409; duplicate live association -> 409 |
| Invalid device association | Bad IPv4/IPv6/token format rejected with field-named errors; unknown kind rejected; attempt to create an `ipv4`/`ipv6_prefix` association with `identity_class = 'credential'` rejected |
| Device IP changes | Retire old binding, add new; engine serves the new address after republish; the old address falls back to default policy; history shows the change |
| Device policy reassignment | Assignment swap is atomic; concurrent reassignments serialize (unique index + write lock); effective-policy reflects the latest assignment |
| Disabled and removed devices | Disabled/removed devices' associations are excluded from the next generation; engine serves those sources the default policy; reactivation restores assignment |
| Unauthorized device-management requests | Every `/api/devices*` route: 401 without session, 403 without CSRF header |
| Concurrent policy changes | Two requests assigning policies / editing a policy race; `_write_txn` + unique indexes guarantee one consistent winner; disable/delete of an assigned policy refused (409) under the same lock |
| Invalid publication | Hand-corrupted policy document in a generation -> publish fails, revision marked failed, previous generation still current; engine reload rejects it and keeps last-known-good |
| Engine restart and reload | Restart with a valid multi-policy generation; SIGHUP/watch reload swaps the whole engine set atomically; in-flight queries finish on the old set; mixed-validity generation rejected wholesale |
| Database failures | Device queries with a corrupt/locked DB surface 500/`{"error"}` without stack traces; `/api/health` reports 503 |
| Rollback | Policy rollback flows to assigned devices after republish; configuration rollback restores an earlier complete generation including `devices.json`; assignment history itself is never rewritten |
| Shared binding = group, not identity | Two simulated clients behind the same mapped address/prefix receive the SAME policy; the effective-policy API reports the association class as `network_binding`; no test asserts a specific physical device was identified |
| Spoofed source address | A client querying from a statically claimed address receives that binding's policy (documented behavior); test proves the default policy is what unbound sources get, and docs/tests pin the mandatory tighten-only rule (4.5) |
| Credential precedence (forward) | Once token identity exists: a query with a valid token gets the credential's policy even from an address bound to another device; a bad/absent token falls through to binding, then default |
| Privacy | Decision log contains no client IP after all engine changes; status file carries device IDs and timestamps only |
| Identity-class enforcement (correction 1) | API attempt to create an `ipv4`/`ipv6_prefix` association as `credential` -> 400 with a field-named error; direct-SQL INSERT and UPDATE with a mismatched (kind, identity_class) pair -> SQLite CHECK violation, the transaction aborts, no row is written; a table-rebuild migration test proves existing rows survive a future kind addition and invalid pairs stay rejected |
| Address canonicalization (correction 2) | The full 6.2 matrix: equivalent IPv6 spellings collapse to one canonical stored value and publish key; a second spelling of the same network 409s as a duplicate; host-bits-set, wrong-length (/48, /128, /32), malformed, zone-ID, IPv4-mapped (mixed and hex spellings), and IPv4-compatible IPv6 rejected (`::/64` in all spellings despite parsing cleanly under strict /64, `::1/64`, `::192.0.2.1/64`, `::c000:201/64`); boundary cases pinned (NAT64 `64:ff9b::/64` accepted; mixed-spelling non-reserved address canonicalized); leading-zero and prefixed IPv4 rejected; exported `devices.json` keys all canonical; engine lookup matches a source inside a canonical /64 |
| Tighten-only rule (correction 3) | The full 4.5 matrix: equivalent candidates accepted (including block-all vs block-all), strict-superset blocking accepted, correlated shared lists never falsely rejected; less-restrictive, incomparable, invalid, and cap-exceeded candidates rejected at assignment, at default-policy selection change, and at publish; feasible-signature cases (candidate allowlists a baseline-blocked domain, drops a baseline blocklist entry, or allowlists a subdomain of one - all rejected); category-precedence cases (category allow vs block, an allowlist entry overriding a category block, default allow vs default block); a violating publish writes no generation and keeps the previous one current |
| Assigned / published / enforced (correction 4) | Saved-but-unpublished assignment is badged unpublished; publish success with no engine -> enforcement reported unavailable (never active); matching engine status -> enforced; engine status on an older revision -> stale; missing status file -> not connected; `last_error` after a publish -> rejection surfaced; no UI or API state ever renders a saved assignment as enforced |

Full existing suites must keep passing unchanged; README test counts
updated honestly, including any flake.

---

## 11. Implementation phases and dependencies

Planning only - no phase has begun. Suggested breakdown, each phase
independently reviewable and shippable on this branch:

- **11A - Registry data model + API.** Migration (including the
  identity-class CHECK constraint, 6.1), the shared address
  canonicalizer (6.2) and the tighten-only comparator (4.5) - both in
  the engine package and re-exported through `engine_bridge.py` -
  `Store` methods, routes with server-side tighten-only enforcement at
  assignment and at default-policy selection, audit actions, tests. No
  engine change; nothing published changes. Depends on: nothing.
- **11B - Dashboard UI.** Device list, detail page, register/edit/
  assign workflows, binding labeling, the three-state
  assigned/published/enforced display (4.6), replacing the placeholder
  `renderDevices()`. Depends on 11A.
- **11C - Engine multi-policy support.** `load_validated_engine_set`,
  client-address threading, binding resolution with canonicalization of
  observed source addresses (6.2) and the strict credential > binding >
  default order, backward compatibility, engine tests. Depends on:
  nothing (independent of 11A/11B, merges before 11D).
- **11D - Publication extension + end-to-end.** Multi-document
  generations, manifest extension (a hash for EVERY file), dashboard
  export, the publish-time tighten-only re-check (4.5), `config_status`
  coverage including the assigned/published/enforced states (4.6),
  rollback coverage, e2e DNS-answer test (two simulated client sources,
  different policies; shared-source group behavior).
  Depends on 11A + 11C.
- **11E - Last-seen reporting + documentation.** Status-file device
  timestamps, dashboard merge, READMEs, runbook notes. Depends on 11D.
- **Later (own stage, recommended):** token-authenticated DoH/DoT
  endpoint and per-device credentials (7.6) - the step that delivers
  genuine per-device enforcement.

Files expected to change (implementation stage only, after approval):
`dashboard/src/db.py`, `store.py`, `server.py`,
`dashboard/static/app.js` (+ `index.html`, `styles.css`),
`dashboard/tests/*`, `filtering-engine/src/dns_service.py` (+
possibly a new `engine_set.py`), `filtering-engine/tests/*`,
`README.md`, `dashboard/README.md`, `filtering-engine/README.md`.
`engine_bridge.py` and `auth.py` likely unchanged.

---

## 12. Risks and unresolved decisions (need the owner's call)

1. **Unknown-source fallback policy.** Recommendation: keep today's
   behavior - sources with no registry match get the policy selected
   for publication (the default). Alternative: a strict block-all
   fallback. This changes real filtering behavior for any new device
   on the network, so it needs an explicit decision.
2. **Engine on staging.** The Oracle staging VM runs no DNS engine.
   Testing Stage 11 end to end on staging would require deploying the
   engine there (free, but a deployment change and a public DNS
   surface). Recommend keeping the engine local-test-only until a
   Stage 12 deployment decision.
3. **Resolver topology.** LAN-resident resolver (bindings can map to
   individual devices) vs hosted resolver (bindings are household/group
   at best). The charter's iPhone direction (hosted DoH/DoT) makes
   bindings group-level, which strengthens the case for the token
   stage. Confirm the intended first topology.
4. **IPv6 segment bindings.** Offer IPv6 /64 associations labeled as
   group/segment bindings (recommended, with the labeling), or leave
   IPv6 out of Stage 11 entirely. Not offered as individual identity
   either way.
5. **DHCP discipline is owner-side.** Bindings are only as stable as
   the network's address assignment. Router DHCP reservations for
   managed devices are recommended where a LAN resolver is used, but
   are the owner's home-router configuration, outside this repository.
6. **Override direction - RESOLVED (review correction 3).** The
   earlier revision offered "bindings may apply any policy, including a
   looser one" as an option. That option is removed: tighten-only is a
   mandatory security requirement, with restrictiveness decided by the
   deterministic comparison of 4.5 (never by names, labels, or rule
   counts), enforced server-side at assignment, at default-policy
   selection change, and at publication. A network binding may only
   apply a policy provably at least as restrictive as the default; a
   candidate that is less restrictive, incomparable, invalid, or too
   large to compare safely is rejected. Looser per-device filtering
   becomes possible only with authenticated identity (the token/DoH
   stage, 7.6, or MDM).
7. **Token/DoH identity as the next stage.** Recommended as the
   dedicated stage after 11 for genuine per-device enforcement (no
   Apple dependency). Confirm it stays out of Stage 11 scope.

---

## 13. Acceptance criteria for Stage 11

Stage 11 is complete only when ALL hold:

1. Registry CRUD, states, associations, and assignment APIs work with
   authorization, CSRF, validation, uniqueness, and audit coverage,
   proven by the new dashboard tests.
2. The engine resolves policies per source association (IPv4 and,
   if approved, IPv6 /64 group bindings), serves unmatched sources the
   default policy, rejects invalid generations wholesale, keeps
   last-known-good, and preserves legacy two-file generations - proven
   by engine tests, including the shared-binding group-behavior test.
3. One explicit publish produces one immutable multi-document
   generation; `config_status` detects unpublished assignment/binding
   changes; rollback restores complete historical generations - proven
   by publication tests.
4. End-to-end: assignment via the dashboard API -> publish -> real DNS
   answers from two simulated client sources differ as configured;
   reassignment and rollback change the answers back.
5. No client IP appears in any log or status file; no device secret
   appears in any API response, log, or audit entry.
6. **Identity honesty:** no UI string, API field, document, or log
   presents a network binding as an authenticated device identity;
   `identity_class` is stored and displayed; every device record
   honestly reports `management_status: unmanaged`; nothing claims
   enrollment, push, or remote management.
7. Full dashboard and engine suites pass on a fresh clone; README
   counts match reality; `main` remains untouched throughout.
8. **Identity-class enforcement (correction 1):** the database CHECK
   constraint rejects every invalid (kind, identity_class) combination
   even when the API is bypassed (direct SQL), proven by tests, and
   the migration path for future credential kinds is documented and
   test-covered.
9. **Canonical addressing (correction 2):** the 6.2 normalization,
   rejection, and duplicate-detection test matrix passes, and
   published generations contain only canonical binding keys.
10. **Tighten-only (correction 3):** the 4.5 comparison matrix
    passes; a less-restrictive, incomparable, invalid, or
    uncomparable candidate is rejected at assignment, at
    default-policy change, and at publication; the UI never decides
    the rule client-side.
11. **Three-state honesty (correction 4):** assigned, published, and
    enforced are returned and displayed distinctly; publication
    without an engine reports enforcement as unavailable; stale,
    missing, or inconsistent engine status is reported honestly; no UI
    state ever shows a saved assignment as enforced.

---

*Prepared as the Stage 11 planning deliverable. No Stage 11
implementation has begun; it waits for independent review and explicit
approval.*
