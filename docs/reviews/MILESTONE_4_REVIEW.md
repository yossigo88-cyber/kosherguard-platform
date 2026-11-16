# Milestone 4 Review - MDM / ADE Foundation

Date: November 16, 2026. Branch: full-platform-build.
Scope: spec Parts 5-6 foundation - own MDM server stack evaluation and
decision, control-plane MDM domain (enrollments, command lifecycle),
NanoMDM adapter interface, real NanoDEP depserver client, enrollment
profile builder, status reconciler, ADE sync planning + execution path,
admin dashboard MDM slice.

## What was built

1. **docs/evaluations/MDM_ADE_EVALUATION.md** - decision: NanoMDM (MIT,
   PostgreSQL storage, multi-topic APNs = tenant model fit) as the MDM
   protocol server, NanoDEP (MIT) for ADE/ABM sync. Rejected: from-scratch
   Python MDM (security surface), MicroMDM v1 (legacy), Fleet (too heavy,
   conflicting data model), commercial MDM SaaS (contradicts spec Part 5).
2. **mdm/adapter.py** - MDMAdapter interface, NanoMDMAdapter HTTP client,
   deterministic SimulatedMDMAdapter. Destructive commands (EraseDevice
   etc.) are absent by design.
3. **control-plane** - mdm_enrollments + mdm_commands tables (alembic
   0004), mdm_ops with mandatory tenant scoping, admin API endpoints,
   KG_NANOMDM_URL / KG_NANOMDM_API_KEY settings. Command lifecycle:
   queued -> delivered -> acknowledged | error | not_now; `applied` is
   set ONLY on a positive device Acknowledged status - never on a
   successful send (spec Part 5 requirement). Adapter failure returns
   the command to queued with the error recorded.
4. **mdm/reconciler.py** - read-only reconciliation from NanoMDM's
   PostgreSQL status storage into the ledger. Terminal statuses never
   re-opened; cross-tenant status rows refused.
5. **mdm/profiles.py** - unsigned .mobileconfig enrollment profile
   builder. https-only URLs enforced, ACME identity placeholder; the
   profile's own description states it is unsigned / not deliverable /
   not tested.
6. **mdm/ade.py + mdm/nanodep.py** - ADESyncPlan validation
   (tenant-scoped serials, unknown serials rejected) and a REAL NanoDEP
   depserver client implementing the documented wire contract
   (operations-guide.md): HTTP Basic auth depserver:<api-key>,
   /version, /v1/dep_names, GET/PUT /v1/assigner/{name}, and the
   transparent-auth /proxy/{name}/... path (GET account,
   cursor-paginated POST /devices, POST /profile/devices).
   NanoDEPSyncer executes plans: validate -> set assigner -> assign.
7. **control-plane/web** - admin MDM slice: enrollments table,
   enrollment creation, command issuing (supported set only), command
   history with honest status labels. The panel states enrollments stay
   pending until Apple prerequisites exist and no device was contacted.

## Test results (actual)

Local held tree (includes the unpublished, held per-tenant publication
fix + category wiring): control-plane 51 passed, mdm package 20 passed,
category-pipeline 6, proxy-edge 11, dns-edge 6.

Published tree, fresh clone of the exact SHA current at publish time
(4cc14b38): control-plane 48, mdm 20, pipeline 6, proxy 11, dns-edge 6,
all passing. The 51-vs-48 delta is exactly the 3 held tests.

Contract tests for NanoDEP run a local in-process fixture server on
127.0.0.1 implementing the documented contract: auth header asserted on
every call, wrong key -> 401, cursor pagination verified, assign body
shape verified, unreachable server raises cleanly. No external service
was contacted.

Admin UI verified visually (headless Chrome via CDP against a live
local instance): sign-in -> MDM panel renders with the dev-status note
-> command history shows queued / not-applied rows.

## Explicitly NOT proven / blocked (genuine external gates)

- No Apple MDM vendor approval, APNs push certificate, Apple Business
  organization, or test device exists (Stage 6 prerequisite audit).
  Therefore: no real enrollment, push, or command delivery has ever
  happened. SimulatedMDMAdapter results are test-only evidence.
- The NanoDEP client is IMPLEMENTED but UNVERIFIED against Apple: only
  fixture-server executions exist.
- Enrollment profiles are unsigned and undeliverable until the vendor
  certificate chain exists.

## Unresolved issues / remaining work

- Status reconciler is implemented against the documented NanoMDM
  storage shape; needs verification against a real NanoMDM deployment.
- last_seen tracking from real device check-ins (depends on NanoMDM).
- Multi-command targeting and per-tenant APNs topic mapping (NanoMDM
  supports multiple topics; wiring is M6 ops work).
- No destructive commands are implemented at all in this build.
