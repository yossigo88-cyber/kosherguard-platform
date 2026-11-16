# KosherGuard Requirements Coverage

Tracks every requirement of the 20-part specification (January 16, 2026
01:36 EST message), the approved Milestones 1-8, and the 22 final
deliverables of Part 18. Statuses are honest: DONE means implemented and
tested in this branch; IN PROGRESS means started; PLANNED means assigned
to a milestone; BLOCKED-BY-APPLE means it needs production Apple
credentials or a real device, which are out of scope for this build;
SUPERSEDED means the requirement was met by an earlier stage whose
artifact is preserved on an old branch.

Legend: [ ] not started, [~] in progress, [x] done in this branch,
[B] blocked by Apple credentials/device access, [S] superseded/preserved
on an earlier branch.

## Milestone map

- M1: Foundation - security fix, architecture, control-plane foundation
  (auth, MFA, tenancy, audit, rate limiting)
- M2: Control plane complete - API, portal, admin dashboard, public website
- M3: Policy compiler, DNS edge, proxy-PAC, category pipeline
- M4: MDM/ADE (NanoMDM/NanoDEP evaluation), enrollment architecture
- M5: Native iOS (Swift, uncompiled/unsigned/untested) + URL-filter servers
- M6: Operations - logging, monitoring, backups, recovery
- M7: Full testing - unit, integration, end-to-end, security negatives
- M8: Final delivery - documentation, limitation list, handoff

## Part-by-part coverage

| Part | Requirement | Status | Milestone | Notes |
| ---- | ----------- | ------ | --------- | ----- |
| 1 | Product inventory (16 numbered systems) | [~] | M1-M8 | Each item maps to a row below |
| 1.1 | Apple Business Manager integration | [B] | M4 | Server-side code + instructions; no production Apple credentials in this build |
| 1.2 | Own Apple MDM server | [ ] | M4 | NanoMDM/NanoDEP evaluation planned |
| 1.3 | Automated iPhone enrollment | [ ] | M4 | ADE flow; real enrollment BLOCKED-BY-APPLE |
| 1.4 | Non-removable device management | [ ] | M4-M5 | Supervised-mode profile configuration |
| 1.5 | Factory-reset restrictions | [ ] | M4-M5 | Restrictions payload design |
| 1.6 | Re-enrollment after restore | [ ] | M4 | ADE re-assignment architecture |
| 1.7 | Apple push integration | [B] | M4 | APNs client code; production certs out of scope |
| 1.8 | Remote device management | [ ] | M4 | Command queue with audit |
| 1.9 | Remote config/policy updates | [~] | M2-M3 | Publication pipeline |
| 1.10 | Own internet filtering engine | [x] | M1 | Adapted engine; symlink fix done, 337 tests pass |
| 1.11 | Website and application filtering | [ ] | M3-M5 | DNS + PAC + URL-filter server |
| 1.12 | Central administration dashboard | [ ] | M2 | New front end on the control plane |
| 1.13 | Customer and device management | [~] | M1-M2 | Tenant/device registry in control plane |
| 1.14 | New customer-facing website | [ ] | M2 | website/ tree; live replacement out of scope |
| 1.15 | Secure backend and database | [~] | M1 | FastAPI + PostgreSQL foundation |
| 1.16 | Logging, monitoring, backups | [ ] | M6 | |
| 2 | ABM + automated enrollment | [B] | M4 | As 1.1-1.3 |
| 3 | Non-removable MDM from day one | [ ] | M4-M5 | Includes the fixed Stage 11C loader on the engine side |
| 4 | Factory reset protection | [ ] | M4-M5 | ADE re-enrollment design |
| 5 | Own MDM server | [ ] | M4 | |
| 6 | Remote management + policy updates | [~] | M2-M4 | |
| 7 | APNs | [B] | M4 | |
| 8 | Filtering engine | [x] | M1, M3 | Engine adapted; compiler in M3 |
| 9 | Category database | [ ] | M3 | Seed dataset with provenance records |
| 10 | Administration dashboard | [ ] | M2 | |
| 11 | Customer-facing website | [ ] | M2 | Steps 1-6 only; step 7 (live replacement) out of scope |
| 12 | Customer accounts + multi-tenancy | [~] | M1-M2 | Family=tenant, multi-guardian |
| 13 | Database and backend | [~] | M1 | PostgreSQL + Alembic |
| 14 | Security | [~] | M1-M7 | MFA, hashed sessions, tenant isolation, redaction |
| 15 | Hosting and infrastructure | [ ] | M6 | Configuration only, no deployment |
| 16 | Apple credentials and setup | [B] | M4, M8 | Instructions deliverable |
| 17 | Testing | [~] | M7 | Suites run per milestone; full pass in M7 |
| 18 | Final deliverables (22) | [~] | M8 | Itemized below |
| 19 | Development rules | [x] | M1-M8 | Followed throughout; review reports per milestone |
| 20 | Pre-build assignment | [S] | - | Completed before this build (44 answers); preserved in docs/reviews |

## Part 18 - the 22 deliverables

| # | Deliverable | Status | Milestone | Notes |
| - | ----------- | ------ | --------- | ----- |
| 1 | Complete source code | [~] | M1-M8 | This branch |
| 2 | Complete MDM server | [ ] | M4 | |
| 3 | Apple enrollment integration | [B] | M4 | Code + instructions; no production credentials |
| 4 | Remote device management | [ ] | M4 | |
| 5 | APNs integration | [B] | M4 | Client code only |
| 6 | Non-removable enrollment configuration | [ ] | M4-M5 | Profile/payload design |
| 7 | Factory-reset restrictions | [ ] | M4-M5 | |
| 8 | Automatic re-enrollment architecture | [ ] | M4 | |
| 9 | Filtering engine | [x] | M1 | Adapted, 337 tests pass |
| 10 | Filtering policy database | [ ] | M3 | |
| 11 | Administration dashboard | [ ] | M2 | |
| 12 | Customer management | [~] | M1-M2 | |
| 13 | Customer-facing website | [ ] | M2 | |
| 14 | Database and migrations | [~] | M1 | Alembic |
| 15 | Hosting and deployment configuration | [ ] | M6 | Config only |
| 16 | Security implementation | [~] | M1-M7 | |
| 17 | Monitoring and logging | [ ] | M6 | |
| 18 | Backup and recovery | [ ] | M6 | |
| 19 | Apple integration instructions | [B] | M8 | Documentation |
| 20 | Testing results | [~] | M7 | Per-milestone review reports |
| 21 | Documentation | [~] | M1-M8 | This doc, architecture doc, reviews |
| 22 | List of remaining limitations | [~] | M8 | Accumulated in every milestone review |

## Test-count reconciliation (Milestone 1)

- filtering-engine: 337 passed (316 pre-existing + 21 new symlink
  regression tests). Baseline before the fix was also 316 - the fix broke
  nothing.
- dashboard (reference tree): 276 passed, matching the collected count.
- Control-plane suite: created in this milestone; counts recorded in the
  Milestone 1 review report.
