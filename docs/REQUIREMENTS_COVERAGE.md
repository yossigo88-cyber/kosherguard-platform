# KosherGuard Requirements Coverage

Tracks every requirement of the 20-part specification (January 16, 2026
01:36 EST message), the approved Milestones 1-8, and the 22 final
deliverables of Part 18. Statuses are honest: DONE means implemented and
tested on this branch at the layer this environment can exercise;
BLOCKED-BY-APPLE means the remaining step needs production Apple
credentials, an Apple Developer Program membership, Xcode, or a physical
supervised device (Answers 36/40: none of these exist in this build);
OUT-OF-SCOPE means the user excluded it (live website replacement, DNS
changes, deployment).

Legend: [ ] not started, [~] in progress / partially implemented,
[x] done and tested on this branch (with the tested layer named),
[B] blocked by Apple credentials/device access, [O] out of scope by
user instruction.

Current verification state (all suites green at the head this file
ships with): control-plane 364, filtering-engine 337, dns-edge 87,
mdm 64, proxy-edge 38, url-filter-server 38, category-pipeline 6,
dashboard 276 - 1,210 tests total, plus three committed load-test
harnesses (docs/reviews/LOAD_TEST.md).

## Milestone map (all eight complete through this branch)

- M1: Foundation - control-plane foundation (auth, TOTP MFA, tenancy,
  audit, rate limiting), engine symlink fix. DONE
- M2: Control plane complete - API, portal UI, admin dashboard, public
  website tree. DONE
- M3: Policy compiler, DNS edge, proxy/PAC, category pipeline. DONE
- M4: MDM/ADE server-side (adapter, APNs client, profiles, reconciler,
  app management, NanoDEP client), enrollment architecture. DONE at the
  server layer; live Apple operation [B]
- M5: Native iOS (Swift, uncompiled/unsigned/untested [B]) + URL-filter
  server (38 tests). DONE except the Apple-blocked native app
- M6: Operations - structured request logs (no secrets), /health/depth,
  staff-only /metrics, backup/restore runbook + tested scripts. DONE
- M7: Full testing - 1,210 automated tests across 8 components, security
  negatives, tenant isolation, concurrency, load harnesses. DONE
- M8: Final delivery - documentation, limitation list, handoff. IN
  PROGRESS (this refresh; final security report and handoff package)

## Part-by-part coverage

| Part | Requirement | Status | Notes |
| ---- | ----------- | ------ | ----- |
| 1 | Product inventory (16 numbered systems) | [x] | Each item maps to a row below |
| 1.1 | Apple Business Manager integration | [B] | `mdm/ade.py` + `mdm/nanodep.py` ADE/DEP client code with tests; no production Apple credentials exist |
| 1.2 | Own Apple MDM server | [x] server-side | `mdm/` package (adapter, APNs client, profiles, reconciler, app management), 64 tests; device push path built-unverified |
| 1.3 | Automated iPhone enrollment | [x] server-side, [B] live ADE | Enrollment tickets + tests (`test_enrollment_tickets.py`, incl. concurrency); real ADE assignment needs Apple |
| 1.4 | Non-removable device management | [x] payloads, [B] device | Supervised-mode profile payloads in `mdm/profiles.py`; removal-prevention is a device behavior |
| 1.5 | Factory-reset restrictions | [x] payloads, [B] device | Restrictions payload set in `mdm/profiles.py` |
| 1.6 | Re-enrollment after restore | [x] server flow, [B] ADE | Restore readiness + attestation endpoints (`restore_routes.py`, `restore_attestations` table, tests) |
| 1.7 | Apple push integration | [B] | `mdm/apns.py` client code; production APNs certificates out of scope |
| 1.8 | Remote device management | [x] server-side | MDM command queue with audit, two-person approval for destructive commands (Answer 25), staff troubleshooting query limits (Answer 29) |
| 1.9 | Remote config/policy updates | [x] | Publication pipeline with immutable generations + atomic flip; propagation measured (median 139 ms in-environment, docs/reviews/LOAD_TEST.md) |
| 1.10 | Own internet filtering engine | [x] | `filtering-engine/`, 337 tests; symlink fix + regression tests from M1 |
| 1.11 | Website and application filtering | [x] server-side | DNS engine + dns-edge DoH (87), proxy/PAC (38), per-device app policy + install/remove commands (`mdm/app_management.py`, control-plane app-policy APIs) |
| 1.12 | Central administration dashboard | [x] | `control-plane/web/` portal (policies, groups, exceptions, schedules, devices, MDM, categories, customers, credentials, guardians, approvals, staff, filtering, apps, audit) + `dashboard/` tree (276 tests); UI e2e verified with local headless browser incl. mobile 390px |
| 1.13 | Customer and device management | [x] | Tenants, guardians (invite/delegation/role/MFA-reset), devices, groups; staff customers view is names+counts only (tenant isolation); customer-tenant onboarding via staff-owner-only POST /api/staff/tenants (7-day hashed owner invite, audited) with staff-panel Add customer form |
| 1.14 | New customer-facing website | [x] tree, [O] live swap | `website/` built and copy-reviewed (privacy/support pages match actual collection/retention); replacing the live site is a separate approval (Part 2 question 15) |
| 1.15 | Secure backend and database | [x] | FastAPI + PostgreSQL, Alembic migrations 0001-0024, hashed sessions, TOTP MFA, CSRF header checks, tenant scoping |
| 1.16 | Logging, monitoring, backups | [x] | JSON request logs without secrets, /health/depth (503 on failure), staff-only /metrics, audit events; backup/restore runbook + scripts tested (`test_backup_restore.py`) |
| 2 | ABM + automated enrollment | [B] live, [x] code | As 1.1-1.3 |
| 3 | Non-removable MDM from day one | [x] design+payloads, [B] device | Profile/restriction payloads; engine loader fixed (M1) |
| 4 | Factory reset protection | [x] design, [B] device | ADE re-enrollment architecture + restore attestation |
| 5 | Own MDM server | [x] server-side | As 1.2 |
| 6 | Remote management + policy updates | [x] | As 1.8/1.9 |
| 7 | APNs | [B] | Client code only |
| 8 | Filtering engine | [x] | 337 tests |
| 9 | Category database | [x] | `category-pipeline/` (taxonomy, provenance, builder, 6 tests) + registry-managed category sources with review/activate/rollback, hash-bound imports, two-person activation gates, file sync integrity (control-plane category-source suite) |
| 10 | Administration dashboard | [x] | As 1.12 |
| 11 | Customer-facing website | [x] tree, [O] step 7 | Steps 1-6; live replacement is a separately-approved step |
| 12 | Customer accounts + multi-tenancy | [x] | Family=tenant, multi-guardian with owner-delegated capabilities and protected baseline; tenant-isolation tests. Part 2A customer portal: secure sign-in (MFA), authorized devices with enrollment/supervision state, online/offline/stale connectivity from stored receipts, last confirmed update, current filtering policy with schedules, permitted delegated settings, structured exception requests (approve/reject creating real audited PolicyExceptions under the requester's delegable limits), support requests |
| 13 | Database and backend | [x] | As 1.15 |
| 14 | Security | [x] | MFA everywhere privileged (fresh TOTP + typed confirmation for sensitive ops), hashed sessions, tenant isolation, read_only staff choke point, credential redaction, security-negative tests; final security report pending in M8 |
| 15 | Hosting and infrastructure | [x] config, [O] deploy | `deploy/` + `render.yaml` configuration; no deployment performed or authorized |
| 16 | Apple credentials and setup | [B] | `docs/MDM_ENROLLMENT_AND_PUSH.md` + setup instructions deliverable |
| 17 | Testing | [x] | 1,210 tests green at head across 8 components; load harnesses + smoke tests; filtering-coverage, tenant-isolation, security-negative, concurrency suites all present |
| 18 | Final deliverables (22) | [~] | Itemized below |
| 19 | Development rules | [x] | Logical commits on `full-platform-build`; main untouched; per-area review docs in `docs/reviews/` |
| 20 | Pre-build assignment | [S] | Completed before this build (44 answers); preserved in docs/reviews |

## Part 18 - the 22 deliverables

| # | Deliverable | Status | Notes |
| - | ----------- | ------ | ----- |
| 1 | Complete source code | [x] | This branch, all components |
| 2 | Complete MDM server | [x] server-side, [B] live | `mdm/` 64 tests; live operation needs Apple |
| 3 | Apple enrollment integration | [B] live, [x] code | ADE client + tickets; no production credentials |
| 4 | Remote device management | [x] server-side | Command queue, approvals, audit |
| 5 | APNs integration | [B] | `mdm/apns.py` client code |
| 6 | Non-removable enrollment configuration | [x] payloads, [B] device | `mdm/profiles.py` |
| 7 | Factory-reset restrictions | [x] payloads, [B] device | `mdm/profiles.py` |
| 8 | Automatic re-enrollment architecture | [x] design+server flow | Restore attestation; ADE reassignment [B] |
| 9 | Filtering engine | [x] | 337 tests |
| 10 | Filtering policy database | [x] | `category-pipeline/` + registry category sources |
| 11 | Administration dashboard | [x] | Portal UI + `dashboard/` (276 tests) |
| 12 | Customer management | [x] | Tenants/guardians/staff customers view; staff-owner tenant onboarding endpoint + Add customer UI |
| 13 | Customer-facing website | [x] tree, [O] live | `website/`; live swap separately approved |
| 14 | Database and migrations | [x] | Alembic 0001-0023 |
| 15 | Hosting and deployment configuration | [x] config, [O] deploy | `deploy/`, `render.yaml` |
| 16 | Security implementation | [x] | As Part 14 |
| 17 | Monitoring and logging | [x] | Observability endpoints + structured logs (dd0518d) |
| 18 | Backup and recovery | [x] | Runbook + scripts + tests (56a08f9) |
| 19 | Apple integration instructions | [x] | `docs/MDM_ENROLLMENT_AND_PUSH.md`, `docs/setup/` |
| 20 | Testing results | [x] | This file's counts; per-area review docs; docs/reviews/LOAD_TEST.md |
| 21 | Documentation | [x] | Architecture doc, reviews/, COMPATIBILITY.md, LOAD_TEST.md, BACKUP_RECOVERY.md |
| 22 | List of remaining limitations | [~] | Accumulated in reviews; final consolidated list ships with the M8 security report |

## Test-count reconciliation (current head)

- control-plane: 343 (179+164 in the two-suite batch split)
- filtering-engine: 337
- dns-edge: 87
- mdm: 64
- proxy-edge: 38
- url-filter-server: 38
- category-pipeline: 6
- dashboard: 276 (164+112 batched)
- Total: 1,189, all green at the head this file ships with; per-SHA
  evidence is in the session reports and docs/reviews/.
