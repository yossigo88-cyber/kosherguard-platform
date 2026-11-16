# MDM / ADE Evaluation and Decision

Status: Milestone 4 design decision. Evaluates how KosherGuard implements its
own MDM server (spec Part 5) and Apple Business / Automated Device
Enrollment integration, per the approved 02:25 decision ("NanoMDM/NanoDEP
evaluation first").

Hard boundary for this whole milestone: no production Apple credentials
exist and none are requested here. Per
`docs/MDM_ENROLLMENT_AND_PUSH.md` (Stage 6 prerequisite audit, Nov 14, 2026),
all four Apple prerequisites are missing: (1) Apple has not selected
KosherGuard as a third-party MDM developer (Developer Program License
Agreement Attachment 10), (2) no MDM APNs push certificate exists, (3) the
Apple Business organization is "Not Qualified" with an unresolved account
conflict, (4) no approved test iPhone. Everything built in M4 is therefore
testable only against a simulated device/adapter; real-device enrollment,
push, and command delivery are explicitly untested and labeled as such.

## 1. Candidates evaluated

### NanoMDM (github.com/micromdm/nanomdm)

- Minimalist Apple MDM server written in Go; MIT license (verified against
  the repository LICENSE, copyright Jesse Peterson 2021). ~700 stars, active.
- Speaks the full Apple MDM check-in and command protocol over HTTPS:
  Authenticate, TokenUpdate, CheckOut, Acknowledged/Idle/Error/NotNow.
- Pluggable storage backends, with MySQL and PostgreSQL provided in the box.
  PostgreSQL matches our approved stack.
- Horizontal scaling: zero/minimal local state, all persistence in the
  storage layer. Multiple APNs topics, i.e. natively multi-tenant at the
  push level - matches our family-is-tenant model.
- API for enqueueing commands and sending pushes, including multi-command
  targeting across enrollments.
- Deliberately minimal: no DEP API access (NanoDEP covers that), no SCEP/ACME
  service, no TLS termination, no blueprints/automation, no admin UI. Those
  are exactly the layers our control plane already owns.

### NanoDEP (github.com/micromdm/nanodep)

- Go tools + library for Apple's Device Enrollment Program (ADE/DEP) API:
  token sync, device fetch, profile assignment. MIT license (verified).
- Covers the ABM/ASM side: syncing enrolled devices and assigning the MDM
  enrollment profile. `mdm/nanodep.py` implements the documented depserver
  contract (HTTP Basic auth, /v1/assigner, cursor-paginated device fetch and
  profile assignment through the transparent-auth /proxy/{name}/... path),
  contract-tested against a local fixture server. It is IMPLEMENTED but
  UNVERIFIED against Apple: no Apple Business organization, DEP tokens, or
  NanoDEP server exist yet, so no live call has ever been made.

### Alternatives considered and rejected

- Build the MDM protocol server from scratch in Python: the Apple MDM
  protocol (Plist XML payloads, per-device identity certs, APNs push topics,
  command lifecycle) is large, security-critical surface. Rebuilding it
  duplicates a maintained MIT implementation and multiplies audit burden.
- MicroMDM v1: legacy; NanoMDM is its maintained successor from the same
  author.
- Fleet (fleetdm): a full device-management product, not an embeddable MDM
  protocol server; far too heavy, and its own data model would fight our
  tenant model.
- Commercial MDM SaaS: contradicts the spec ("our own backend rather than
  relying on an external MDM provider") and adds unapproved cost.

## 2. Decision

Adopt **NanoMDM** as the MDM protocol server (Go sidecar, PostgreSQL
storage) and **NanoDEP** as the ADE/ABM sync tool. Our FastAPI control
plane remains the system of record for tenants, devices, policies, and
guardians, and orchestrates MDM through a narrow adapter interface.

## 3. Integration architecture

```
guardian -> admin dashboard -> control plane (FastAPI)
                                    |  owns tenants, devices, policies,
                                    |  command intent + status ledger
                                    v
                            MDMAdapter interface (mdm/)
                            |                       |
                    NanoMDMAdapter          SimulatedMDMAdapter
                    (HTTP API enqueue +     (in-process fake for
                     PostgreSQL status       tests; deterministic
                     reads)                  device responses)
                            |
                        NanoMDM (Go sidecar, PG storage)
                            |  APNs push per topic
                            v
                          iPhone
```

Command lifecycle we track in our own ledger (spec Part 5/6 requirement -
never report success just because a command was sent):
`queued -> delivered -> acknowledged | error | not_now`, with `applied`
recorded only from a positive device Acknowledged status plus, where
verifiable, a confirming query (e.g. ProfileList after InstallProfile).

## 4. What M4 builds now vs what stays blocked

Buildable now (this milestone):
- Control-plane MDM domain: devices, enrollments, commands with the full
  status lifecycle, last-seen tracking, per-tenant isolation + negative
  tests.
- `mdm/` adapter package: `MDMAdapter` interface, `NanoMDMAdapter` HTTP
  client (enqueue + push), `SimulatedMDMAdapter` for tests.
- Admin API endpoints to issue supported commands and read status.

Blocked until Apple prerequisites land (explicitly NOT built as live paths):
- APNs push certificate wiring, real enrollment-profile signing, real ADE
  sync, any command against a real device. No destructive MDM commands
  (erase) are implemented in this build at all.
