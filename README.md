# KosherGuard Platform

KosherGuard is an iPhone filtering and management platform under development. The intended platform is a central server, an administrator dashboard, website and category filtering, supported app restrictions, device enrollment, push-triggered policy updates, and recovery after device resets. What exists in this repository today is the backend filtering engine and the approved Stage 7 admin dashboard (see Status below).

## Status

The core filtering engine (Stage 5, full testing and verification) is complete in [filtering-engine/](filtering-engine/README.md): the central policy engine, the DNS filtering service (UDP and TCP), the website category database, structured decision logging, and a 119-test automated suite. Device enrollment, push-triggered policy updates, iPhone management, and reset recovery described in the [project charter](docs/PROJECT_CHARTER.md) are not built yet. Nothing in this repository currently filters or manages an iPhone; there is no Apple commercial MDM authorization and no real-device test environment (see the [technical investigation](docs/GENTECH_TECHNICAL_INVESTIGATION.md)).

Stage 7 (the [admin dashboard](dashboard/README.md)) is complete and approved at commit ad999b739075364dc05191bd95c2c500cad2a3e9: a development application (stdlib Python backend API, SQLite storage, session authentication, audit logging, browser interface) for managing filtering policies, categories, and domain records. Stage 9A hardened it (configurable Secure cookies with a deployment guard, trusted-proxy login limiting, a 12-character password minimum, failed-login auditing, expired-session cleanup, a health endpoint, strict request-body validation, and bounded request handling with a total request deadline); the dashboard now has a 120-test automated suite. Stage 9B added deployment preparation (a runbook and pre-launch checklist in docs/deployment/, Caddy and systemd examples and backup/restore scripts in deploy/); nothing is deployed. Policy evaluation is performed by the existing filtering engine. The dashboard manages local policy data only: no devices are enrolled, no Apple MDM connection exists, and no remote policy push is available. It is not deployed anywhere.

Stage 6 (iPhone enrollment and push notifications) was attempted as a preparation stage. The prerequisite audit found that none of the four required Apple prerequisites exist (Apple MDM vendor selection, an MDM APNs push certificate, Apple Business enrollment credentials, and an approved test iPhone), so no MDM, enrollment, or push code was written. The architecture, required credentials, security requirements, enrollment and push flows, and exact remaining blockers are documented in [docs/MDM_ENROLLMENT_AND_PUSH.md](docs/MDM_ENROLLMENT_AND_PUSH.md).

## Documents

- [Project charter](docs/PROJECT_CHARTER.md) - goals, scope, and working principles
- [Repository handoff test](docs/REPO_HANDOFF_TEST.md) - initialization record for this repository
- [MDM enrollment and push preparation](docs/MDM_ENROLLMENT_AND_PUSH.md) - Stage 6 prerequisite audit, architecture, and blockers
- [Admin dashboard](dashboard/README.md) - Stage 7 dashboard: architecture, security model, and development instructions

## Repository rules

- GitHub is the permanent source of truth for the project.
- No passwords, API keys, certificates, or other secrets in this repository.
- This is a brand-new project; nothing is imported or copied from earlier projects.
