# Account roles, MFA, sessions, and account recovery

Requirement sources: spec Answer 29 (five account roles, MFA for
privileged accounts, least privilege, session management, audit logs,
documented account recovery, staff configured later) and Answer 25
(sensitive device commands: fresh verification, explicit confirmation,
two-person approval for especially destructive operations).

## The five roles

| Role | Where it lives | Capabilities |
| --- | --- | --- |
| Owner | `users.staff_role = 'owner'` | Full platform control: staff management, category dataset, all security-admin capabilities, sensitive-op request/approve. |
| Security administrator | `users.staff_role = 'security_admin'` | Security policy surface: category dataset, sensitive-op request/approve, support queries. No staff management. |
| Support administrator | `users.staff_role = 'support_admin'` | Limited troubleshooting only: tenant list, read-only MDM query commands (`DeviceInformation`, `ProfileList`, `InstalledApplicationList`, `ManagedApplicationList`). No policy, category, profile, or destructive changes - even if the same account also holds a tenant owner role. |
| Customer/parent administrator | tenant `Role.owner` / `Role.guardian` | Policy and account functions for their own tenant: policies, schedules, groups, devices, publications (per delegation), guardians. This is a tenant role, not a staff role. |
| Read-only operator | `users.staff_role = 'read_only'` | Viewing authorized information only (tenant list/overview reads). Cannot issue any command or change anything - even if the same account also holds a tenant owner role. |

Least privilege: every staff endpoint names the exact staff roles it
accepts (`require_staff`); a staff role outside the list gets 403.
Support/read-only restrictions win over any tenant-side role the same
account happens to hold.

Staff are not assumed to exist: a single owner is enough to run the
platform, and authorized contacts are configured later via
`POST /api/staff/{user_id}/role` (owner only; the last staff owner
cannot be demoted or revoked). `is_platform_admin` is retired: alembic
0017 maps legacy rows to `staff_role = 'owner'` and new code reads
`staff_role` only.

## MFA and sessions

- Every staff account (any of the four staff roles) and every tenant
  owner/guardian must enroll TOTP MFA. A password-only login is a
  restricted enrollment session: only `/api/auth/me`, logout,
  enrollment and password-change paths work until MFA is enrolled and
  the session is MFA-verified. Tenant viewers are the only
  unprivileged accounts.
- Sessions store only token hashes, expire after the configured
  lifetime, and record whether MFA was verified at login.
- Login lockout throttles repeated failures per email+IP.

## Sensitive operations: two-person approval (Answer 25)

Especially destructive operations - `EraseDevice` (remote erase),
`ABMRelease`, `ProtectionRemoval`, `CertificateOperation` - are not
issuable directly. The adapter refuses them outside the approval flow
(`mdm_ops.issue_command(..., allow_destructive=False)` raises).

Flow:

1. **Request** (`POST /api/mdm/enrollments/{pk}/commands` with a
   destructive command): requires a tenant owner or staff
   owner/security_admin, a **fresh** TOTP code (independent of the
   session), `confirm` equal to the operation name, and a reason.
   Nothing is queued to the device; a `sensitive_command_approvals`
   row is created, valid for 1 hour.
2. **Approval** (`POST /api/mdm/sensitive-approvals/{id}/approve`):
   requires a DIFFERENT privileged user (the requester approving their
   own request is refused, 403), again with a fresh TOTP code and the
   confirmation string. Only then is an `EraseDevice` command queued
   to the device. `ABMRelease`, `ProtectionRemoval` and
   `CertificateOperation` have no live integration in this build: an
   approval is the audited authorization record, and an operator
   performs the external step per the runbook - the decision detail
   says so explicitly.
3. **Reject / expiry**: any privileged user can reject with a reason;
   expired requests cannot be approved (410) and move to `expired`.

Every transition writes an audit event naming the real actor.
Because two distinct privileged users are required, a deployment that
wants destructive capability must configure a second privileged staff
contact (owner or security administrator) - consistent with Answer
29's "authorized contacts configured later."

Authority and binding guarantees (tested synthetically, never against
real devices):

- Authority is re-validated at approval time, not inherited from
  request time: the approver must currently be privileged, and the
  REQUESTER's authority is re-checked too - if the requester was
  demoted while pending, the approval is voided (409) and must be
  re-made. An approver demoted while pending gets 403.
- Execution is bound to the exact operation, target enrollment, tenant
  and payload recorded on the request; the approval request body
  cannot redirect it (the confirmation string must name the recorded
  operation).
- Single-use: the row is locked FOR UPDATE during decision and the
  status guard refuses any second decision (409), so concurrent
  approvers cannot double-execute. Verified against disposable
  PostgreSQL with two barrier-synchronized approvers racing the same
  pending request: exactly one executes (200), the other gets 409, and
  exactly one device command is queued
  (test_concurrent_double_approval_single_use).
- Cross-tenant: approvals are only visible/decidable inside their own
  tenant (404 outside).

## Audit logs

Append-only `audit_events` per tenant record auth events, MFA
enrollment/reset, staff role changes (`staff.role.change`), sensitive
requests/approvals/rejections (`mdm.sensitive.*`), category
administration, and publications.

## Account-recovery procedures

- **Tenant guardian loses MFA**: a tenant owner resets it via
  `POST /api/guardians/{user_id}/mfa-reset` (audited). The guardian
  re-enrolls on next login.
- **Tenant owner loses access**: another owner or an owner-delegated
  guardian flow applies; if the tenant has a single owner, recovery is
  an out-of-band platform-staff procedure (staff owner verifies the
  customer's identity through the established support channel, then
  resets MFA or password; every step is audited).
- **Staff account loses MFA**: a staff owner resets the staff member's
  secret out of band; the member re-enrolls.
- **Sole staff owner loses access**: there is no self-service reset -
  recovery is a documented operator procedure: direct database update
  of the owner row from the operator host (clear `totp_secret`, force
  re-enrollment on next login), recorded in the operator log. Refusing
  automated reset here is deliberate, not a solved self-service story.
