# Enrollment tickets and device identity (Answer 28)

Requirement (user answer 28, 2026-11-16 02:17): staff-assisted
enrollment uses short-lived, single-use tickets; tenant and device
assignment must be validated; a device identity certificate should be
checked; enrollment status is tracked; tickets expire and cannot be
replayed; everything is audited. "A serial number alone is not proof."
Test rule 14: invalid tickets and identity certificate cases must be
tested.

## What is implemented

`control-plane/app/enrollment_routes.py`, model `EnrollmentTicket`,
migration `0018_enrollment_tickets.py`.

- **Issue** - `POST /api/mdm/devices/{id}/enrollment-tickets`
  (owner or guardian with `devices` delegation, CSRF header required).
  Creates a ticket bound to THIS tenant and THIS active device, with a
  caller-chosen lifetime of 5 minutes to 24 hours (default 60). The raw
  token is returned once and never stored or logged; only its SHA-256
  hash is kept.
- **List / revoke** - `GET /api/mdm/enrollment-tickets`,
  `DELETE /api/mdm/enrollment-tickets/{id}`. Tenant-scoped; a used or
  already-revoked ticket cannot be revoked again.
- **Redeem** - `POST /api/mdm/enroll` (unauthenticated by design: the
  single-use token IS the redemption authentication, and the ticket's
  tenant+device binding is the assignment validation). The row is
  locked `FOR UPDATE`; invalid, expired, revoked and already-used
  tickets are rejected (403/410/409). A concurrent double redeem
  succeeds exactly once (tested with a barrier-raced disposable
  PostgreSQL test).
- **Device identity** - on redeem, the device UDID binds the pending
  enrollment. A second ticket redeemed with a DIFFERENT UDID against an
  existing pending/enrolled record conflicts (409) - a serial number
  or a bare claim never re-binds identity. The same UDID re-binds
  cleanly (re-issue after a failed setup).
- **Identity certificate** - an optional PEM certificate presented at
  redemption is checked by `control-plane/app/certificate_ops.py`:
  parse + expiry (hard reject), subject CN / SAN must contain the
  device UDID (hard reject), and `openssl verify` chain validation
  against `KG_DEVICE_IDENTITY_CA_FILE` when configured (hard reject on
  failure). Without a configured CA the certificate is recorded as
  `chain_unverified` - parsed and bound, NOT cryptographically
  anchored. The fingerprint and status are stored on the enrollment
  for audit and later re-verification.
- **Audit** - issue, revoke and redeem each write an audit event with
  the actor (redeem records the issuing staff member) and the details.

## Honest limits

- No device identity CA ships with this build. Chain verification runs
  only when `KG_DEVICE_IDENTITY_CA_FILE` points at a real CA bundle;
  until then certificates are recorded `chain_unverified` and the
  ticket itself remains the authentication.
- Redemption records the pending enrollment and binds the UDID; the
  actual Apple enrollment still completes through the existing MDM
  check-in path, which upgrades the record as before.
- Verification parses with the stdlib decoder (`ssl._ssl._test_decode_cert`)
  and chains with the `openssl` CLI - no new Python dependencies.

## Tests

`control-plane/tests/test_enrollment_tickets.py` (14 tests): issue
gating (viewer 403, cross-tenant device 404), issue+list (raw token
never listed), redeem success, invalid/expired/revoked/replayed
tickets, concurrent double redeem (exactly one succeeds, exactly one
enrollment row), UDID conflict and same-UDID rebind, and certificates:
CA-signed verified, no-CA chain-unverified, expired rejected,
wrong-UDID rejected, self-signed rejected when a CA is configured
(cryptography-generated fixtures, `openssl verify` chain check).
