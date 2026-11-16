# Offboarding process (Answer 24)

Requirement (user answer 24, 2026-11-16 02:17): a documented, verified
offboarding process handling customer identity/ownership verification,
customer cancellation, device sale or transfer, loss of authority over
a device, ownership disputes, MDM unenrollment or authorized release,
Apple Business/ADE assignment changes, data deletion and retention,
and Activation Lock considerations. "Do not permanently lock a device
because of nonpayment. Do not automatically erase a device or release
it from Apple Business."

## What is implemented

`control-plane/app/offboarding_routes.py`, model `OffboardingCase`,
migration `0019_offboarding_cases.py`.

A case records the verified process end to end:

1. **Create** - `POST /api/offboarding/cases` (owner only). Kinds:
   `cancellation`, `transfer`, `loss_of_authority`, `dispute`.
   Transfer and loss-of-authority require a device of the same tenant.
2. **Ownership verification** - `POST .../verify`: the tenant owner
   re-verifies with a CURRENT MFA code plus explicit confirmation
   (`verify-offboarding`) before anything can complete. This is the
   recorded customer identity/ownership verification step.
3. **Attestations** - `POST .../attest` (`activation_lock`,
   `abm_release`), each with fresh MFA confirmation. These record that
   the MANUAL Apple-side steps (clearing Activation Lock on the
   device, releasing the device in Apple Business) were performed.
   They are attestations, not executed changes: this build has no
   Apple credentials and never touches ABM/ADE or the device lock
   state. Activation Lock considerations and ABM/ADE assignment
   changes are therefore handled as recorded manual steps, and MDM
   unenrollment remains a separate, already gated action
   (two-person approval for destructive commands) - never automatic.
4. **Complete** - `POST .../complete` performs the
   environment-feasible orchestration HERE (not just attestations),
   for device kinds (transfer / loss_of_authority): deactivates the
   device's policy assignments, marks its enrollment records
   `offboarded`, revokes its outstanding issued credentials, and
   deletes the departing device's filter-decision rows (actual data
   deletion); `data_retention_until` is stamped from the tenant's
   configured retention policy. Cancellation touches NO device -
   nonpayment must never revoke protection. Disputes additionally
   require resolution notes; transfers require both attestations;
   loss-of-authority requires the ABM attestation.
5. **Cancel** - `POST .../cancel` any time before completion.

Every transition writes an audit event with the acting user.

## Hard rules enforced by code and tests

- Nonpayment cancellation completes with NO device effects: no lock,
  no erase, no ABM release, and zero MDM commands issued by the case
  flow (`test_cancellation_completes_without_device_effects` asserts
  the command table stays empty).
- Nothing auto-erases or auto-releases: the only destructive MDM path
  remains the separately gated two-person approval flow.
- Attestation is never counted as executed orchestration: completion
  performs the local orchestration listed above and the docs/tests
  keep the two distinct.

## Runtime boundaries (verified by tests)

- **Access stop is real, not attested**: completion of a device case
  revokes the device's outstanding scoped credentials (edge verifiers
  refuse revoked jtis via the revocation feed), deactivates its
  assignments, offboards its enrollment records and purges its
  filter-decision rows. Tested end to end.
- **No silent reactivation**: the authenticated DDM path authorizes
  only `enrolled`/`active` states, so an `offboarded` enrollment is
  refused even with valid HMAC; new enrollment tickets refuse an
  offboarded device (a fresh authorized enrollment requires an
  explicit guardian/owner step). Tested.
- **No fallback to tenant default for a departed device**: with
  credentials revoked the edge refuses the device outright; the
  tenant default policy in the device map is only reachable with a
  valid credential.
- **Nonpayment never revokes protection**: cancellation completes
  with assignments active, enrollment untouched, credentials
  unrevoked, device state unchanged and zero MDM commands - tested
  with a device attached.
- **Publication stays clean**: the case flow never publishes; bundle
  generation remains the separately gated publish flow, which ships
  published policy state plus the current device map (deactivated
  assignments drop out) - never unrelated drafts.

## Tests

`control-plane/tests/test_offboarding.py` (14 tests): lifecycle,
owner-only gating (viewer 403), cross-tenant isolation (404 + empty
list), fresh-MFA verification required, completion blocked before
verification, transfer attestation requirements, full local
orchestration effects (assignments, enrollments, credential
revocation, log purge), DDM reactivation refusal, dispute resolution
notes, cancel flow, and the nonpayment hard rule with a device
attached.
