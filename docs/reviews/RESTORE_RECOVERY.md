# Restore and backup recovery (Answers 26 + 37)

Answer 26's recovery model, and what implements it:

1. **A legitimate computer-based restore may erase the iPhone.** That
   erasure happens on the customer's computer (Finder / Apple Devices
   for Windows / recovery mode / DFU) - outside this platform. Device
   testing of those paths stays Apple-gated and is listed under
   external validation, never claimed as tested here.
2. **The device remains assigned to the correct Apple Business/ADE
   organization.** This build has no Apple credentials, so this step
   is a recorded guardian attestation
   (`POST /api/mdm/devices/{id}/restore-attest`, explicit
   confirmation), never an executed change.
3. **During activation and Setup Assistant the device must re-enroll.**
   Re-enrollment runs the same ticket + authenticated DDM check-in
   flow as initial enrollment (Answer 28); an offboarded enrollment is
   never silently reactivated.
4. **Baseline management and filtering configuration are restored.**
   The readiness check verifies an ACTIVE policy assignment and an
   unrevoked filtering credential for the device.
5. **Setup is released only after the required checks succeed.**
   `GET /api/mdm/devices/{id}/restore-readiness` computes the live
   checklist (ABM attested, re-enrolled, baseline assignment active,
   filtering credential issued) and reports setup_release_ready only
   when every check is green. It is a report; nothing touches the
   device.

**Account boundaries** (from the answer): customers keep control of
their Apple Accounts and personal credentials; the platform never
shares Apple Accounts and never modifies customer backups. Find My,
Activation Lock, backup restoration and eSIM behavior are Apple-side
limitations - a restored phone is NOT promised to activate when Apple
services, network access, credentials or account ownership prevent it.

**Uptime/recovery targets** (Answer 37): no SLA is promised before the
service is deployed, measured and funded. The proposed production
planning targets - recovery within one hour, 15-minute database
recovery-point objective - remain future targets subject to budget and
successful recovery testing. The development environment is
best-effort. Database backup/restore procedures and restoration tests
are tracked in the backup/restore cluster.

## Tests

`control-plane/tests/test_restore.py`: readiness requires every check
(live state for enrollment/assignment/credential, attestation for
ABM), attestation requires explicit confirmation, cross-tenant
isolation.
