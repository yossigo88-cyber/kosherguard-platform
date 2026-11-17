# Stage 6: iPhone Enrollment and Push Notifications - Preparation and Blockers

Date: November 14, 2026

> Historical Stage6 audit, superseded for current implementation by
> [Real MDM enrollment infrastructure review](reviews/REAL_MDM_ENROLLMENT_REVIEW.md).
> Read that report for implemented native PKCS12/CMS/TLS/check-in/attended ADE
> paths, tests and remaining authorization/device/production blockers.
> This historical document is not a current assertion that no code exists.
Status: **Preparation documentation only. No MDM enrollment or push-notification
functionality exists, and none was demonstrated. The required Apple
prerequisites are not available (see section 1).**

This document records the Stage 6 prerequisite audit and, because the
prerequisites are missing, the safe preparation work that does not depend on
them: the architecture, the required credentials, the security requirements,
the enrollment flow, the push-notification flow, and the exact remaining
blockers. Everything here is grounded in `GENTECH_TECHNICAL_INVESTIGATION.md`
(sections 2, 3, 4, 7, 8, 10), which re-checked Apple's current documentation
on November 13, 2026.

No code was written in this stage. Writing an MDM server, an enrollment
endpoint, or a push client without the credentials they exist to use would
produce software that cannot be run, cannot be tested against a real device,
and could falsely imply that Apple MDM functionality is operational.

---

## 1. Prerequisite audit (performed before any implementation)

| # | Prerequisite | Status | Evidence | What unblocks it |
| --- | --- | --- | --- | --- |
| 1 | Apple approval for the required MDM capabilities (selection as a third-party MDM developer, Developer Program License Agreement Attachment 10) | **NOT OBTAINED** | The investigation (section 3.4) established from the current agreement text that any customer-facing MDM requires Apple to select KosherGuard; no selection has been requested or granted. | Enroll in the Apple Developer Program ($99/year) and request the MDM Vendor CSR Signing Certificate from the developer account; Apple's answer is a binary gate. Purchasing anything is explicitly out of scope for this stage. |
| 2 | A valid MDM APNs push certificate and its private key | **NOT AVAILABLE** | The push certificate is issued only through the flow that starts with the vendor CSR signing certificate (prerequisite 1). No certificate or key exists; none was invented or generated. | Prerequisite 1, then the CSR exchange at the Apple Push Certificates Portal (identity.apple.com). The certificate is free but must be renewed yearly against the same topic. |
| 3 | Apple-issued device identity and enrollment credentials (a working Apple Business organization for Automated Device Enrollment) | **NOT AVAILABLE** | The organization enrollment was marked "Not Qualified" and the Apple Account shows an existing-organization management conflict (user-reported, unresolved - investigation section 2.4). | Apple Support review of the "Not Qualified" decision and the account conflict. Until resolved, no ADE enrollment, no Apple Business device adds. |
| 4 | An approved spare iPhone for real-device testing | **NOT CONFIRMED** | No organization-owned device has been designated and approved for testing this new platform. The family's existing managed phones belong to the current production filtering setup and are out of scope for unapproved experiments. | The owner designates an organization-owned test iPhone (iOS 17+) for in-house testing. |

**Conclusion: all four prerequisites are missing.** Every Stage 6 objective
(device identity and enrollment, enrollment-profile delivery, APNs push
integration, sending an MDM command, recording a device response) depends on
at least one of them, so implementation stops here, exactly as the stage
specification requires.

## 2. Target architecture (for when the prerequisites exist)

Components KosherGuard must build and operate, per the investigation
(section 3.1):

1. **Enrollment endpoint (HTTPS).** Serves the enrollment profile to the
   iPhone. The device obtains its identity certificate via ACME (Apple's
   current recommendation) or SCEP. This is the only inbound contact the
   platform ever receives from a device: Apple devices never accept inbound
   connections from an MDM server.
2. **MDM protocol server.** Speaks the check-in and command protocol over
   HTTPS: the device contacts the server (Authenticate, TokenUpdate, then
   Acknowledged/Idle/Error statuses) and the server holds a per-device
   command queue (profiles, restrictions, queries, wipe). Declarative Device
   Management (DDM) declarations are the current delivery style for new
   payloads.
3. **APNs push client.** To deliver a command, the server sends an APNs push
   on the device's MDM topic; the device wakes and checks in over HTTPS and
   receives the queued command. APNs is the only supported wake channel
   (device ports 5223/443 to Apple; server to Apple on 443/2197).
4. **Response recording.** Every device response (Acknowledged/Error/Idle,
   status reports) is stored per device so the platform can prove what a
   device actually did. This is the audit trail the stage goals require:
   a command is only "sent" when the queue accepted it, and only "worked"
   when the device's recorded response confirms it.
5. **Policy integration.** The existing `filtering-engine/` policy engine
   stays the source of filtering decisions; the MDM layer delivers the
   profiles and declarations that point devices at it. The two layers are
   separate: the filtering engine works today without any Apple
   authorization; the MDM layer cannot operate without it.

## 3. Required credentials and their rules

| Credential | Who issues it | Rules (from the investigation, DPLA Attachment 10) |
| --- | --- | --- |
| MDM Vendor CSR Signing Certificate | Apple, on request from a paid Developer Program account, after selection | Gates everything below. Selection is not guaranteed and its criteria are not public. |
| APNs push certificate (per managed organization/customer) | Apple Push Certificates Portal, from a vendor-signed CSR | Free; yearly renewal against the same topic or enrolled devices can no longer be pushed. Each customer must obtain its **own** certificate; the vendor verifies the customer's identity before signing the CSR. |
| Vendor certificate private key | KosherGuard (generated with the CSR) | Never shared, never embedded in a product, never committed to this repository. The vendor may never generate or access a customer's private key (A10 4.2). |
| TLS certificate for the HTTPS endpoints | Any public CA (e.g. Let's Encrypt, free) | Required before any device can enroll or check in. |
| Profile-signing certificate (optional but recommended) | Any CA the devices trust | Signs enrollment profiles so devices can verify them. |
| Device identity certificates | Issued per device via ACME/SCEP during enrollment | Established by the enrollment flow itself; needs prerequisites 1-3 first. |

Apple may revoke MDM access or certificates at any time at its sole
discretion (A10 5.3); the entire fleet design must tolerate that.

## 4. Security requirements (binding on any future implementation)

- No private key, certificate, token, or other secret is ever committed to
  this repository, written to logs, or pasted into documentation. (This
  stage adds none.)
- Private keys are generated and stored server-side in an access-controlled
  store; the repository holds only code and documentation.
- Enrollment and check-in endpoints authenticate every device message
  against the device's issued identity certificate before acting on it.
- Push tokens and device identities are per-device secrets: stored
  server-side only, never logged in full.
- The APNs push certificate's yearly renewal is tracked with lead time;
  a missed renewal silently strands every enrolled device.
- Nothing in this repository may bypass Apple's enrollment requirements,
  share one certificate across customers, or extract customer keys -
  A10 4.1/4.2 prohibit these explicitly.

## 5. Enrollment flow (target, per Apple's current documentation)

1. The organization exists in Apple Business (prerequisite 3) and the test
   device is assigned to KosherGuard's MDM server there - for a device not
   purchased through an authorized channel, via Apple Configurator for
   iPhone (free; note Apple's 30-day provisional release window for devices
   added this way).
2. The device is erased and activates; activation forces Remote Management
   enrollment with the assigned MDM server (this is also the recovery path
   after any later erase).
3. The server serves the enrollment profile; the device obtains its
   identity certificate via ACME (or SCEP).
4. The device completes Authenticate and TokenUpdate check-ins; the server
   records the device as enrolled and stores its push token and identity.
5. The server issues the device's profiles/declarations from stored policy
   (filtering DNS settings, restrictions, app rules) and records each
   response.

ADE separately supports Prevent Unenrollment. Apple also documents the
profile top-level PayloadRemovalDisallowed key for supervised iOS MDM
profiles; supervision may be established with Configurator without Apple
Business. This project's manual-supervision enrollment option remains
EXPERIMENTAL: acceptance and Settings-removal enforcement of the generated
artifact have not been tested on an iPhone. No manual automatic reenrollment
after clean erase is promised. See the current review linked above.

## 6. Push-notification and command flow (target)

1. An operator action (or policy change) creates a command in the device's
   server-side queue.
2. The server sends an APNs push on the device's MDM topic using the push
   certificate (prerequisite 2).
3. The device wakes and contacts the MDM server over HTTPS (Idle status).
4. The server delivers the queued command; the device executes it and
   reports Acknowledged or Error.
5. The server records the response per device. A command is reported as
   delivered only when this response exists - never before.

## 7. Exact remaining blockers

1. **Apple MDM vendor selection** - not requested, not granted. Next step:
   enroll in the Apple Developer Program ($99/year) and request the MDM
   Vendor CSR Signing Certificate; document Apple's answer either way.
   (Purchasing is out of scope for this stage and needs an explicit owner
   decision.)
2. **Apple Business organization** - "Not Qualified" decision and
   existing-organization account conflict unresolved. Next step: Apple
   Support review.
3. **APNs push certificate** - unobtainable until blocker 1 clears.
4. **Test iPhone** - none designated or approved for this project.
5. **Server hosting with public HTTPS** - needed for the enrollment and
   check-in endpoints; free tiers exist but none is provisioned for this
   project.

## 8. What this stage did and did not do

Did: audited the four prerequisites against the current facts; documented
the architecture, credentials, security requirements, enrollment flow, push
flow, and blockers above; preserved all Stage 1-5 work unchanged.

Did not: write, deploy, or claim any MDM, enrollment, push, or iPhone
functionality; create, request, purchase, or invent any credential,
certificate, or authorization; contact any Apple service; touch any real
device; touch the existing production filtering setup (ManageEngine or the
PC Setup installer - nothing in this repository interacts with them); claim
any device enrollment or any delivered push notification or command.

**Real iPhone enrollment and MDM push were NOT demonstrated in this stage,
because the prerequisites to attempt them do not exist.**
