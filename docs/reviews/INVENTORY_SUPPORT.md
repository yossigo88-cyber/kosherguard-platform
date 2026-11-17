# Inventory minimization, invitation-only registration, support (Answers 31/33/34)

## Answer 31 - device inventory minimization

Collected per device, only what management and security need: device
name + UDID (enrollment identifier), supervision requested/verified
(distinct facts), enrollment state, last check-in (last_seen_at), and
the identity-certificate fingerprint/status from ticket redemption.
Managed-app state exists only as the per-device app POLICY
(DeviceAppPolicy) and DDM declaration status, not an app inventory.

NOT collected, by design and enforced by test: device location (no
latitude/longitude/GPS columns anywhere in the inventory models) and
no expanded personal app inventory. The DDM declarations served to
devices never request Location or InstalledAppList data (tested
against the served declaration payloads). DDM status reports are
MINIMIZED before persistence: only the declaration-state receipt is
stored; unsolicited payload fields (location, personal-app content,
anything else) are dropped before they can be stored or logged -
tested with an injection of sensitive keys. Not requesting sensitive
data was not enough; not storing it is enforced.

## Answer 33 - invitation-only registration

Registration is invitation-only. There is NO open public customer
signup endpoint (tested: unauthenticated tenant-creation paths return
404/405); new guardians join only through the InviteToken flow (hashed
token shown once to the inviting owner, expiring, single-use).
Billing is outside the initial build: no payment provider, no stored
payment-card details, no subscription charges.

## Answer 34 - support channels

`POST /api/support/requests` (any tenant user, CSRF) creates a support
request with kind: account_recovery, enrollment_assistance,
connectivity_troubleshooting, policy_change, or general. The
verified-email support channel is recorded as channel metadata only -
no outbound email delivery is claimed without a reviewed integration.
`GET /api/support/requests` lists tenant requests (owners/guardians
see all tenant requests; viewers only their own).

Staff handling: `GET /api/admin/support/requests` (staff owner /
security_admin / support_admin), `POST .../advance` moves
open -> in_progress -> resolved -> closed (resolving requires notes),
`POST .../escalate` flags escalation to an authorized administrator
with audit. Every transition is audited.

Hard rule (tested): support workflows never touch protection - a
policy_change request end-to-end (create, advance, escalate, resolve)
changes no policy rows and issues no MDM commands; the requested
change still goes through the normal gated policy flow by an
authorized guardian. No support hours or 24/7 service is promised.

## Tests

`control-plane/tests/test_support.py` (12 tests): create/list kinds,
invalid kind rejected, email channel metadata-only, viewer scoping,
staff advance flow + required resolution notes + closed terminal,
escalation, non-staff 403, protection untouched, inventory model
minimization, status-report sensitive-key injection dropped,
served declarations contain no location/app-list
requests, no public signup route, invite accept requires a valid
token.
