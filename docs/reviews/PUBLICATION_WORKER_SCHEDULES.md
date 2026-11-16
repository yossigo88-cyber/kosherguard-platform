# Publication and scheduled-policy integration

Code build only. No services started outside local test harnesses.
Checkpoint before these changes: 69406f27d926f34586038e4f809ead8c6c8088e5.

## Executable background worker

Migrate with Alembic, then run `python -m app.worker` from control-plane.
The systemd example in deploy is configuration, not an installed service.
The authenticated `/api/publications/jobs` route queues a durable request.
A request key deduplicates retries within one tenant; the status route is
also tenant scoped. A worker publishes the selected policy state at
execution time, not a snapshot of the queue request. The UI states this.

PostgreSQL workers claim rows with SKIP LOCKED. The claim transaction spans
publication; killed processes release it. Five attempts, exponential
backoff, and a terminal failed status bound retries. A job ID in the
atomic generation manifest supports recovery after activation but before
DB commit. The publication-state row lock serializes workers and the
existing synchronous route. Completion means publication only, never
push acceptance, device application, or verified filtering.

## Supplemental authenticated-device bundle

Keep the legacy default policy.json/categories.json contract. When active
assignments exist, also emit device-map.json and assigned-policy-N.json.
The manifest hashes every supplemental file. Files are written under the
same private generation and verified before one atomic current switch.
This is a new authenticated-device schema, not the older IP-binding
Stage11C devices.json schema. It never calls an IP address device identity.

The bundle reader pins the generation directory, opens regular files
without following symlinks, validates hashes, rejects unknown files and
unresolved references, and validates every assigned policy and schedule
before activation. Publication re-proves assigned policies against the
selected default. Ambiguous assignments are refused, not last-write-wins.

The DoH endpoint accepts bounded wire-format DNS GET/POST requests and
header credentials only. A signed tenant chooses its publication root;
a signed device chooses the current published assignment. A corrupt
replacement keeps last-known-good; absent initial configuration returns
503. The published proxy constructor uses the same bundle and refuses
other-tenant credentials. Its explicit reload preserves last-known-good.
The DNS runner loads scheduled bundles before a single engine swap.
Unauthenticated UDP remains tenant-default only, not per-device identity.

## Calendar windows

Weekly school/bedtime rules may include inclusive start_date/end_date
constraints. One date on both fields represents a one-time or holiday
window. Dates constrain the start day of an overnight window. IANA zones
handle DST, including repeated fall-back minutes. The fixed configured
zone does not change with travel; the UI offers explicit zone editing.
No religious calendar or location tracking is inferred. Date-bounded
candidate schedules cannot cover an unbounded protected baseline.
Schedules add blocks only. Time-limited allow exceptions/manual bypass
approvals are separate requirements and are NOT implemented by dates.

## Evidence and limits

Local PostgreSQL worker tests exercise committed API queueing, dedup,
concurrent worker locking, retry/backoff, terminal failure and recovery
from activation-before-commit. Bundle integration tests publish from the
real control-plane DB and send real DNS wire data through the DoH HTTP
route. Separate actual-UDP reporting evidence belongs to the prior
checkpoint; no privacy-storage changes are included here.

Apple credentials/devices, Swift compile/sign, deployed health and live
latency remain unverified. This is not a full44-answer completion claim.
The activity-retention component is held for separate security approval.
