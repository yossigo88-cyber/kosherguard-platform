# Policy preview and bounded synthetic DNS test

Code-only increment after publication-worker/schedule integration. Not full
platform completion and not authorization for production use.

## Policy editor and preview

- Strict unknown-domain blocking is the recommended new-policy UI default.
- Two editable-form starting examples: strict-review and category-mode. These
  are not owner-approved content/religious standards. Existing policies do not
  change when a template is selected. Category approvals remain separate.
- Authenticated tenant-scoped preview evaluates the stored policy, current
  configured category dataset, and schedules at an optional offset-aware time.
  It accepts domain names only, not URLs or paths, and stores no preview input.
- A preview proves a server engine decision, not actual iPhone enforcement.
  It does not preview app restrictions or full URL filtering.
- Schedule table displays dates below the timezone, not concatenated with it.

## Verification

Local PostgreSQL control-plane suite: 209 passed. New tests cover strict
example, URL rejection, domain validation, schedule on/off, offset requirement,
API preview and cross-tenant denial. JavaScript syntax check passed.

Actual local rendered workflow: selected a policy, submitted a dated overnight
schedule, saw the persisted row and Saved, queued publication, ran the separate
worker, refreshed to completed/attempts1, then submitted domain preview and saw
block/default. UI explicitly says publication does not verify device behavior.
Strict recommendation and date-range rows visually inspected at 1209x950.

## Synthetic benchmark

Run from the repository root with the Python development dependencies:

```
python tools/benchmark_dns.py --queries 10000 --clients 16 --output /tmp/kg-load.json
```

It creates an isolated temporary generation and sends only synthetic .example
queries over loopback UDP to the real DNS runner. It never contacts Apple,
customer devices, or an upstream resolver. Bounds: 100,000 queries/64 clients.

One local run on Linux/Python3.10.12, 1 available CPU, November16,2026:
10,000/10,000 correct sinkhole answers, zero errors, 1.2353s elapsed,
8,094.90 queries/s, median1.634ms, p95 4.389ms, p99 8.426ms.
These are measured values in this environment, NOT a production capacity
estimate, SLA or supported customer/device count. This excludes upstream DNS,
TLS/DoH, database/API load, APNs/MDM, native extension performance and internet
latency. Those remain unmeasured, with Apple/device paths externally gated.

## Open items

Original44-answer coverage remains incomplete. This increment does not add
policy groups, time-limited allow approvals, owner-approved category standards,
full policy editor CRUD, recovery/support/onboarding/offboarding or migrations
from another service. Previously reported privacy retention and viewer/MFA
findings are held pending explicit user approval; no fixes to those components
are included. Nothing deployed or connected to production.
