# KosherGuard Core Filtering Engine (Stage 3)

The backend filtering core of the KosherGuard platform: a central policy
engine, a working DNS filtering service, an expandable website category
database, and structured decision logging, with automated tests.

**Stage 3 scope, stated plainly:** this stage builds and tests the
*backend* only. It contains no dashboard, no MDM, and no iPhone
management or enrollment features, and nothing here claims to filter
iPhones. Apple has not approved KosherGuard as a commercial MDM provider
(see `../docs/GENTECH_TECHNICAL_INVESTIGATION.md`, section 3.4); this
stage neither needs nor assumes that approval. Everything runs locally.

## Technology choices

| Choice | Rationale |
| --- | --- |
| Python 3 (3.10+) | Readable, maintainable, no build step; the whole team can audit a policy engine written in plain Python. |
| [`dnslib`](https://github.com/paulc/dnslib) | Mature, permissively licensed (BSD) DNS wire-protocol library. Hand-rolling DNS packet parsing is a classic source of security bugs; dnslib is the standard, well-tested answer. |
| [`pytest`](https://pytest.org) | Standard Python test runner. |
| JSON for all config and data | Python's standard library reads it with zero extra dependencies; diffs review cleanly in git. |

No paid APIs, paid databases, subscriptions, or services are used or
required. The only runtime dependency besides dnslib is a DNS upstream
resolver (any free resolver, e.g. 1.1.1.1 or 9.9.9.9, or your own).

## Layout

```
filtering-engine/
  README.md                  this file
  requirements.txt           pinned dependency ranges
  config/
    policy.example.json      example policy configuration
  data/
    categories.test.json     small, clearly labeled TEST category dataset
  src/
    policy_engine.py         central policy engine (allow/block/category/default)
    category_db.py           category database + import tool (CLI)
    dns_service.py           DNS filtering service (UDP) + structured logging
  tests/
    test_policy_engine.py    precedence, lists, categories, unknowns, validation
    test_dns_service.py      real UDP tests: responses, upstream failure, malformed, logs
    test_category_db_and_import.py  dataset, multi-category, import process
```

## Architecture

```
            +-------------------+        +-----------------------+
 DNS query  |                   | decide |                       |
 ---------> |  DNS filtering    | -----> |  Central policy engine |
 (UDP)      |  service          | <----- |  (allow/block + why)   |
            |  src/dns_service  |        |  src/policy_engine     |
            +-------------------+        +-----------+-----------+
              |        |                           |
   blocked:   |        | allowed: forward          | reads
   sinkhole/  |        v                           v
   NXDOMAIN   |   upstream resolver(s)      category database
              |   (configurable)            data/categories.test.json
              v
   structured JSON decision log (no personal data)
```

The policy engine is transport-independent: the DNS service is its first
consumer, and later stages (proxy, URL filter backend) can reuse it as-is.

## Policy engine

Configured entirely in JSON (see `config/policy.example.json`) - no code
changes to change policy:

```json
{
  "default_policy": "allow",
  "allowlist": ["important-override.example"],
  "blocklist": ["tracker.example.com"],
  "category_rules": {
    "allow": ["education", "reference"],
    "block": ["adult", "gambling", "malware"]
  }
}
```

**Rule precedence (highest first):**

| Order | Rule | Result |
| --- | --- | --- |
| 1 | Explicit allowlist match | ALLOW (`explicit_allow`) |
| 2 | Explicit blocklist match | BLOCK (`explicit_block`) |
| 3 | Domain is in a blocked category | BLOCK (`category_block`) |
| 4 | Domain is in an allowed category | ALLOW (`category_allow`) |
| 5 | Nothing matched | `default_policy` |

Notes:

- A listed domain matches itself and all of its subdomains
  (`tracker.example.com` covers `ads.tracker.example.com`).
  `eviltracker.example.com` does **not** match.
- The allowlist wins over the blocklist, so surgical exceptions are
  possible.
- A blocked category beats an allowed category when a domain has both.
- Putting the same category in both `allow` and `block` is rejected as a
  configuration error, as is a `default_policy` that is not
  `allow`/`block`.
- Category lookup uses the most specific database entry covering the
  domain (a `safe.example.org` entry overrides `example.org` for its
  subdomains).
- Domains are normalized (case, whitespace, trailing dot) before matching.

Every decision carries the action, the rule that fired, the matching
category (if any), and a human-readable reason - this is what gets logged.

## Website category database

Structure (`data/categories.test.json`):

```json
{
  "_meta": {"description": "...", "dataset": "...", "version": 1},
  "domains": {"example.com": ["education", "reference"], ...}
}
```

- Domains can have **multiple categories**.
- The shipped dataset is a **small, clearly labeled TEST dataset**
  (~20 domains). It is not a complete website database and must never be
  presented as one. Sensitive categories use reserved `.example`
  placeholder domains. No proprietary or unlicensed dataset was copied;
  production use needs a properly licensed feed or a much larger
  self-maintained dataset.

**Import format and process.** New or updated records are JSON Lines, one
object per line:

```json
{"domain": "example.org", "categories": ["education", "reference"]}
```

Import with the built-in CLI:

```bash
python src/category_db.py data/categories.test.json import new_records.jsonl \
    --out data/categories.test.json
```

Every record is validated (domain syntax, category syntax, non-empty
category list); malformed records are rejected with their line number and
the import aborts without writing. Existing domains get the union of old
and new categories. The importer prints how many domains were added vs
updated. Only import data we have the rights to use.

## DNS filtering service

- Listens on UDP (`127.0.0.1:5353` by default for local development; port
  53 requires privileges in production).
- **Allowed domains** are forwarded to configurable upstream resolvers
  (tried in order; per-upstream timeout, default 3s) and the upstream
  answer is relayed.
- **Blocked domains** are answered locally. Default `sinkhole` mode:
  A -> `0.0.0.0`, AAAA -> `::` (TTL 60s). `nxdomain` mode answers NXDOMAIN
  instead. Non-A/AAAA query types for blocked domains get NXDOMAIN either
  way.
- **Upstream failure** (all upstreams fail): the client gets SERVFAIL and
  the error is logged.
- **Malformed packets**: a FORMERR response is returned when a transaction
  ID can be recovered; otherwise the packet is dropped. Bad input can
  never crash the service.
- Current transport limitation: **UDP only**. TCP (needed for very large
  responses) is a documented future integration point, not present today.

### What DNS filtering can and cannot block

DNS filtering controls access to **domains only**:

- It **can** allow or block an entire domain (and its subdomains), for
  every protocol and app on a device that uses it as its resolver.
- It **cannot** block individual URLs, pages, or paths (all of
  `example.com` is one decision).
- It **cannot** see or filter the contents of HTTPS traffic - encryption
  hides everything except the domain lookup itself.
- It **cannot** stop a determined user who switches to their own DNS
  resolver or a VPN; on managed devices that is addressed by separate
  controls (supervised restrictions, locked DNS settings - outside this
  stage's scope).

Per-device enforcement and the proxy/URL-filter layers that cover
per-URL filtering are later stages, documented in
`../docs/GENTECH_TECHNICAL_INVESTIGATION.md`.

## Filtering event logs

Every decision is logged as one structured JSON object per line:

```json
{
  "ts": "2026-11-13T21:34:25.382189Z",
  "event": "dns_query",
  "domain": "doubleclick.net",
  "qtype": "A",
  "decision": "block",
  "rule": "explicit_block",
  "category": null,
  "reason": "doubleclick.net matches blocklist entry doubleclick.net",
  "outcome": "answered_blocked",
  "block_mode": "sinkhole",
  "latency_ms": 0.21
}
```

`outcome` is one of `answered_blocked`, `forwarded`, `servfail`,
`answered_refused`, `dropped_or_formerr`. `upstream` and `error` appear
when relevant.

**Privacy by design:** the client IP address is intentionally **not**
recorded. The log contains the requested domain, the decision, and why -
nothing else. No unnecessary personal information is collected. The
JSON-lines format is deliberately dashboard-friendly for a later stage.

## Running locally

```bash
cd filtering-engine
pip install -r requirements.txt

python src/dns_service.py \
    --policy config/policy.example.json \
    --categories data/categories.test.json \
    --listen 127.0.0.1:5353 \
    --upstream 1.1.1.1 \
    --block-mode sinkhole \
    --log decisions.jsonl
```

Then, from another shell:

```bash
dig @127.0.0.1 -p 5353 example.com        # allowed: real answer
dig @127.0.0.1 -p 5353 tracker.example.com # blocked: 0.0.0.0
```

## Running the tests (repeatable procedure)

```bash
cd filtering-engine
pip install -r requirements.txt
python -m pytest tests/ -v
```

The suite runs the real service over real UDP sockets against an in-test
fake upstream resolver, so no internet access is needed and results are
deterministic. It covers: policy precedence, allowlists, blocklists,
category rules, unknown domains, DNS responses (sinkhole A/AAAA,
NXDOMAIN, forwarded answers, TXT), upstream failures (SERVFAIL),
malformed requests (FORMERR + service survival), import merging and
validation, and the structure and privacy properties of the decision log.

Latest local run: **41 passed** (Python 3.10, pytest 8.4, dnslib 0.9).

## Security notes

- No secrets or credentials exist anywhere in this stage; the upstream
  resolver is the only external dependency.
- Policy and database files are validated on load; invalid configuration
  fails fast with a clear error instead of silently mis-filtering.
- The sinkhole answers point at `0.0.0.0`/`::`, not at a server we run -
  blocked devices go nowhere, and there is no block-page attack surface.

## Future integration points (not built in this stage)

Listed for orientation only; none of this exists today:

- Dashboard ingestion of the JSON decision log.
- Per-device or per-group policies (the engine already takes any policy
  object; keying policies by client identity is future work).
- DNS over HTTPS/TLS listeners, and TCP DNS for large responses.
- Policy hot-reload without restart.
- A production-scale, properly licensed category feed.
- Integration with the managed-device layers (proxy, MDM, URL Filter
  backend) described in the investigation document - all gated on the
  Apple authorization questions documented there.
