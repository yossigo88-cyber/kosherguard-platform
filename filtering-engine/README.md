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
    test_policy_engine.py    precedence, lists, categories, unknowns
    test_policy_validation.py  startup validation of the policy structure
    test_dns_service.py      real UDP tests: responses, upstream failure, malformed, logs
    test_concurrency.py      worker pool: slow upstream, saturation, shutdown
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
- Category lookup uses the most specific database entry covering the
  domain (a `safe.example.org` entry overrides `example.org` for its
  subdomains).
- Domains are normalized (case, whitespace, trailing dot) before matching.

**Startup validation.** The complete policy structure is validated
before the service starts (`validate_policy()` in `policy_engine.py`;
every `PolicyEngine` goes through it). Any of these is a hard
configuration error (`PolicyConfigError`) that names the exact field -
the service refuses to start rather than filter with a broken policy:

- `default_policy` missing, not a string, or not `allow`/`block`.
- `allowlist`/`blocklist` not a list (a bare string is rejected instead
  of being silently iterated character by character - a silently ignored
  block rule is an unintended allow, and vice versa).
- A domain entry that is not a string, is empty/whitespace, or is not a
  syntactically valid domain.
- `category_rules` not an object, or containing keys other than
  `allow`/`block`.
- A category allow/block list that is not a list, or a category entry
  that is not a string, is empty, or is not a valid category name
  (`a-z0-9` and dashes, same syntax the category database enforces).
- The same category in both `allow` and `block`.
- Unknown top-level keys (typo protection; keys starting with `_` are
  allowed for metadata).

Valid entries are normalized (case, whitespace, trailing dot), so
`"  WWW.Example.COM. "` in a list matches `www.example.com`.

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

- Listens on **UDP and TCP** on the same configured port
  (`127.0.0.1:5353` by default for local development; port 53 requires
  privileges in production). UDP is bound first; TCP is then bound to the
  same numeric port (with port `0`, the port the kernel assigned to UDP).
  If either listener fails to start, everything started so far is torn
  down again - the service never runs half-configured.
- **DNS over TCP framing** follows RFC 1035: each message on a TCP
  connection is a two-byte unsigned big-endian length followed by that
  many bytes of DNS message. Reads assemble complete messages across
  partial TCP deliveries; multiple messages on one connection are
  answered in order. The two-byte prefix can hold at most 65535 - exactly
  the supported maximum - so the only invalid length on the wire is zero;
  a zero length or an unrecoverably malformed message closes that
  connection safely and is logged - it can never crash the service.
- **Allowed domains** are forwarded to configurable upstream resolvers
  (tried in order; per-upstream timeout, default 3s) and the upstream
  answer is relayed. The original query - EDNS0 OPT record included - is
  forwarded unchanged.
- **Upstream TCP fallback**: if an upstream's UDP answer has the
  truncation (TC) flag set, the same query is retried over TCP to *that
  same upstream*, and the complete TCP answer is used. If the TCP retry
  fails, the next configured upstream gets the normal UDP attempt plus
  its own truncation check; if every upstream fails, the client gets
  SERVFAIL. The structured log records the transport actually used
  (`udp` or `tcp`) and every `tcp_fallback_failed` event. Queries are
  never sent over TCP unless a UDP answer arrived truncated.
- **EDNS0 and downstream UDP sizes**: a downstream UDP response is
  limited to the client's advertised EDNS0 UDP payload size, or 512
  bytes when the query carried no OPT record, additionally capped by the
  configurable `max_udp_response` safety limit (default 4096; minimum
  512 - a DNS header plus the echoed question always fits in 512 bytes,
  which is what makes the guarantee below possible). A response that
  does not fit - including a large answer fetched via TCP fallback - is
  truncated at whole-record boundaries (never mid-record) and the TC
  flag is always set when anything was removed, so the client can retry
  over TCP and get the complete answer. The OPT record is preserved when
  it fits; an OPT record so large that it alone prevents the response
  from fitting is dropped (OPT is advisory) rather than sent oversized -
  a UDP response never exceeds the effective limit. Downstream TCP clients
  always receive the complete response, up to the 65535-byte
  DNS-over-TCP maximum.
- **Blocked domains** are answered locally. Default `sinkhole` mode:
  A -> `0.0.0.0`, AAAA -> `::` (TTL 60s). `nxdomain` mode answers NXDOMAIN
  instead. Non-A/AAAA query types for blocked domains get NXDOMAIN either
  way.
- **Upstream failure** (all upstreams fail): the client gets SERVFAIL and
  the error is logged.
- **Malformed packets**: a FORMERR response is returned when a transaction
  ID can be recovered; otherwise the packet is dropped. Bad input can
  never crash the service.

### Remaining transport limitations

- Classic DNS only: no DNS-over-HTTPS or DNS-over-TLS (out of scope for
  this stage), so DNS traffic is visible to - and can be redirected by -
  the local network, as before.
- Upstream answers are trusted as received; there is no DNSSEC
  validation.
- Upstream TCP fallback happens only when a UDP answer arrives with TC
  set; an upstream that silently drops large UDP answers instead of
  truncating them is indistinguishable from a timeout and fails over to
  the next upstream.
- The per-upstream timeout applies to each attempt, so worst-case
  latency for one query grows with the number of configured upstreams
  (timeout x upstreams, doubled when each answer is truncated).
- `max_udp_response` (minimum 512) caps downstream UDP answers even
  when the client advertises more; affected clients retry over TCP and
  get the complete answer.

### Concurrency

Requests are processed by a **bounded worker pool**, never one thread per
request and never the single synchronous loop this stage started with:

- `max_workers` (default 32) worker threads pull requests off a bounded
  queue; `max_queued` (default 128) caps how many requests may wait.
  Thread and memory use stay bounded no matter the load.
- A slow or unreachable upstream occupies at most one worker, so it
  cannot delay unrelated requests. Blocked-domain queries in particular
  are decided locally with no network I/O and answer promptly even while
  upstreams are stuck (covered by an automated test with a deliberately
  delayed upstream).
- **Saturation is safe**: when every worker is busy and the queue is
  full, new packets are dropped and a `queue_full` event is written to
  the structured log. Dropping is the standard UDP-overload answer -
  clients retry - and it can never exhaust resources.
- Requests still queued at shutdown are dropped; clients retry. See the
  shutdown paragraph below for the shared-deadline behavior across both
  transports.

TCP connections get the same bounded treatment: a fixed pool of
`tcp_workers` (default 16) threads serves accepted connections from a
bounded `tcp_queued` (default 64) queue; a connection that arrives at a
full queue is closed safely and a `tcp_queue_full` event is logged.
Per-connection guardrails keep one client from monopolizing a worker:
`tcp_idle_timeout` (default 10s) is one absolute deadline for each
complete message: the two-byte length prefix and the message body share
it (it is never reset between them), so a client trickling bytes or
going idle is dropped and one message can never take almost twice the
timeout to arrive; `tcp_max_messages` (default 64) caps how
many queries one connection may send before it is closed. A slow TCP
client therefore occupies at most one worker and never delays unrelated
UDP or TCP traffic.

All limits are configurable on the command line (`--max-workers`,
`--max-queued`, `--tcp-workers`, `--tcp-queued`, `--tcp-idle-timeout`,
`--tcp-max-messages`, `--max-udp-response`) or via `ServiceConfig` in
code. Invalid values (non-integer, < 1) are rejected at startup.

**Shutdown across both transports** uses one overall monotonic deadline
shared by the receive loop, the accept loop, all UDP workers, and all
TCP workers: the budget is the worst-case upstream work (upstream
timeout x number of upstreams x 2, covering a UDP attempt plus a TCP
fallback per upstream) plus the connection read timeout and a 2s margin.
Each thread is joined only for the time remaining before that shared
deadline - the wait never multiplies by the worker or connection count.
Every accepted connection is tracked from the moment it is accepted. At
shutdown the accept loop stops first, then connections still waiting in
the connection queue are drained and closed (they are not being served
yet, so this cannot interrupt in-flight work), and a connection accepted
just as shutdown begins is closed immediately rather than enqueued. Idle
or slow TCP connections being served cannot hold shutdown: after the
deadline, any still-open tracked connection is force-closed as a
backstop, and any worker or thread that survives the deadline is
reported by name, kept referenced on the service, and returned in an
accurate incomplete-shutdown result. An incomplete shutdown is never
presented as clean.

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
    --max-workers 32 --max-queued 128 \
    --tcp-workers 16 --tcp-queued 64 \
    --tcp-idle-timeout 10 --tcp-max-messages 64 \
    --max-udp-response 4096 \
    --log decisions.jsonl
```

Then, from another shell:

```bash
dig @127.0.0.1 -p 5353 example.com        # allowed: real answer
dig @127.0.0.1 -p 5353 tracker.example.com # blocked: 0.0.0.0
dig @127.0.0.1 -p 5353 +tcp example.com    # same service over TCP
```

## Running the tests (repeatable procedure)

```bash
cd filtering-engine
pip install -r requirements.txt
python -m pytest tests/ -v
```

The suite runs the real service over real UDP and TCP sockets against
in-test fake upstream resolvers, so no internet access is needed and
results are deterministic. It covers: policy precedence, allowlists,
blocklists, category rules, unknown domains, DNS responses (sinkhole
A/AAAA, NXDOMAIN, forwarded answers, TXT), upstream failures (SERVFAIL),
malformed requests (FORMERR + service survival), the full policy
validation matrix (invalid types, malformed domains/categories, empty
entries, unknown keys), bounded concurrency (a deliberately delayed
upstream does not delay unrelated or blocked requests, concurrent slow
requests run in parallel, saturation drops safely and logs it, shutdown
is clean), import merging and validation, and the structure and privacy
properties of the decision log. Stage 4 adds: blocked and allowed
answers over TCP, ordered multi-message connections, partial (trickled)
frame delivery, malformed/zero/oversized length handling, slow-client
isolation, the bounded TCP pool and full-queue close + log, idle-timeout
and per-connection message limits, port-0 binding both transports to one
port, listener-failure cleanup, upstream TC-triggered TCP fallback with
logged transports, fallback failure moving to the next upstream,
SERVFAIL over TCP, EDNS0 preservation end to end, 512-byte truncation
without an OPT record, complete responses within an advertised payload
size, the `max_udp_response` cap, complete large answers to downstream
TCP clients, and shared-deadline shutdown closing listeners, connections
and workers. Regression coverage for the reliability corrections: one
shared deadline per complete TCP message (a fragmented frame within the
deadline succeeds; prefix-fast-plus-body-fast but over-deadline total is
disconnected; the shutdown budget covers exactly one message deadline),
queued connections drained and closed at shutdown, the accept/shutdown
race guard (including a worker that is parked inside the connection
queue's get() when shutdown begins: a connection it then dequeues is
closed, never served), UDP bind-failure cleanup, the max_udp_response
512-byte minimum, and oversized-OPT truncation that never exceeds the
limit. Stage 5 adds: first-upstream failover to the next upstream,
both for a genuine timeout (proven with a silent fake upstream that
receives the query and never answers) and for an immediate connection
refusal; an unrecoverable packet dropped with no response (service
survives); a questionless packet answered REFUSED; a root-name query
answered REFUSED; non-A/AAAA queries for blocked domains answered
NXDOMAIN in sinkhole mode; decision-log write failures that cannot
crash request processing; a policy rule naming a category the database
does not have; category-database file validation (missing file,
missing or mistyped `domains` key); explicit rejection of non-string
domain and category values with clear validation errors; duplicate-
domain records in one import file; import atomicity (a malformed
record leaves the database unchanged); and concurrency tests
synchronized on real events and conditions instead of fixed sleeps.

Latest local run: **119 passed** (Python 3.10, pytest 8.4, dnslib 0.9).

## Security notes

- No secrets or credentials exist anywhere in this stage; the upstream
  resolver is the only external dependency.
- Policy and database files are fully validated on load; invalid
  configuration fails fast with a clear error naming the field instead
  of silently mis-filtering. See "Startup validation" above.
- The sinkhole answers point at `0.0.0.0`/`::`, not at a server we run -
  blocked devices go nowhere, and there is no block-page attack surface.

## Future integration points (not built in this stage)

Listed for orientation only; none of this exists today:

- Dashboard ingestion of the JSON decision log.
- Per-device or per-group policies (the engine already takes any policy
  object; keying policies by client identity is future work).
- DNS over HTTPS/TLS listeners (deliberately out of scope: the
  service speaks classic DNS on UDP and TCP only).
- Policy hot-reload without restart.
- A production-scale, properly licensed category feed.
- Integration with the managed-device layers (proxy, MDM, URL Filter
  backend) described in the investigation document - all gated on the
  Apple authorization questions documented there.
