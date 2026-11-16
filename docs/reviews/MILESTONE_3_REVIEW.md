# Milestone 3 review - category pipeline, PAC generation, DNS edge, filtering proxy

Date: 2026-11-16. Scope: the filtering-edge milestone - everything a
device's traffic actually meets. Publication-wiring for the category
dataset in the control plane is HELD (unpublished) with the Milestone 2
security fix: both are prepared locally and pending the user's
decision, and are intentionally not on this branch yet.

## Test results (actual, this environment)

- category-pipeline: `python3 -m pytest category-pipeline/tests -q`:
  **6 passed** (real seed builds and engine-loads, union across
  sources, unknown category rejected, provenance mismatch rejected,
  bad domain rejected, empty sources rejected).
- proxy-edge PAC: `python3 -m pytest proxy-edge/tests/test_pac.py -q`:
  **6 passed**, including running the real generated PAC under node and
  comparing every host decision against the reference evaluator
  (bad.example, sub.bad.example, bet365.com via baked category block,
  allowlist override, plain hostname, default allow and default block).
- dns-edge: `python3 -m pytest dns-edge/tests -q`: **6 passed** against
  synthetic on-disk fixtures, including a live UDP query: blocked
  domain -> sinkhole 0.0.0.0; allowed domain with a dead upstream ->
  SERVFAIL (fail-closed); broken republication keeps the previous
  configuration; watch reload picks up a new generation.
- proxy-edge server: `python3 -m pytest proxy-edge/tests/test_server.py
  -q`: **5 passed** against a live loopback proxy: 403 block page for
  blocked and category-blocked hosts, CONNECT refused for blocked
  domains, malformed request 400, allowed request relayed to a real
  upstream with body intact.

## Components

- `category-pipeline/`: taxonomy.json (30 categories covering the
  spec's required list), sources/seed-manual.jsonl (221 hand-assigned
  records, 215 unique domains - our own assignments of well-known
  public domains, no third-party database content), PROVENANCE.md
  (license records: UT1 and Shallalist evaluated and NOT imported as
  non-commercial-only; commercial feeds need a contract decision),
  build.py (engine-validated, provenance-enforced, atomic write,
  output clearly labeled SEED DATA - NOT A COMPLETE WEBSITE DATABASE).
- `proxy-edge/pac.py`: deterministic PAC generation from policy +
  category document. Blocklist and baked category-blocks route to the
  proxy; allowlist always DIRECT (engine priority); strict
  default-block policies route everything else to the proxy. Includes
  a reference evaluator for testing without a JS runtime.
- `dns-edge/runner.py`: runs the Stage-4-reviewed DNSFilteringService
  from a generation root and triggers its fail-safe reload (full
  validation before swap) when the publication revision advances. The
  runner owns no policy logic and never writes the publication tree.
- `proxy-edge/server.py`: forward HTTP proxy enforcing engine decisions
  after the PAC (defense in depth). Plain HTTP filtered by host with a
  403 block page; CONNECT tunnel-or-refuse by domain.

## Security and honesty notes

- TLS interception is deliberately NOT implemented in this milestone:
  certificate installation, pinning compatibility, and legal
  constraints are separate work. HTTPS filtering today is
  domain-level only (CONNECT allow/refuse), which is exactly what the
  website copy says.
- The DNS runner was verified against synthetic fixtures only, NOT
  through the control plane's held publication path. Per-tenant
  publication isolation is pending user approval (M2 erratum).
- The proxy logs every decision (host, action, rule, client address);
  no credentials or content are logged.

## Known limitations / remaining work

- No proxy authentication or per-device identification on the proxy
  yet (client IP only); authenticated per-device identity is an
  approved-decision item owed to a later milestone.
- The seed category dataset is intentionally small; real coverage
  needs a licensed commercial feed (cost decision) or a larger
  rights-clean import.
- PAC hosting (serving the generated file over HTTPS to devices) is
  wired in a later milestone with device management.
