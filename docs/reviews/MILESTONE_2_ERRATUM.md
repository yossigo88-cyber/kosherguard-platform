# Milestone 2 erratum - cross-tenant publication isolation

Date: 2026-11-16. Status: fix prepared and tested locally, PENDING user
approval before publication (serious-security stop condition).

## What was wrong

Milestone 2 as published (head ec1dcbe3) used ONE shared publications
root for all tenants. The publication revision counter is per-tenant,
so generation directory names collide across tenants.

## Reproduction (performed against bundled PostgreSQL, two tenants)

1. Tenant A selects a default policy and publishes: generation 1 written.
2. Tenant B selects a default policy and publishes: its revision counter
   also starts at 1, so the publisher tries to create `generations/1`,
   which already exists (tenant A's). The publish fails with
   FileExistsError.
3. The failure path in `Publisher.publish()` removed the "partial"
   generation directory with `shutil.rmtree` - but that directory was
   tenant A's LIVE published generation, not a partial write.
   Verified: `Publisher.current()` after the failed publish raised
   FileNotFoundError; tenant A's on-disk configuration was gone.

Impact: any second tenant's first publish would (a) always fail and
(b) delete the first tenant's active published configuration.
Cross-tenant destruction of published state. No live deployment exists,
so there was no production impact; this was caught in pre-launch
testing on 2026-11-16.

## Correction (local commit 2af092e, unpublished pending approval)

- `tenant_root()`: per-tenant publication roots at
  `<KG_PUBLICATIONS_ROOT>/tenant-<id>/`. The path is built from the
  integer tenant id only; no user-controlled path segment can appear.
- `Publisher.publish()`: failure cleanup only removes a directory the
  current publish itself created. A replay or collision can never
  delete existing data, even inside one tenant's root.
- `GET /api/publications/current` is scoped to the caller's tenant
  root; a tenant can only ever see its own manifest.

## Negative tests (all passing, 34 total control-plane tests)

- `test_second_tenant_publish_never_touches_first`: two tenants publish
  independently; both succeed, both generations intact, each tenant's
  current manifest names only its own policy, tenant A's engine still
  loads and decides correctly.
- `test_replay_same_revision_is_refused_and_preserves_data`: a direct
  replay of an existing revision is refused and the original generation
  is byte-for-byte untouched.

## Reporting note

Milestone 2 should not be characterized as security-complete; this
erratum is part of its record.
