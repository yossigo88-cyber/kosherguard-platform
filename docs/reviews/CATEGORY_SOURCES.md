# Category source registry (Answer 22)

Requirement (user answer 22, 2026-11-16 02:17): every category-data
source needs name, license and attribution, import date, version and
hash, category mapping, update history, validation results, rollback
support, and manual review with overrides. An open-source repository
license must NOT be assumed to make the dataset commercially usable,
and no paid classification feed is approved without separate sign-off.

## What is implemented

`control-plane/app/category_source_routes.py`, models `CategorySource`
+ `CategorySourceUpdate`, migration `0020_category_sources.py`. All
routes are staff-only (owner / security_admin), the same gate as the
category dataset admin.

- **Source registry** - `POST/GET /api/admin/category-sources`:
  name (unique), license name and attribution are REQUIRED fields
  (a blank license is refused), status and notes.
- **Versioned imports with the actual rows** - `POST .../imports`
  takes the version string, the dataset SHA-256, the source's category
  mapping AND the dataset rows themselves (domain/category/verdict,
  each validated; any malformed row rejects the whole import). The
  hash is verified, not just format-checked: it must equal the SHA-256
  of the canonical dataset bytes (canonical JSON of the validated
  rows: sorted keys, 2-space indent, trailing newline), so a tampered
  or truncated import can never be activated under a format-valid
  hash. Imports land as `pending_review` and their rows are NOT
  effective.
- **Manual review with real activation** - `POST .../activate`
  requires a fresh staff MFA code plus explicit confirmation; only
  then do the update's rows REPLACE the previously active update's
  rows in category_rules (each bound to its source@version and update
  id). One active update per source; concurrent activations serialize
  on the source row (FOR UPDATE), so interleaving cannot mix rows.
- **Real rollback** - `POST .../rollback` reactivates a superseded
  update with fresh MFA: the current update's rules are deactivated,
  the rollback target's rules are re-applied, and the categories
  document is rebuilt again. Full history is kept
  (`GET .../history`), never rewritten.
- **Overrides** - per-domain manual review and overrides remain the
  existing category-rules admin (`source='manual-review'`, never
  hard-deleted), which sits alongside the source registry.
- Every create/import/activate/rollback writes an audit event.

## Transactional integrity of the categories file

The database is the source of truth; KG_CATEGORIES_FILE is a
materialized view of it:

1. Activation/rollback COMMIT the rule changes first.
2. The categories document is then re-rendered from the committed
   active rules, validated with the engine's own loader, written to a
   temp file and atomically `os.replace`d into place, then re-read
   and digest-checked. Syncs serialize GLOBALLY (process lock plus a
   PostgreSQL advisory transaction lock), because the file is shared
   across sources: the last writer always materializes the latest
   committed rules, so concurrent activations on different sources
   (or a resync racing an activation) cannot leave a stale subset
   after newer commits. A failed sync leaves the last-known-good file
   untouched, is audited (`category_source.file_sync_failed`), and
   returns an explicit error; `POST .../category-sources/resync`
   (staff-only) re-materializes the file without changing rules.
3. The publish flow re-verifies the file against the committed
   registry-managed rules before shipping and REFUSES a diverged or
   unreadable file. Enforcement is by provenance, not row count: once
   any registry-managed rule row exists or any update is active, the
   file must match the committed registry state - even when every
   rule was later deactivated (zero active rules never silently
   downgrade to a stale file). Only with NO registry involvement at
   all is the file treated as operator-provided (category-pipeline
   build) and the check skipped.
4. Consumers: only the gated publish flow (and its worker) read
   KG_CATEGORIES_FILE, at publish execution time. Already-running
   DNS/proxy bundles keep their generation; nothing live-reads the
   file, so re-materializing it is never itself publication.

## Honest limits

- Activation updates the dataset the publish flow ships; tenants pick
  it up on their next (separately gated) publish, matching how all
  protection changes propagate. Nothing auto-publishes.
- No paid classification feed is introduced or integrated; per the
  answer that needs separate approval first.

## Tests

`control-plane/tests/test_category_sources.py` (23 tests):
create/list, staff gate (non-staff 403), required license +
attribution, duplicate name, import validation (hash, malformed rows
rejected), pending rows never effective, activation requires fresh
MFA and applies rows with source@version provenance, supersede
replaces active rules, rollback restores the previous rules for real,
rules-less updates cannot activate, history, hash-payload binding
(mismatched/tampered digests rejected), commit-failure leaves the file
untouched, sync failure keeps last-known-good + audits + resync
repairs, engine-valid file materialization, publish divergence guard
(and its operator-provided skip), concurrent activation serialization.
