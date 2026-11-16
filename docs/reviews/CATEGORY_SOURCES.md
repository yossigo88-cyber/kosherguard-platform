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
  takes the version string, the dataset SHA-256 (format validated),
  the source's category mapping AND the dataset rows themselves
  (domain/category/verdict, each validated; any malformed row rejects
  the whole import). Imports land as `pending_review` and their rows
  are NOT effective.
- **Manual review with real activation** - `POST .../activate`
  requires a fresh staff MFA code plus explicit confirmation; only
  then do the update's rows REPLACE the previously active update's
  rows in category_rules (each bound to its source@version and update
  id), and the categories document the publish flow ships
  (KG_CATEGORIES_FILE) is rebuilt from the active rules and validated
  with the engine's own loader. One active update per source.
- **Real rollback** - `POST .../rollback` reactivates a superseded
  update with fresh MFA: the current update's rules are deactivated,
  the rollback target's rules are re-applied, and the categories
  document is rebuilt again. Full history is kept
  (`GET .../history`), never rewritten.
- **Overrides** - per-domain manual review and overrides remain the
  existing category-rules admin (`source='manual-review'`, never
  hard-deleted), which sits alongside the source registry.
- Every create/import/activate/rollback writes an audit event.

## Honest limits

- Activation updates the dataset the publish flow ships; tenants pick
  it up on their next (separately gated) publish, matching how all
  protection changes propagate. Nothing auto-publishes.
- No paid classification feed is introduced or integrated; per the
  answer that needs separate approval first.

## Tests

`control-plane/tests/test_category_sources.py` (13 tests):
create/list, staff gate (non-staff 403), required license +
attribution, duplicate name, import validation (hash, malformed rows
rejected), pending rows never effective, activation requires fresh
MFA and applies rows with source@version provenance, supersede
replaces active rules, rollback restores the previous rules for real,
rules-less updates cannot activate, history.
