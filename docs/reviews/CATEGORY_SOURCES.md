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
- **Versioned imports** - `POST .../imports`: version string and
  SHA-256 of the imported dataset (format validated), the source's
  category mapping and the import validation results (row counts,
  rejects) are stored on the update. Imports land as
  `pending_review`.
- **Manual review** - `POST .../activate` requires a fresh staff MFA
  code plus explicit confirmation (`activate-category-update`); only
  then does an update become `active`. One active update per source:
  the previous one is marked `superseded`. Content correctness stays
  a human decision - the validation results are the record the
  reviewer approves against.
- **Rollback** - `POST .../rollback` reactivates a superseded update
  with fresh MFA; the current active is marked `rolled_back`. Full
  history is kept (`GET .../history`), never rewritten.
- **Overrides** - per-domain manual review and overrides remain the
  existing category-rules admin (`source='manual-review'`, never
  hard-deleted), which sits alongside the source registry.
- Every create/import/activate/rollback writes an audit event.

## Honest limits

- The registry records and gates dataset provenance and review; the
  actual dataset rows still enter the filter dataset through the
  existing category-rules admin (bulk import of a registered update
  into rules is future work, noted in REQUIREMENTS_COVERAGE).
- No paid classification feed is introduced or integrated; per the
  answer that needs separate approval first.

## Tests

`control-plane/tests/test_category_sources.py` (9 tests): create/list,
staff gate (non-staff 403 on read and write), required license +
attribution, duplicate name, import starts pending_review with hash
validation, activation requires fresh MFA, one-active supersede
semantics, rollback restores the superseded update, history ordering.
