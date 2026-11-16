# Milestone 2 review - control plane slice 2: policies, devices, tighten-only, front ends, publication trigger

Date: 2026-11-16. Scope: everything built on top of the Milestone 1
foundation (head f4eb0fe): policy/device APIs with the tighten-only
invariant (published earlier as f4eb0fe), the three front ends, and the
publication trigger.

## Test results (actual, this environment)

- `python3 -m pytest control-plane/tests -q`: **32 passed** against
  bundled PostgreSQL (pgserver). Breakdown: 18 Milestone 1 foundation +
  auth, 7 policy/device tighten-only tests (Milestone 2 slice 1), 3
  front-end serving tests, 5 publication tests (including end-to-end
  below).
- Alembic: migration 0003 (publication revision counter) applied via
  real `alembic upgrade head` to a fresh bundled PostgreSQL as part of
  the end-to-end check. Migrations 0001/0002 verified in their own
  slices.
- End-to-end publication proof (kept as a permanent test,
  `test_published_generation_loads_in_the_engine`): API publish ->
  Publisher writes generation 1 -> the filtering engine's
  `load_validated_engine` loads it through the `current` symlink (the
  Stage 11C no-follow code path) -> `decide("bad.example")` returns
  block, `decide("good.example")` returns allow.
- Visual evidence: 7 headless-Chrome screenshots driving the real UI
  against a live uvicorn server on bundled PostgreSQL (sign-in, policy
  creation, device registration, portal view). Inspected manually; all
  render correctly. Captured in the build environment, not committed.

## Changed files (since f4eb0fe)

- `control-plane/app/publisher.py` (new): generation publisher adapted
  from the Stage 11C security-reviewed dashboard publisher. Discipline
  preserved: validate with the engine's own validators before writing;
  write-once generation directories; 0700 tree / 0600 files via
  temp + atomic rename; on-disk re-verification before the atomic
  `current` symlink switch; a failed publish removes the partial
  generation and leaves `current` untouched; thread + cross-process
  lock file.
- `control-plane/app/publication_ops.py` (new): exports the tenant's
  selected default policy as engine `policy.json` + `categories.json`
  and publishes it as the next revision.
- `control-plane/app/main.py`: `POST /api/publications`
  (owner/guardian only) and `GET /api/publications/current`; static
  mounts `/web` (admin), `/portal`, `/` (website); publication
  endpoints registered before the mounts so `/api/*` is never shadowed.
- `control-plane/app/models.py`: `revision` counter on
  `publication_states`; `control-plane/alembic/versions/0003_publication_revision.py`.
- `control-plane/app/config.py`: required `KG_PUBLICATIONS_ROOT`.
- `control-plane/app/asgi.py` (new): ASGI entry point reading
  configuration from the environment.
- `website/` (new): public marketing page. Copy states development
  status honestly: device-management capabilities are goals pending
  Apple approval, enrollment eligibility, and real-device validation.
- `portal/` (new): guardian portal - sign-in (with TOTP field),
  devices, family policies, sign out.
- `control-plane/web/` (new): admin dashboard - sign-in, policy
  list/create/make-default, device register/assign.
- `control-plane/tests/`: test_publications.py (new, 5 tests);
  fixture updates for `KG_PUBLICATIONS_ROOT`.

## Security notes

- Both JS apps escape every interpolated value through `esc()` before
  inserting into the DOM (stored-XSS surface closed by construction;
  no `innerHTML` of raw API data anywhere).
- Publishing keeps the reviewed Stage 11C discipline verbatim in
  behavior; the publisher is an adaptation, not a re-design, and its
  end-to-end test loads through the engine's own no-follow reader.
- The revision counter lives in the database and increments before the
  on-disk publish, so two concurrent publishes cannot collide on a
  generation number; the publisher also refuses an existing generation
  directory outright.
- Publication is owner/guardian only; viewers get 403. Publishing
  without a selected default is a clean 409.

## Known limitations / remaining work

- `categories.json` is published structurally valid but empty
  (`domains: {}`); category rules therefore resolve to no matches.
  The real category dataset and compilation pipeline are Milestone 3.
- Front ends are initial slices: no policy editing UI, no audit-trail
  view, no user/guardian management UI yet. Admin dashboard writes are
  real (they drove the API in the evidence run) but coverage is thin.
- Per-tenant publication roots are not yet isolated on disk (single
  configured root); multi-tenant isolation of the publication tree is
  owed before any real second tenant exists.
- MFA enrollment/management UI is not in this slice (API from
  Milestone 1).
