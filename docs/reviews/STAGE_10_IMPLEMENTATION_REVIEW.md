# Stage 10 Implementation Review

Date: 2026-11-15. Author: implemented on the `stage-9b-deployment-preparation`
branch of `yossigo88-cyber/kosherguard-platform`. This document is the review
evidence required by the Stage 10 authorization. It describes what was built,
how it was proven, and what is honestly not done.

## 1. Starting and ending points

- Starting HEAD (verified before any work):
  `c8008472fa57730301f6cc836d21d617423d836f`
  (`docs: add Stage 10 technical roadmap`)
- Main before, during, and after: `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`
  - never modified, never merged into, never deployed from.
- Ending HEAD: the final Stage 10 commit on the branch (see section 2; the
  branch tip after this document's commit is reported alongside it).

## 2. Commits (in order, oldest first)

| # | SHA | Message |
|---|-----|---------|
| 1 | `3ed3c6ca3333aef5bb5d875c82985e703ef7a17b` | Stage 10: policy versions, publication state, config revisions schema + migration |
| 2 | `b6212f9fdeba6749d11effa443bb93c35c8f969b` | Stage 10: atomic generation-based configuration publisher |
| 3 | `d1f4be3af25c92b914704371db70bf7c3b628822` | Stage 10: policy versioning, publication selection, config publish and rollback |
| 4 | `bd0dcf0a9e4363e544845ae80500af97b1ee5a8b` | Stage 10: publication API routes and publish directory wiring |
| 5 | `6e79e6eede03f2ec8d75adce783405ceb97f1a1e` | Stage 10: fail-safe hot reload (SIGHUP, watch, status file) |
| 6 | `ce9c25afaff6e2a2d83345aa4ebb6c8c73bd4997` | Stage 10: hot reload tests incl. real-subprocess SIGHUP |
| 7 | `2cea155a7e6b6e6f341535bf78c3df1beee76559` | Stage 10: publish directory in the test server fixture |
| 8 | `2c3e0047dd62f708d307a2cc97ebfac8505a0ba4` | Stage 10: policy version history and rollback tests |
| 9 | `20be8a067814a1f0529ea544e87080e08a0a8cda` | Stage 10: publication, history, and safety tests |
| 10 | `972a48d2415ae430d17b2f817b411034b09f2316` | Stage 10: end-to-end dashboard-to-DNS proof test |
| 11 | `f1addf7c7ad3cd8d64e380f7f8d3572465e565b0` | Stage 10: publication page, version history, selection in the UI |
| 12 | `05fc6b34c23123210f69b4263a14b4ce51fdc065` | Stage 10: publication navigation entry |
| 13 | `256fa2cfe0bd1c48c79ab3bbfb426b4843ab6207` | Stage 10: systemd unit for the DNS engine with reload wiring |
| 14 | `6a5a9d31ae5f19d9d199d0dbbb082a5b659b43ad` | Stage 10: publish directory for the dashboard unit |
| 15 | `f34f9b6ff6fe5a24dea764cd1edf8ffc966a2864` | Stage 10: ignore the local publication output directory |
| 16 | `e2a5efb8a06c1599ca5a12b92fe273e6237f6d1c` | Stage 10: document the publication loop and rollback |
| 17 | `6691608f1ac7793f97325e28a7b73cef3bf09df8` | Stage 10: publication loop summary and accurate test counts |
| 18 | `d5c29439ec0b6a94861f0e9833285df6c351d694` | Stage 10: publication API, publishing module, test count |
| 19 | `36b562fe8f879c2193abeca81f6bd79a9f017656` | Stage 10: hot reload documentation and test count |

Commits are one file per commit because the GitHub web editor commits a
single file at a time; the Stage 10 authorization accepts web-editor
commits. No commits were squashed. github.dev was not used (it demands a
new OAuth grant, which is not authorized).

## 3. Files created, modified, deleted

Created:

- `dashboard/src/publishing.py` - the generation publisher (section 6).
- `dashboard/tests/test_policy_versions.py` - 9 policy-history tests.
- `dashboard/tests/test_publishing.py` - 16 publication tests.
- `dashboard/tests/test_end_to_end.py` - the end-to-end acceptance test.
- `filtering-engine/tests/test_reload.py` - 10 hot-reload tests.
- `deploy/kosherguard-engine.service` - systemd unit for the DNS engine.
- `docs/reviews/STAGE_10_IMPLEMENTATION_REVIEW.md` - this document.

Modified:

- `dashboard/src/db.py` - three new tables + migration (section 5).
- `dashboard/src/store.py` - versioning, selection, publish, rollback,
  status (sections 4-7).
- `dashboard/src/server.py` - new API routes, `--publish-dir` /
  `KG_PUBLISH_DIR` wiring.
- `dashboard/tests/conftest.py` - the test server fixture gets a
  temporary publish directory.
- `dashboard/static/app.js` - Publication page, policy version history
  with rollback, selected-for-publication badges.
- `dashboard/static/index.html` - Publication navigation entry.
- `filtering-engine/src/dns_service.py` - fail-safe hot reload (section 8).
- `deploy/kosherguard-dashboard.service` - `KG_PUBLISH_DIR` environment.
- `.gitignore` - ignores the local publication output directory.
- `docs/deployment/RUNBOOK.md` - the publication loop procedure.
- `README.md`, `dashboard/README.md`, `filtering-engine/README.md` -
  accurate scope and test counts.

Deleted: none.

## 4. Architecture before and after

Before: the dashboard and the engine shared CODE only (the dashboard
reuses the engine's validators and PolicyEngine through
`engine_bridge.py`). The engine loaded its policy and category JSON
files once at startup; nothing the dashboard did could reach it. There
was no policy versioning, no publication, no reload.

After: a deliberate control-plane loop.

1. Every policy mutation in the dashboard appends an immutable
   `policy_versions` snapshot. Rollback adds a new version; history is
   never modified.
2. One policy is explicitly SELECTED FOR PUBLICATION (a single-row
   `publication_state` table). The selected policy cannot be disabled or
   deleted until another is selected - the publication pointer can never
   dangle.
3. Publish (`POST /api/config/publish` or the Publication page) exports
   the selected policy plus ALL configuration inputs that affect
   filtering (allow/block rules, category rules, domain records,
   domain-category assignments, enabled/disabled categories) as the
   engine's exact two JSON documents, validated by the engine's own
   code, and records them in an immutable `config_revisions` row with
   SHA-256 content hashes before anything touches disk.
4. The publisher writes a new immutable generation directory, verifies
   it FROM DISK, and atomically switches the `current` symlink. A failed
   publish keeps the previous generation live and records the failure.
5. The engine reloads fail-safe: a complete replacement engine is built
   and validated (including manifest hash verification) before one
   immutable reference is swapped. Rejection keeps the last valid
   configuration serving.
6. The engine writes `engine-status.json` after every load attempt; the
   dashboard shows a configuration as live only when the engine's own
   status confirms it is enforcing the published revision.

## 5. Database migration

Three new tables (full DDL in `dashboard/src/db.py`):

- `policy_versions(policy_id, version, name, description,
  default_policy, enabled, engine_json, admin, note, created_at)` -
  primary key (policy_id, version); intentionally no foreign key to
  `policies`, so history survives policy deletion.
- `publication_state(id CHECK id=1, selected_policy_id, selected_by,
  selected_at, active_revision)` - exactly one row.
- `config_revisions(revision AUTOINCREMENT, policy_id, policy_name,
  policy_version, admin, created_at, policy_json, categories_json,
  policy_sha256, categories_sha256, generation, status
  ('pending'|'published'|'failed'), detail)` - stores the EXACT
  published JSON of both documents, so any historical published
  configuration is recoverable and republishable even if the files on
  disk are gone.

Migration: `init_db` gives every pre-Stage-10 policy an initial version
1 snapshotted from its current content, attributed to
`system-migration` (not to a person). It is idempotent and covered by
`test_migration_gives_existing_policies_version_one`.

## 6. Policy-versioning and published-configuration design

Policy versions: create, update, enable, disable, and delete each append
a snapshot of the complete normalized engine-format content with the
acting administrator and timestamp. `POST /api/policies/<id>/rollback
{"version": n}` copies version n's content into the live policy and
records it as a NEW version (`note: "rollback to version n"`). Audit
entries carry version numbers.

Published configurations: each publish or configuration rollback creates
one `config_revisions` row containing the exact published bytes of both
documents, their hashes, the acting admin, and the generation directory
name. `POST /api/config/rollback {"revision": n}` republishes revision
n's stored content as a new revision; the historical row and its
generation are never touched. `GET /api/config/status` reports the
selected policy, the active revision, an `unpublished_changes` flag
(computed by hashing a fresh in-memory export and comparing with the
active revision's hashes - a real comparison, not a guess), the on-disk
generation, and the engine's self-reported status.

## 7. Atomic publication mechanism

Implemented in `dashboard/src/publishing.py`; POSIX semantics (the
deployment target is Linux under systemd):

1. In-memory validation with the engine's own `validate_policy` and
   `CategoryDB`.
2. `generations/<revision>` created with `O_EXCL` semantics
   (`os.mkdir`), mode 0700 - a revision number is used once, so
   concurrent publishes can never write the same generation.
3. `policy.json` and `categories.json` each written to a uniquely named
   temp file in the same directory, fsynced, chmod 0600, atomically
   renamed into place.
4. `manifest.json` records the revision and both SHA-256 hashes.
5. The generation is re-read from disk, re-validated, and hash-checked
   before it can become current.
6. `current` is switched by creating a new symlink and `os.replace`-ing
   it over the old one (atomic rename). Readers see the complete old or
   the complete new generation, never a mixture.

Failure at any step before 6: `current` keeps pointing at the previous
complete generation, the partial generation directory is removed
best-effort, the revision row is marked `failed`, and the failure is
audited. Concurrent publishes are serialized by an `flock` advisory lock
on `<root>/.publish.lock` plus a process-local lock. Stale temp files
are cleaned.

## 8. Reload and concurrency design (engine)

`filtering-engine/src/dns_service.py`:

- `load_validated_engine()` reads both files, verifies the generation
  manifest's hashes when a manifest exists (rejecting corrupted or
  mixed-generation file sets), parses, and validates with the engine's
  own validators, returning a COMPLETE new `PolicyEngine`. Nothing is
  mutated.
- `DNSFilteringService.reload_from_paths()` activates the replacement
  with a single reference assignment. `handle_packet` reads the engine
  reference exactly once per query, so every query evaluates against one
  complete engine instance and in-flight queries finish against the
  previous (never mutated) engine object. Any failure is logged loudly,
  recorded in `last_reload_error` and the status file, and returns
  False; the service keeps answering with the last valid configuration.
- Triggers: SIGHUP (the handler only sets a `threading.Event`; all file
  I/O and validation run in the service's normal loop) and an optional
  `--watch SECONDS` poll that notices a new generation through the
  resolved `current` path (and does not retry an identity that already
  failed).
- `--status-file` atomically (temp + rename) writes the ACTIVE
  configuration identity - paths, SHA-256 hashes, generation, revision,
  reload count, trigger, timestamp, and the last rejected reload - after
  every load attempt. A rejected reload never appears as active.

## 9. Security considerations

- No new authentication surface: every new endpoint sits behind the
  existing session + CSRF-header checks and the existing request-body
  limits. No existing protection was weakened.
- Publication output is owner-only: 0700 directories, 0600 files,
  matching the Stage 9B hardening. The systemd units run both services
  as the same `kosherguard` user.
- The engine never executes or interprets manifest content beyond hash
  comparison; policy/category content is validated by the engine's own
  strict validators before use, exactly as at startup.
- The dashboard reads `engine-status.json` as untrusted display data; it
  drives no decisions. The UI escapes every rendered value.
- No secrets, identifiers, or personal data were added to the
  repository; commits are authored under the owner's GitHub noreply
  identity.
- The selected-policy guard (no disable/delete while selected) removes
  the ambiguous-state class of errors rather than handling it after the
  fact.

## 10. Test commands and exact results

Commands run on the development tree (Python 3.10.12, pytest 8.x,
dnslib 0.9.x):

```
python3 -m pytest dashboard/tests -q        # 157 passed (was 131; +26 new)
python3 -m pytest filtering-engine/tests -q # 129 passed (was 119; +10 new)
bash -n deploy/backup.sh deploy/restore.sh  # clean
node --check dashboard/static/app.js        # clean
```

New tests (36 total):

- `dashboard/tests/test_policy_versions.py` (9): create/update/enable/
  disable/delete snapshot behavior, immutability of history, sequential
  numbering, rollback creating a new version with the exact prior
  content, admin/timestamp attribution, audit entries carrying version
  numbers, and the pre-Stage-10 migration.
- `dashboard/tests/test_publishing.py` (16): selection semantics
  (publish without selection fails; disabled policy cannot be selected;
  selected policy cannot be disabled or deleted), published content
  correctness, engine validation of published files, domain/category/
  enabled-state reflection, policy selection changes, the
  unpublished-changes flag, complete configuration history with content
  hashes, configuration rollback publishing a new revision with the
  prior exact content, owner-only permissions, temp-file cleanup, failed
  publish keeping the previous generation (simulated pointer-switch
  failure), real concurrent publishes from four threads producing four
  complete generations, and status reporting with no engine present.
- `filtering-engine/tests/test_reload.py` (10): successful reload
  changing real UDP and TCP answers, rejection of an invalid policy, an
  invalid category database, a missing file, and a corrupted generation
  (manifest hash mismatch), last-known-good retention, service health
  after repeated failed reloads, in-flight safety across 40 real reloads
  under query load, status-file accuracy, a REAL SUBPROCESS SIGHUP test
  (signal, reload, observable DNS change, rejection of a broken config,
  process still healthy), and a real-subprocess `--watch` test.
- `dashboard/tests/test_end_to_end.py` (1): the acceptance test - real
  dashboard server plus a real DNS service subprocess sharing a real
  publication root. Category, domain, and policy created through the
  dashboard API; publish; bounded polling until the engine's status file
  reports the new revision; real DNS UDP answers change to the sinkhole
  for the newly blocked domain (subdomains included) and TCP answers
  match; the dashboard then reports `engine_matches_active_revision:
  true`; policy changed and republished, answers change again; rollback
  publishes a new generation and the DNS answers revert. No sleeps: all
  synchronization is bounded polling on observable state.

Fresh-clone runs of both suites on the committed branch are reported in
the final report message alongside this document (the clone is taken
after this file's commit, so its results cannot be embedded here).

Per-run honesty: the pre-existing engine suite has historically shown
one intermittent failure
(`test_truncated_udp_upstream_large_answer_complete_over_tcp_downstream`,
which passes in isolation and on rerun) and occasional transient
warnings; see the final report for the exact per-run outcomes of this
stage's runs.

## 11. Known limitations

- The engine's status file requires the engine and dashboard to share a
  filesystem (true in the documented single-host systemd deployment).
  Without it the dashboard honestly shows the engine state as unknown.
- `--watch` polling means a publication can take up to the watch
  interval to reach the engine absent a SIGHUP; the units set 5 seconds
  and `systemctl reload kosherguard-engine` forces an immediate reload.
- The publication layout uses POSIX symlinks and flock; it targets the
  documented Linux deployment and is not portable to Windows.
- The new systemd engine unit is reviewed but NOT tested on a live
  system, exactly like the Stage 9B assets; the pre-launch checklist
  covers verifying it.
- The UI's version-history view shows metadata, not full rule content
  (the API returns complete content for any version or revision).
- Policy category rules can reference categories with no domains; the
  engine treats that as a rule that matches nothing (unchanged
  pre-existing behavior, preserved deliberately).

## 12. Scope confirmations

- Nothing was merged into main; main is unchanged at
  `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`.
- Nothing was deployed. No server was provisioned; no paid service was
  used.
- Apple MDM remains unimplemented and blocked on the four missing
  prerequisites documented in `docs/MDM_ENROLLMENT_AND_PUSH.md`. No
  iPhone is enrolled, managed, or receiving remote updates, and nothing
  in this stage claims otherwise.
- No new GitHub permissions or OAuth scopes were requested; all commits
  went through the standard web file editor.
- Existing engine behavior (precedence, allow/block semantics, category
  and subdomain matching, validation, UDP/TCP handling, concurrency
  limits, bounded shutdown) was preserved: the full pre-existing suites
  pass unchanged, and the dashboard continues to reuse the engine's own
  code rather than duplicating policy logic.
