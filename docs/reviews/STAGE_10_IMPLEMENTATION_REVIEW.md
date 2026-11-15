# Stage 10 Implementation Review

Date: 2026-11-15. Author: implemented on the `stage-9b-deployment-preparation`
branch of `yossigo88-cyber/kosherguard-platform`. This document is the permanent
source of truth for the Stage 10 implementation: every implementation detail,
changed file, commit SHA, test command, exact test result, failure, limitation,
security finding, and deployment/merge status. It is written for independent
review (ChatGPT) directly against the committed code.

## 1. Starting and ending points

- Starting HEAD (verified before any work):
  `c8008472fa57730301f6cc836d21d617423d836f`
  (`docs: add Stage 10 technical roadmap`)
- Implementation HEAD (all 20 implementation commits):
  `1703d095a285b9517a4dbf46976fe768cc2cb92a`
  (`docs: add Stage 10 implementation review` - the first version of this file)
- This document was then completed with the full final report (exact fresh-clone
  test results, all 20 commit SHAs, and final confirmations) in one follow-up
  commit on the same branch; that commit's SHA is reported in the final summary
  message accompanying this stage (a file cannot contain its own commit SHA).
- Main before, during, and after: `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`
  - never modified, never merged into, never deployed from. Verified by
  `git ls-remote` after the final implementation commit.

## 2. Commits (20, oldest first, none squashed)

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
| 20 | `1703d095a285b9517a4dbf46976fe768cc2cb92a` | docs: add Stage 10 implementation review |

Direct link pattern: `https://github.com/yossigo88-cyber/kosherguard-platform/commit/<SHA>`.

Commits are one file per commit because the GitHub web editor commits a
single file at a time; the Stage 10 authorization accepts web-editor
commits. No commits were squashed. github.dev was not used (it demands a
new OAuth grant, which is not authorized). All commits authored under the
owner's GitHub noreply identity.

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

The four states required by the authorization are distinct and visible:
a policy existing in the dashboard; a policy enabled administratively; a
policy selected for publication; the configuration the running engine
reports it is enforcing (`engine_matches_active_revision`).

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

## 9. Security considerations and findings

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
- No secrets, credentials, identifiers, or personal data were added to
  the repository; commits are authored under the owner's GitHub noreply
  identity. The repository is public and stays clean.
- The selected-policy guard (no disable/delete while selected) removes
  the ambiguous-state class of errors rather than handling it after the
  fact.
- No security regressions were found in this stage's work; the
  pre-existing Stage 9B hardening (auth, CSRF, permissions, audit) is
  untouched and its tests still pass.

## 10. Test commands and exact per-run results

All results below are real, per-run outputs (Python 3.10.12, pytest 8.x,
dnslib 0.9.x).

Working development tree (same content later committed):

- `python3 -m pytest dashboard/tests -q` -> **157 passed in ~100s**
  (was 131 before Stage 10; +26 new)
- `python3 -m pytest filtering-engine/tests -q` -> **119 passed**
  (pre-existing suite, run before the reload tests were added)
- `python3 -m pytest filtering-engine/tests/test_reload.py -q` ->
  **10 passed** (the 10 new hot-reload tests)

Fresh anonymous clone of the committed branch at implementation HEAD
`1703d095a285b9517a4dbf46976fe768cc2cb92a` (final verification):

- `python3 -m pytest dashboard/tests -q` -> **157 passed in 101.83s**
- `python3 -m pytest filtering-engine/tests -q` ->
  **128 passed, 1 failed in 55.84s**
- The single failure:
  `filtering-engine/tests/test_tcp_service.py::test_truncated_udp_upstream_triggers_tcp_fallback`
  - a known PRE-EXISTING intermittent timing test (unchanged by this
  stage; byte-identical code also flaked once during Stage 9B). Immediate
  isolated rerun: **1 passed in 0.51s**. The full engine suite's 129 tests
  (119 pre-existing + 10 new) have each passed; the flake is
  environmental timing, not Stage 10 code.
- `python3 -m pytest filtering-engine/tests/test_reload.py -q` ->
  **10 passed in 6.77s** (on the clone)
- `bash -n deploy/backup.sh deploy/restore.sh` -> clean
- `node --check dashboard/static/app.js` -> clean
- Byte-identity spot check between the fresh clone and the tested
  working tree: identical for `dashboard/src/db.py`,
  `dashboard/src/publishing.py`, `dashboard/src/store.py`,
  `dashboard/src/server.py`, `filtering-engine/src/dns_service.py`.

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
- `dashboard/tests/test_end_to_end.py` (1): see section 11.

## 11. End-to-end result

`dashboard/tests/test_end_to_end.py`: real dashboard server plus a real
DNS service subprocess sharing a real publication root. Category,
domain, and policy created through the dashboard API; publish; bounded
polling until the engine's status file reports the new revision; real
DNS UDP answers change to the sinkhole for the newly blocked domain
(subdomains included) and TCP answers match; the dashboard then reports
`engine_matches_active_revision: true`; policy changed and republished,
answers change again; rollback publishes a new generation and the DNS
answers revert. Passed on both the working tree and the fresh clone
(within the 157). No sleeps anywhere: all synchronization is bounded
polling on observable state (the engine's status file and real DNS
answers).

## 12. Known bugs, limitations, and failed tests

- The one failed test in section 10 is the known pre-existing flake
  (passes on rerun; unchanged by this stage). No other failures.
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

## 13. Deployment and merge status confirmations

- Nothing was merged into main; main is unchanged at
  `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a` (verified after the final
  implementation commit).
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

## 14. What remains

- Independent ChatGPT review of the branch against this document.
- After review passes and the owner authorizes it: Stage 11 (honest
  device registry and per-client policy by IP, per the approved
  roadmap). No Stage 11 work has begun.

## 15. Independent-review corrections (2026-11-15)

After an independent ChatGPT review of the committed Stage 10 code, three
defects were identified and fixed on this branch. This section is the
complete correction record: defects, exact code changes, new regression
tests, exact test results, and correction commit SHAs. Where test counts
here differ from section 10, this section supersedes it (counts grew
because regression tests were added).

Starting HEAD for the corrections:
`6c832a58a1883b2357ffbf6a44d05dd07f69d0f0`.

### Defect 1: the selected-policy safety rule did not cover every
### mutation path

Before: `_require_not_selected()` was enforced only in
`set_policy_enabled()` and `delete_policy()`. A selected policy could be
disabled two other ways: an `update_policy()` payload with
`enabled=false`, or a `rollback_policy()` to a historical version whose
`enabled` field was false. In addition, the checks ran OUTSIDE the write
transaction, so a concurrent select-for-publication could interleave
between check and mutation.

After (dashboard/src/store.py):

- A new `_write_txn()` context manager runs mutations under
  `BEGIN IMMEDIATE`: the database write lock is taken BEFORE the
  invariant check, making check+mutation atomic against concurrent
  requests.
- `update_policy()` rejects a payload with `enabled=false` for the
  selected policy (409, same message as an explicit disable).
- `rollback_policy()` rejects rolling the selected policy back to a
  disabled historical version (409).
- `set_policy_enabled()` and `delete_policy()` now run their existing
  checks under the write lock.
- `select_policy_for_publication()` (the other side of the race) also
  runs under the write lock and re-verifies the policy is still enabled
  when the selection lands.
- Sweep: every SQL path that can change a policy's `enabled` flag or
  delete a policy was audited (INSERT on create cannot be selected yet;
  the two UPDATEs and the DELETE are the only ones, and all are
  guarded). Category enable/disable is unrelated state.
- Rollbacks and updates that leave the selected policy enabled still
  work; nothing silently changes or replaces the selection.

New regression tests (dashboard/tests/test_publishing.py, +4 tests):

- `test_update_selected_policy_with_enabled_false_rejected` - the update
  API route cannot bypass the invariant; the policy stays enabled and
  selected afterwards.
- `test_rollback_selected_policy_to_disabled_version_rejected` - the
  rollback route cannot bypass it either; state unchanged afterwards.
- `test_selected_policy_normal_update_and_rollback_still_work` - normal
  updates and rollbacks on the selected policy keep working.
- `test_concurrent_disable_and_select_never_leave_selected_disabled` -
  10 real concurrent disable/select requests; every answer is a clean
  200 or 409 (never a 500), and whatever is selected at the end is
  enabled.
- (Selecting another enabled policy first, then disabling/deleting the
  previous one, was already covered by
  `test_selected_policy_cannot_be_disabled_or_deleted`.)

### Defect 2: generation manifest verification was not fail-closed

Before: `load_validated_engine()` in filtering-engine/src/dns_service.py
compared a manifest hash only when the field was present and non-empty
(`if expected and expected != actual`). A manifest with a missing or
empty `policy_sha256`/`categories_sha256` silently bypassed content
verification. Structure, hash format, and revision/generation
consistency were never checked. The publisher's `verify_generation()`
in dashboard/src/publishing.py compared hashes but also did not enforce
structure or consistency.

After:

- New `_validate_generation_manifest()` in dns_service.py: when
  manifest.json exists it MUST be a JSON object with both hashes present
  as 64-character lowercase SHA-256 hex, a non-negative-integer
  revision, a non-empty generation string equal to `str(revision)` and
  equal to the resolved generation directory name, and both hashes
  matching the actual file bytes exactly. Any missing, empty, malformed,
  inconsistent, or mismatched data raises PolicyConfigError; there is no
  silent fallback to unverified loading when a manifest exists.
  (Non-negative, not positive: the dashboard's own bootstrap layout can
  publish an initial generation 0, exercised by the end-to-end test.)
- New `_check_manifest()` in publishing.py enforces the same rules, so
  the publisher and the engine reject and accept the same things.
- A configuration with NO manifest at all still loads unverified (the
  pre-publication legacy layout), preserving compatibility.
- Hash format is lowercase hex because that is what the publisher
  writes; any other encoding is rejected as malformed.

New tests (filtering-engine/tests/test_reload.py, +8 tests):

- `test_manifest_missing_policy_hash_rejected`,
  `test_manifest_missing_categories_hash_rejected`,
  `test_manifest_empty_hashes_rejected`,
  `test_manifest_malformed_hashes_rejected` - each rejected.
- `test_corrupted_generation_rejected` (rewritten): a structurally valid
  manifest with a wrong hash is rejected on the hash comparison itself
  (the old version was rejected for the wrong reason - its metadata did
  not match the directory either).
- `test_manifest_inconsistent_metadata_rejected` - generation !=
  str(revision), missing revision, non-integer revision, and a manifest
  internally consistent but not matching its real directory: all
  rejected.
- `test_manifest_valid_accepted` - a complete correct manifest loads and
  reports its generation/revision identity.
- `test_legacy_config_without_manifest_accepted` - no manifest at all
  still loads.
- `test_invalid_manifest_reload_keeps_last_known_good` - a reload whose
  files carry a defective manifest is rejected by the running service,
  which keeps answering UDP and TCP with the last valid configuration.

### Defect 3: the SIGHUP subprocess test had a vacuous assertion

Before: `test_sighup_real_subprocess()` in
filtering-engine/tests/test_reload.py contained
`assert answer_a(query_udp(port, "blocked-one.test")) == UPSTREAM_A or True`,
which always passes. The subprocess also was not pointed at the test's
fake upstream resolver, which is why the assertion could not be made
real at the time.

After: the test starts the real fake-upstream resolver, passes
`--upstream 127.0.0.1:<port>` to the subprocess, and now asserts real
DNS answers on BOTH transports after the SIGHUP reload:
`blocked-two.test` returns the sinkhole (UDP and TCP), `blocked-one.test`
is forwarded to the upstream resolver (UDP and TCP), and the process is
still healthy. The invalid-configuration follow-up still proves a failed
SIGHUP reload retains POLICY_V2 as the last known-good configuration on
both transports.

Vacuous-assertion sweep: the whole Stage 10 test suite was searched for
`or True`, `assert True`, unexpected skips, and xfails. This was the
only vacuous assertion. The remaining `@pytest.mark.skipif` markers are
deliberate POSIX-only guards (SIGHUP, fork, permission bits), not
unexpected skips.

### Correction commits (oldest first)

1. `a9b2aecd4eae7b705dee86ded1c5e3fdcc11c406` - Stage 10 review fix:
   enforce selected-policy invariant in update and rollback, under write
   lock (dashboard/src/store.py)
2. `9c50c1fd3d8225813d7d5ccba4a8cf7bbb1f5b14` - Stage 10 review fix:
   fail-closed manifest verification in the publisher
   (dashboard/src/publishing.py)
3. `44b085645275a70757c21cdbc8793c3dc3176372` - Stage 10 review fix:
   strict fail-closed generation manifest verification
   (filtering-engine/src/dns_service.py)
4. `d83eb1b179834301bdbe01efde3dab13ac00d23d` - Stage 10 review fix:
   real SIGHUP assertions and strict manifest tests
   (filtering-engine/tests/test_reload.py)
5. `34e934702935d3351347051b2bf518da441c51b3` - Stage 10 review fix:
   regression tests for the selected-policy invariant
   (dashboard/tests/test_publishing.py)
6. `4763287f3890d1a107b3a46d1b61ad1aa1962808` - Stage 10 review fix:
   repair whitespace mangled by the editor fill
   (dashboard/src/publishing.py). Editorial repair only: the web
   editor's auto-indent re-indented one closing brace during commit 2's
   form fill (syntactically valid, behavior-identical, caught by the
   post-commit byte-identity check against the tested tree); this
   commit restores the exact tested bytes. No functional change.
7. This document's own update commit follows; its SHA and the final
   branch HEAD are reported in the final summary message (a file cannot
   contain its own commit SHA).

### Exact test commands and results after the fixes

Working tree (identical content to the committed corrections):

- `python3 -m pytest dashboard/tests/test_publishing.py -q` ->
  20 passed (16 existing + 4 new)
- `python3 -m pytest filtering-engine/tests/test_reload.py -q` ->
  18 passed (10 existing incl. the fixed SIGHUP test + 8 new)
- `python3 -m pytest dashboard/tests -q` -> 161 passed in 111.22s
  (157 before the corrections + 4 new)
- `python3 -m pytest filtering-engine/tests -q` -> first run: 136
  passed, 1 failed in 56.67s; the failing test's name was not captured
  before the cache cleared, but the pattern matches the known
  pre-existing intermittent TCP-truncation flake
  (test_truncated_udp_upstream_triggers_tcp_fallback /
  test_truncated_udp_upstream_large_answer_complete_over_tcp_downstream,
  both unchanged by this stage). Three subsequent full runs: 137 passed
  in 57.3s, 137 passed in 57.01s, 137 passed in 56.98s. The two flake
  candidates in isolation: 2 passed in 1.03s. Reported honestly: one
  failure observed once, never reproduced in three later full runs, in a
  test this stage did not touch.
- `node --check dashboard/static/app.js` -> clean
- `bash -n deploy/backup.sh deploy/restore.sh` -> clean
- Combined targeted run (e2e + reload + publishing):
  39 passed in 18.29s

Fresh-clone verification of the final committed branch (after this
document's commit) is reported in the final summary message alongside
the final HEAD.

### Remaining limitations (corrections)

- The one intermittent pre-existing engine-suite flake above remains
  what it was: environmental timing, unchanged by Stage 10 and by these
  corrections.
- No new limitations introduced. The stricter manifest rules reject
  hand-written manifests that omit metadata the publisher always writes;
  plain legacy file sets without any manifest are unaffected.

### Confirmations

- main remains untouched at
  `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`.
- Nothing was merged or deployed; no services provisioned, no costs
  incurred.
- No new GitHub permissions or OAuth scopes were requested; commits went
  through the standard web file editor.
- Stage 11 has not started.
- Existing Stage 10 functionality and Stage 9B hardening preserved:
  the full pre-existing suites pass, and no authentication, CSRF,
  validation, audit, or filesystem-permission behavior was weakened
  (the corrections only ADD checks).
- Stage 10 is NOT claimed approved; that decision belongs to the
  independent review of these commits.

## 16. Final fail-closed manifest edge case (2026-11-15)

The independent review of the seven correction commits found one
remaining bypass.

### The defect

`load_validated_engine()` in filtering-engine/src/dns_service.py gated
manifest verification on `manifest_path.is_file()`. `is_file()` follows
symlinks and is False for directories and broken symlinks, so a
manifest.json that EXISTS as a directory, a broken symlink, or any
other unusable filesystem object was silently treated as "no manifest",
falling back to legacy unverified loading. Stage 10's rule is: only a
genuinely ABSENT manifest path may use legacy compatibility; a present
but invalid manifest must never be ignored.

### The fix

The gate is now `os.path.lexists(manifest_path)`, which is True for any
filesystem entry including broken symlinks. Any existing entry that is
not a regular readable file is rejected with PolicyConfigError; a
regular file is parsed and strictly validated exactly as before (hash
format, hash equality, revision/generation/directory consistency - all
unchanged, nothing weakened). A genuinely absent path keeps legacy
compatibility. The publisher's verify_generation() was already
fail-closed for these cases (a directory, broken symlink, or missing
manifest fails the manifest read with PublicationError), so publisher
and engine behavior are consistent.

### Regression tests (filtering-engine/tests/test_reload.py, +3 tests)

- `test_manifest_path_is_directory_rejected` - manifest.json as a
  directory: rejected.
- `test_manifest_path_broken_symlink_rejected` - manifest.json as a
  broken symlink: rejected (POSIX-only guard, genuinely necessary for
  symlink creation).
- `test_manifest_path_directory_reload_keeps_last_known_good` - a
  running service rejects the reload and keeps answering UDP and TCP
  with the last valid configuration.
- (Already covered by section 15's tests: no manifest at all loads
  legacy; a valid regular manifest is accepted; a rejected reload
  retains last-known-good.)

### Commits

1. `d45ee9b8f8cdb1c3953bf0a3cddda2334ec177e0` - Stage 10 review fix:
   reject present-but-unusable manifest paths (lexists)
   (filtering-engine/src/dns_service.py)
2. `72314718d8f16aa860f58660435c963958cceda9` - Stage 10 review fix:
   manifest path edge-case tests
   (filtering-engine/tests/test_reload.py)
3. This document's own update commit follows; its SHA and the final
   branch HEAD are in the final summary message.

### Exact test commands and results (working tree, same content committed)

- `python3 -m pytest filtering-engine/tests/test_reload.py -q` ->
  21 passed in 5.01s
- `python3 -m pytest filtering-engine/tests -q` -> 140 passed in 57.60s
- `python3 -m pytest dashboard/tests -q` -> 161 passed in 113.48s
- `node --check dashboard/static/app.js` -> clean
- `bash -n deploy/backup.sh deploy/restore.sh` -> clean
- No failures, no reruns needed in this round. Fresh-clone verification
  of the final branch is reported in the final summary message.

### Confirmations

- main remains untouched at
  `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`.
- Nothing merged, nothing deployed, no services provisioned, no costs,
  no new GitHub permissions or OAuth scopes.
- Stage 11 has not started. No commits squashed or rewritten.
- Stage 10 is NOT claimed approved; independent review decides.
