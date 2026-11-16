# Stage 11C Implementation Review: Engine Multi-Policy Support

**Status: READY FOR INDEPENDENT REVIEW. Not approved. Not deployed. Stage
11D/11E not begun.**

**Repository:** https://github.com/yossigo88-cyber/kosherguard-platform
**Working branch:** `stage-9b-deployment-preparation`
**Starting SHA (approved):** `c6966c197a4a10d2dd71c51483f778f42da8f581`
**Main (verified unchanged before and after work):** `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`
**Final SHA:** the branch HEAD at this report's commit; the completion
message records it. The fresh-clone verification in section 10 ran on a
clone of the branch and was verified file-identical to the tested
implementation tree; any commits after the verified clone SHA touch ONLY
this report file.

Stage 11C makes the DNS filtering engine multi-policy: one running
service chooses the correct policy for each query from the published
device/network binding map, using one immutable, fully validated engine
set. No dashboard file, schema, API, UI, or publication logic was
changed; Stage 11D (publisher) and 11E (last-seen) were not begun.

## 1. Starting and final SHA

See the header. Branch, starting HEAD, remote main, and a clean working
tree were verified before editing (`git checkout
stage-9b-deployment-preparation`; `git log -1` = `c6966c19...`;
`git ls-remote origin main` = `5f75d213...`). Before designing anything,
the Stage 10 reload implementation, the Stage 11A canonicalizer and
comparator, the full DNS engine tests, and
`docs/reviews/STAGE_11_TECHNICAL_PLAN.md` sections 3, 4.5, 6.2, 7.1,
7.2, 10, and 11 were re-read.

## 2. Exact changed files

1. `filtering-engine/src/generation_io.py` (new, 330 lines) - the shared
   fail-closed generation I/O layer. The Stage 10 descriptor-based safe
   open (`O_NOFOLLOW` where the platform has it, regular-file fstat
   check, read from the same descriptor) and the two-file manifest
   validation MOVED here from `dns_service.py` unchanged in behavior;
   added: `safe_open_generation_file` (the required-file variant),
   `read_fd_bytes`, `load_json_strict` (rejects duplicate JSON object
   keys), `validate_manifest_path_key` (traversal-safe manifest keys),
   and `validate_multidoc_manifest` (revision/generation/files
   structure).
2. `filtering-engine/src/engine_set.py` (new, 720 lines) - the immutable
   engine set and its loader: `EngineSetError` (subclasses
   `PolicyConfigError`), frozen `BindingRecord`, the immutable
   `EngineSet` (`MappingProxyType` maps; `policy_for_client` never
   raises), `binding_key_for_client` (delegates all canonicalization to
   the Stage 11A canonicalizer), strict `devices.json` validation,
   `load_validated_engine` (moved from `dns_service.py` verbatim), and
   `load_validated_engine_set` (directory -> multi-doc generation; file
   without a `devices.json` sibling -> legacy Stage 10 wrapped as a
   single-policy set; file WITH a `devices.json` sibling -> ambiguous
   mixed layout, rejected).
3. `filtering-engine/src/dns_service.py` (modified) - imports and
   re-exports from the two new modules (every existing import path and
   test hook, including `dns_service._safe_open_manifest` and
   `dns_service.load_validated_engine`, works unchanged); client-address
   threading: the UDP worker passes the datagram source to
   `handle_packet(data, client_addr=...)`, TCP peer addresses are
   recorded in a lock-guarded side map (`_conn_addrs`) so queued items
   keep their exact Stage 10 shape, and `_serve_tcp_conn` falls back to
   the recorded address; `handle_packet` reads the engine-set reference
   exactly once and resolves through `policy_for_client`; reload uses
   `load_validated_engine_set`; the status file gains `format`,
   `default_policy_id`, `policy_count`, `binding_count`, `device_count`,
   `devices_sha256` (never client addresses); `main()` and `--policy`
   help document directory mode.
4. `filtering-engine/src/address_canonicalization.py` (modified) -
   `canonical_source_key` now maps IPv4-mapped IPv6 sources
   (`::ffff:a.b.c.d` in every spelling) to the IPv4 binding key and
   strips IPv6 scope/zone IDs (`fe80::1%eth0`) before the /64 grouping;
   both behaviors were verified in a sandbox before being written.
5. `filtering-engine/tests/test_multi_policy.py` (new, 1548 lines, 107
   tests) - the full Stage 11C matrix (section 9). No existing test file
   was modified; the entire pre-existing suite passes untouched.
6. `filtering-engine/README.md` (modified) - the Stage 11C section:
   engine-set architecture, generation format, manifest schema and hash
   verification, resolution order, IPv4/IPv6 binding semantics,
   unknown-source fallback, group-not-identity, legacy compatibility,
   atomic reload, privacy, and the not-implemented list; layout and test
   count updates.
7. `README.md` (modified) - engine suite count (209 -> 316) and one
   Stage 11C architecture sentence (engine loads multi-policy
   generations; dashboard publication remains Stage 11D). No other root
   change was genuinely necessary.
8. `docs/reviews/STAGE_11C_IMPLEMENTATION_REVIEW.md` (new) - this file.

No file under `dashboard/`, `deploy/`, or any schema/migration was
modified. `git status` at completion shows exactly the files above.

## 3. Engine-set architecture

`load_validated_engine_set(policy_path, categories_path)` returns one
immutable `EngineSet`:

- `default`: the default `PolicyEngine` (always exists).
- `per_policy`: policy ID -> independently validated `PolicyEngine`,
  behind `MappingProxyType` (no mutable dict escapes).
- `bindings`: canonical binding key -> frozen `BindingRecord(device_id,
  policy_id, identity_class="network_binding")`.
- `credentials`: reserved, always empty; Stage 11C implements no token
  issuance, storage, authentication, or credential-based routing.

Validation is all-or-nothing: any malformed policy, binding, ID,
reference, hash, or required metadata rejects the entire generation
before anything is activated. The service holds one immutable reference
(`self.engine`); each query reads it exactly once, resolves the policy
from that one snapshot, and completes against it. `PolicyEngine`
instances are never mutated to switch policies.

The path contract is unchanged from the operator's point of view:
`--policy` either names a legacy `policy.json` (Stage 10 behavior,
unchanged) or a multi-document GENERATION DIRECTORY (typically the
publisher's atomically switched `current` symlink), in which case
`--categories` must name that same generation's `categories.json`
(mixed-generation file sets are rejected).

## 4. Generation format and manifest schema

```
generations/<revision>/
  policies/<policy_id>.json   one validated policy document per published policy
  categories.json             the shared category database
  devices.json                default policy pointer + binding map
  manifest.json               revision/generation identity + SHA-256 of EVERY file
```

`manifest.json`: `{"revision": <int>, "generation": "<revision as
string>", "files": {"<relative path>": "<sha256 hex>", ...}}`.
`generation` must equal `str(revision)` and the generation directory
name; `files` must list `categories.json`, `devices.json`, and
`policies/<id>.json` for exactly the referenced policy set (canonical
decimal IDs only - `policies/05.json` is malformed). Manifest keys are
validated as safe relative paths; duplicate keys are rejected at parse
time; unknown, extra, missing, or mismatched entries reject the
generation; every listed file's bytes are read through the
descriptor-based safe open and verified against its own hash before any
document is used; and a directory scan rejects any file on disk the
manifest does not list (unverified content in a verified generation).
The Stage 10 two-file manifest remains valid for legacy generations.

`devices.json` has a strict schema - exactly `default_policy_id`,
`bindings`, `credentials` (must be empty), optional `_meta` (a
`_meta.revision` must equal the manifest revision). Binding keys must be
the canonical strings produced by the Stage 11A canonicalizer (no other
spelling can appear). IDs are real positive integers; booleans are
rejected. Non-empty `credentials` rejects the generation.

Two contract decisions, resolved against the plan and recorded here in
full:

- **Exact referenced policy set.** Plan 7.3 defines the published policy
  set exactly: the publisher emits documents for the default policy and
  every policy referenced by an active assignment. A manifest listing a
  policy document nothing references therefore means devices.json and
  the policy set disagree - an inconsistent generation. It is rejected
  fail-closed: silently accepting it could mask a binding lost from
  devices.json, quietly demoting those clients to the default policy.
  The two failure classes are distinct and separately enforced: an
  unmanifested file on disk fails the directory scan; a manifested,
  hash-correct but unreferenced policy fails the referenced-set
  equality check.
- **Inline device metadata, with an explicit format limitation.** Plan
  7.1 fixes the devices.json schema at exactly the four keys above -
  there is no device inventory, and the engine never touches the device
  registry (no SQLite, file, or network access during request
  processing). Each binding must CARRY its device metadata inline: a
  missing, null, or malformed `device_id` rejects the whole generation.
  LIMITATION, stated plainly: a well-formed positive `device_id` does
  NOT prove the ID exists in the dashboard registry; that is not
  verifiable from this generation format, no registry lookup is
  performed at load time or per query, and registry existence is
  enforced upstream by the publisher (plan 7.1 exports only
  associations of active devices with active assignments). The required
  "binding referencing nonexistent device metadata is rejected" test
  proves the inline-metadata property only; it is not evidence about
  registry existence.

## 5. Address resolution behavior

Strict per-query order: (1) authenticated credential - a reserved
extension point that never fires in Stage 11C (no authenticated channel
exists, and no query is ever attributed to one); (2) exact IPv4 network
binding; (3) IPv6 /64 network/group binding; (4) the default policy.
Observed addresses go through the shared Stage 11A canonicalizer:
AF_INET and AF_INET6 socket tuples unpack to the host, IPv4 maps to its
dotted-quad key, IPv6 collapses to its /64 network key (never a /128
identity), IPv4-mapped forms map to the IPv4 key, and scope IDs are
stripped. An invalid, unsupported, malformed, or absent client address -
including a truncated address tuple - safely selects the default policy;
`policy_for_client` never raises and cannot crash request processing.
Callers that supply no address get exactly the historical behavior. A
shared address or prefix applies one policy to every client behind it;
bindings are group routing hints and are never described as
authenticated device identity (the only identity class the format
accepts is the literal string `network_binding`).

## 6. Legacy compatibility

A Stage 10 generation (`policy.json` + `categories.json` + optional
legacy two-file manifest, no `devices.json`) loads exactly as before:
the same validation, the same hashes, the single policy wrapped as the
engine set's default, every client unregistered, every DNS answer
unchanged. A legacy file set WITH a `devices.json` sibling is an
ambiguous mixed layout and is rejected loudly rather than guessed at.
The entire pre-existing suite (209 tests: service, concurrency, reload,
EDNS0, fallback, truncation, shutdown, logging, canonicalization,
comparator) passes with ZERO modifications to existing test files.

## 7. Atomic reload, concurrency, privacy

Reload builds a complete replacement engine set separately, validates
every document and hash, and swaps one immutable reference only after
everything succeeds; a rejected reload keeps the entire previous set
serving (last-known-good) and records the error. SIGHUP and `--watch`
are preserved and now reload whole engine sets through the publisher's
atomic symlink switch. In-flight queries finish on the snapshot they
captured at request start, proven by a gated-engine test that swaps the
active set mid-decision. Privacy: client addresses exist only in memory
during routing; the decision log and the status file never contain
client IPv4/IPv6 addresses or prefixes, credentials, or tokens, and
there are no last-seen timestamps. New status fields identify the engine
set and its generation only (`format`, `default_policy_id`,
`policy_count`, `binding_count`, `device_count`, `devices_sha256`);
`device_count` is the count of distinct device IDs referenced by
bindings, not a device list.

## 8. Not implemented (stage boundaries)

Dashboard publication of multi-policy generations (Stage 11D), DoH/DoT
listeners, token authentication and credential-based routing, Apple
MDM/APNs/ABM, real device enrollment, and last-seen reporting (Stage
11E) are all NOT implemented and NOT begun. No dashboard file, schema,
Store, API contract, or UI was touched. No deployment, DNS, firewall,
Oracle, Render, or production change occurred; no external server was
accessed; no merge, rebase, squash, force-push, or main update occurred;
no new dependency, paid service, or secret was introduced (the suite
uses the existing pinned `dnslib` and the standard library only).

## 9. Test commands and exact results (full honesty trail)

All runs: `cd filtering-engine && python3 -m pytest tests/ -q`
(or the named subset), Python 3.10, pytest 8.4, dnslib 0.9, no internet
access (in-test fake upstream resolvers).

1. Baseline before any change: **209 passed** (58s) - matches the Stage
   11B record.
2. New-suite first run (`tests/test_multi_policy.py`, 104 tests at the
   time): **74 passed, 18 failed, 12 errors**. NOT hidden; every cause:
   - 12 errors + most failures: the test helper built generations
     listing policy documents that no binding referenced, which the
     loader's exact-referenced-set rule correctly rejects. Test-side
     fix: helpers build conforming generations (full binding set, or
     exactly the referenced policy documents).
   - `test_invalid_client_address_safely_selects_default`: REAL
     IMPLEMENTATION DEFECT - a one-element address tuple
     `("192.168.1.50",)` was accepted as a client and resolved its
     binding. Fixed: `binding_key_for_client` requires the
     `(host, port, ...)` socket-tuple shape, else the default policy.
   - Four parametrized extra/malformed-manifest cases: REAL ORDERING
     DEFECT - hash verification ran before entry classification, so a
     bad manifest entry reported as a hash mismatch. Fixed: entries are
     classified (known names, canonical policy IDs) before any file is
     hashed.
   - `test_symlinked_generation_files_rejected[categories.json]`: REAL
     DEFECT - the `--categories` equality check resolved the final
     symlink, so a symlinked categories.json was misreported as a
     mixed-generation set instead of reaching the `O_NOFOLLOW` check.
     Fixed: the directory is compared fully resolved, the final
     component literally; the symlink is rejected by the descriptor
     open.
   - `test_invalid_categories_rejects_entire_set`: rejection worked but
     the error did not name the file. Improvement: category-database
     errors are wrapped with the `categories.json` context.
3. Second run: **94 passed, 10 failed**. Causes: the same
   helper/generation mismatch in ad-hoc test generations (fixed by
   making `build_generation` default to exactly the referenced policy
   set), and `.hidden/x.json` raising `EngineSetError` where the test
   expects a policy-configuration error. Improvement: `EngineSetError`
   now subclasses `PolicyConfigError`, so existing reload/startup catch
   paths handle it unchanged.
4. Third run: **100 passed, 4 failed**. Causes: a helper `KeyError` on
   an intentionally invalid policy ID, a missing test import, and the
   SIGHUP/watch subprocess tests pointing at the real default upstream
   (no internet in the sandbox) with a stale `policy_count` assertion
   (2 referenced policies, not 4). All test-side; no behavioral
   assertion was weakened at any point in this trail.
5. New suite green: **104 passed**. Full suite: **313 passed** (70s).
6. Contract rework after design review (section 4): removed the
   ungrounded optional device-inventory map, added the unmanifested-file
   directory scan and its test, parametrized the inline-device-metadata
   test. Intermediate run: 4 failures - the symlink tests' link target
   lived inside the generation (tripped the new scan; moved outside,
   which is also the stronger test) and the concurrent-reload test
   republished generations in place, leaving stale policy files (the
   helper now wipes the directory first: the real publisher writes each
   generation into a FRESH directory, and in-place rewrite leaving
   strays is exactly what the scan rejects).
7. Final new-suite run: **107 passed**.
8. Final full-suite run on the implementation tree: **316 passed**
   (209 pre-existing + 107 new), 69.86s. `python3 -m py_compile
   src/*.py`: clean.
9. Git diff inspection: only the 8 files in section 2; no Stage 11D/11E
   or prohibited file; no secrets; no client addresses in any log or
   status path (privacy tests 56-59 prove the negative over real
   sockets).

The 107 new tests map to the prompt's 59 required cases one-to-one or
finer (loader 1-25, resolution 26-35, DNS behavior 36-43, reload and
concurrency 44-55, privacy 56-59), plus format-detection and helper-edge
cases. Flakiness: the historically intermittent socket-bind setup error
in `tests/test_reload.py::test_failed_reload_does_not_stop_service`
(Stage 11B record) did NOT occur in any Stage 11C run; no new flake was
observed; nothing was classified as pre-existing without that record.

## 10. Fresh-clone verification

Every committed file was verified BYTE-IDENTICAL to the tested local
file immediately after its commit (raw fetch from the branch vs the
local file, `cmp`; SHA-256 recorded for the first:
`c354dc4d797e39b0bc4dcbe574543503dba60e3729da02dafcf4e550d8fba123` for
generation_io.py). Commits, in order:

1. `fc748d35` generation_io.py (new)
2. `ae6e1178` engine_set.py (new)
3. `1d1f5579` address_canonicalization.py (modified)
4. `7872bc5a` dns_service.py (modified)
5. `db87748c` test_multi_policy.py (new)
6. `7eda5476` filtering-engine/README.md (modified)
7. `27c25636` README.md (modified) - code-final SHA

A fresh single-branch clone of the branch at
`27c25636596957bfb4009c33256084236d40fd5e` was verified
`diff -r`-identical to the tested implementation tree (only `.git`,
`.pytest_cache`, `__pycache__`, and this not-yet-committed report were
excluded), and all suites were re-run on that clone:

- Engine suite (`cd filtering-engine && python3 -m pytest tests/ -q`):
  **316 passed, 3 warnings** (70.10s).
- `python3 -m py_compile src/*.py`: clean.
- Dashboard suites (untouched): **276 passed** = 150 + 80 + 21 + 24 + 1
  across five invocations (split only to fit execution time limits),
  matching the Stage 11B record (98 + 178 = 276) exactly.

The historically intermittent socket-bind setup error in
`tests/test_reload.py::test_failed_reload_does_not_stop_service` did NOT
occur in the clone run. `git ls-remote` after every commit confirmed
main stayed `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a`. The commit
after `27c25636` adds ONLY this report file; every code, test, and
documentation file at the final branch HEAD is byte-identical to the
verified clone.

Note on commit mechanics: the first commit attempt used GitHub's file
upload flow; its draft state renamed the upload (`2-generation_io.py`)
and the first submit hit a browser error page without landing (verified
via `git ls-remote`: branch unchanged, no partial state). The flow was
switched to the standard web editor with the exact local bytes filled
programmatically; every commit after that landed on the first attempt
and was byte-verified. No commit landed twice and no stray file was
created.

## 11. Security review notes

- Fail-closed everywhere: any defect in any document, hash, reference,
  path, or file set rejects the whole generation; the last valid set
  keeps serving; there is no partial activation and no unverified
  fallback when a manifest exists.
- The descriptor-based safe open (no symlinks, regular files only,
  read-from-same-fd) now covers every generation file, and unsafe or
  non-canonical manifest paths are rejected before opening anything.
- Boolean IDs are rejected as IDs everywhere; duplicate JSON keys are
  rejected at parse time; duplicate binding keys and non-canonical
  spellings are rejected.
- The reserved credential structure cannot fire: no authenticated
  channel exists, no credential is accepted as input, and non-empty
  published credentials reject the generation.
- Client addresses are used in memory for routing only and never reach
  logs, status files, or any persistent output.
- `EngineSetError` subclassing `PolicyConfigError` widens no catch
  path: both are configuration errors handled by the same existing
  fail-closed reload/startup code.

## 12. Untouched systems confirmation

No deployment, merge, main update, dashboard change, Stage 11D/11E work,
external server access, new dependency, or secret introduction occurred.
Main remained `5f75d213a5ef9a19e811cfe4f56c44acc9f06f2a` throughout.
