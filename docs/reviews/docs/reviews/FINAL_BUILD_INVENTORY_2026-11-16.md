# Build source and commit inventory

Snapshot of the published source before this inventory document is added.
Base: `9eaa2213ea357bcd7a7795a23063b8d9e283d771`
Source head: `4986903f782bc146bc7dd8e30ef7f0e26865878d`

143 changed source files; 371 commits.
This report itself adds one documentation file and one subsequent commit.
The final delivered head is recorded in the handoff, avoiding a self-referential
commit hash. No source changes are omitted from this inventory.

## Changed files (name-status)

```text
A	category-pipeline/PROVENANCE.md
A	category-pipeline/build.py
A	category-pipeline/sources/seed-manual.jsonl
A	category-pipeline/taxonomy.json
A	category-pipeline/tests/test_pipeline.py
A	control-plane/alembic.ini
A	control-plane/alembic/env.py
A	control-plane/alembic/versions/0001_initial_schema.py
A	control-plane/alembic/versions/0002_policies_devices.py
A	control-plane/alembic/versions/0003_publication_revision.py
A	control-plane/alembic/versions/0004_mdm_enrollments_commands.py
A	control-plane/alembic/versions/0005_supervision_split.py
A	control-plane/alembic/versions/0006_pending_mfa_enrollments.py
A	control-plane/alembic/versions/0007_enrollment_device_udid.py
A	control-plane/alembic/versions/0008_remaining_tables.py
A	control-plane/alembic/versions/0009_users_admin_session_index.py
A	control-plane/app/__init__.py
A	control-plane/app/app_ops.py
A	control-plane/app/asgi.py
A	control-plane/app/config.py
A	control-plane/app/credential_ops.py
A	control-plane/app/db.py
A	control-plane/app/ddm_ops.py
A	control-plane/app/filter_log_ops.py
A	control-plane/app/main.py
A	control-plane/app/mdm_ops.py
A	control-plane/app/models.py
A	control-plane/app/policy_ops.py
A	control-plane/app/publication_ops.py
A	control-plane/app/publisher.py
A	control-plane/app/schedule_ops.py
A	control-plane/app/security.py
A	control-plane/requirements.txt
A	control-plane/tests/__init__.py
A	control-plane/tests/conftest.py
A	control-plane/tests/test_api.py
A	control-plane/tests/test_app_policy.py
A	control-plane/tests/test_category_admin.py
A	control-plane/tests/test_credentials.py
A	control-plane/tests/test_ddm.py
A	control-plane/tests/test_dns_reporting_e2e.py
A	control-plane/tests/test_filter_logs.py
A	control-plane/tests/test_foundation.py
A	control-plane/tests/test_guardians.py
A	control-plane/tests/test_mdm.py
A	control-plane/tests/test_migrations.py
A	control-plane/tests/test_policies.py
A	control-plane/tests/test_publications.py
A	control-plane/tests/test_self_service.py
A	control-plane/web/app.js
A	control-plane/web/index.html
A	deploy/COSTS.md
A	deploy/monitoring.md
A	deploy/ohttp/Dockerfile
A	deploy/ohttp/PINNED
A	deploy/ohttp/README.md
A	deploy/ohttp/interop/interop-client.mjs
A	deploy/ohttp/interop/run-local-interop.sh
A	deploy/pg_backup.sh
A	deploy/pg_restore.sh
A	deploy/pir/Dockerfile
A	deploy/pir/README.md
A	deploy/pir/prepare-dataset.sh
A	deploy/prometheus.yml.example
A	dns-edge/device_policy.py
A	dns-edge/doh_identity.py
A	dns-edge/reporter.py
A	dns-edge/runner.py
A	dns-edge/schedules.py
A	dns-edge/tests/test_device_policy.py
A	dns-edge/tests/test_doh_identity.py
A	dns-edge/tests/test_reporter.py
A	dns-edge/tests/test_runner.py
A	dns-edge/tests/test_schedules.py
A	docs/FULL_BUILD_ARCHITECTURE.md
A	docs/REQUIREMENTS_COVERAGE.md
A	docs/design/DOH_IOS_TRANSPORT.md
A	docs/evaluations/MDM_ADE_EVALUATION.md
A	docs/reviews/FULL_BUILD_PRESTART_QUESTIONS.md
A	docs/reviews/MILESTONE_1_REVIEW.md
A	docs/reviews/MILESTONE_2_ERRATUM.md
A	docs/reviews/MILESTONE_2_REVIEW.md
A	docs/reviews/MILESTONE_3_REVIEW.md
A	docs/reviews/MILESTONE_4_REVIEW.md
A	docs/reviews/MILESTONE_5_REVIEW.md
A	docs/reviews/MILESTONE_6_REVIEW.md
A	docs/reviews/OHTTP_GATEWAY_ASSESSMENT.md
A	docs/reviews/SECURITY_FIXES_2026-11-16.md
A	docs/reviews/SPEC_RECONCILIATION.md
A	docs/setup/APPLE_CREDENTIALS.md
M	filtering-engine/src/engine_set.py
M	filtering-engine/src/generation_io.py
A	filtering-engine/tests/test_generation_symlink.py
A	ios/Configuration/App-Info.plist
A	ios/Configuration/App.entitlements
A	ios/Configuration/FilterExtension-Info.plist
A	ios/Configuration/FilterExtension.entitlements
A	ios/KosherGuard.xcodeproj/project.pbxproj
A	ios/Package.swift
A	ios/README.md
A	ios/Sources/FilterExtension/FilterControlProvider.swift
A	ios/Sources/FilterExtension/FilterDataProvider.swift
A	ios/Sources/KosherGuard/KosherGuardApp.swift
A	ios/Sources/URLFilter/AppConfiguration.swift
A	ios/Sources/URLFilter/AuthSessionClient.swift
A	ios/Sources/URLFilter/CredentialIssuanceClient.swift
A	ios/Sources/URLFilter/DNSOverHTTPSClient.swift
A	ios/Sources/URLFilter/KeychainCredentialStore.swift
A	ios/Sources/URLFilter/MDMEnrollmentClient.swift
A	ios/Sources/URLFilter/PrefilterUpdater.swift
A	ios/Sources/URLFilter/URLFilterConfiguration.swift
A	mdm/__init__.py
A	mdm/adapter.py
A	mdm/ade.py
A	mdm/apns.py
A	mdm/app_management.py
A	mdm/nanodep.py
A	mdm/profiles.py
A	mdm/reconciler.py
A	mdm/tests/__init__.py
A	mdm/tests/test_ade_profiles.py
A	mdm/tests/test_apns.py
A	mdm/tests/test_app_management.py
A	mdm/tests/test_nanodep.py
A	portal/app.js
A	portal/index.html
A	proxy-edge/forwarder.py
A	proxy-edge/pac.py
A	proxy-edge/server.py
A	proxy-edge/tests/test_forwarder.py
A	proxy-edge/tests/test_pac.py
A	proxy-edge/tests/test_server.py
A	url-filter-server/app/__init__.py
A	url-filter-server/app/bloom.py
A	url-filter-server/app/dataset.py
A	url-filter-server/app/device_auth.py
A	url-filter-server/app/pir_export.py
A	url-filter-server/app/revocations.py
A	url-filter-server/app/server.py
A	url-filter-server/tests/__init__.py
A	url-filter-server/tests/test_revocations.py
A	url-filter-server/tests/test_url_filter.py
A	website/index.html
```

## Commits (full SHA, newest first)

```text
4986903f782bc146bc7dd8e30ef7f0e26865878d test(ui): dns_reporting status transitions
97b4da5400f9369ac1052c846b6f5af8d0c9694f fix(ui): evidence-based dns_reporting edge status
3a4a52ac4a3f96eaaa8d46b738721ee18aaafeff fix(ui): filtering panel DNS label reflects connected pipeline
e54dcac94a02f37e8117652ca0803e1f6b207d63 test(db): migration comparison docstring - PG evidence recorded
c66e6fe76a685c4fdb5fba0e5495cc7323a97641 fix(db): 0008 reuses existing role enum type (create_type=False) - PG upgrade path
8eabbf16f0861d9fe87cf460359d9801dfa1353a docs(reviews): DNS e2e evidence, layout parity, migration 0009
ae9081a334f1dedae4c2e883264731f3aa92aa66 docs(reviews): staleness vs token-expiry bounds stated separately
f044d1c5ae87957ca5dd783626c6a171c628e7e7 test(dns): tenant root parity with publisher layout
b5c38eb185161d6ebda36bd54a650ba99d185236 fix(dns): tenant_root_for_token matches publisher layout tenant-<id>
e4bc18b3f5838c60f6a53440abe5f72765bfcb40 fix(ui): MDM command select matches adapter SUPPORTED_COMMANDS
7c1c9b002df99e09ee18521568809e3035e7d3b4 test(dns): end-to-end query -> runner -> reporter -> ingestion row
50fe4b7386dccc3026bb832071f4669f1f8ec724 test(db): alembic-vs-create_all schema/constraint/index comparison
dcdb285187797ac91092e2f854df2d7a710ee605 fix(db): migration 0009 - is_platform_admin + unique session index (parity)
101cd36679fab34619ad9655147a19091ed8d2a2 docs(reviews): DNS reporting connected; full migration coverage
866242794d8eb8a11aef5efa9d736d9c7a1b8236 docs(reviews): revocation entrypoints + exact staleness/renewal semantics
d73152475ab1f8f70d4609958eb2f66e810ebf07 test(security): entrypoint build_runtime tests
707f54c535907b15c1bee13f35c6243fdb913226 test(security): entrypoint revocation refusal after loop tick
f6947538d3069228f1e36555daa8582ebff0e2d6 feat(security): build_proxy entrypoint - feed + refresh loop wiring
321c74cc5de05fa88b6e17210122d04910781cea feat(security): build_runtime entrypoint - feed + refresh loop wiring
92369efad540daea5ae671797b8cd7ea00cc7e24 test(dns): reporter batching/drop + runner wiring tests
f641c0c4ea2d2f4c2ea7284d2a1959453d9b02a7 feat(dns): runner wires decision reporter + revocation feed lifecycle
20e4bd624d57e79182cf9fe9d53792cf09ce2532 feat(dns): DNSDecisionReporter - decision reporting to control plane
6c49f1eeccee71817b1ef7db4c95f192201c5780 test(security): doh ingestion roundtrip + cross-scope refusal
6f8687890f26cb1ae1e47944ea686cef18705b15 feat(security): dns ingestion source bound to doh credential scope
a4610a2a57fb293e5972b886f22da3d425c73857 test(db): clean alembic-only install asserts all 20 tables
9ae3fdc52730577bd4f71736ba8e5f52509bf3ca feat(db): migration 0008 - complete table coverage (was create_all only)
4f311ac1c849d93b5a9c9573f002a579b398a9f2 docs(reviews): runtime revocation done, migration 0007 tested
581b32517fc81e1e01371ca28a2e5f6f7e97e3fa docs(reviews): runtime revocation wiring + evidence-layer separation
b6c5b581e1e962d80180ef6e257e233146dc1dbe test(security): revoked doh token refused, unrevoked passes
60251e3f0ea02004f7dfb22d11079e3c69297297 feat(security): doh identity refuses revoked tokens
8faf931e4d484403f6abd2d162c5932d9649eafb test(security): proxy end-to-end revocation refusal after loop tick
9f4101a9dcb4ca3abfe0cc6837d620c038adb6dc test(security): runtime refresh loop, tenant isolation, fail-open startup
42ecee061b47a8e90d00fdafdb7cb1973b004cd2 feat(security): create_app consumes revocation feed shared set
b551e2624fee166bc796dbca48c1b9d6ec57de92 feat(security): RevocationFeed background refresh loop + shared set
4bcbab669dc6be4ad4b17361d4f172bb7d083791 test(security): alembic upgrade from prior schema preserves rows
e3cadaa67979a7ed6e5f5fb20136d5f48d8648c6 feat(security): migration 0007 mdm_enrollments.device_udid
a19ff46f1f489cb1c111d0969c1b373ac9491536 docs(reviews): revocation distribution done; held labels updated
8903ea53f66d807d66101ca562e3e2bb63603142 docs(reviews): UDID binding + revocation distribution implemented
edadd7000ea34d640ee5a765fd71497d7affbea9 test(security): feed client + end-to-end revocation consumption tests
3e35ca94ac15030adab66f4d9ef5bab8efd9e71d feat(security): RevocationFeed edge distribution client
e2189178acb4782f98bb5e558cfca3422f5aa755 feat(security): create_app accepts revoked_jtis set for edge refusal
caf6ef60b245003db00bed28fb2e01f6a8b44146 test(security): revocation feed scoped-bearer + tenant isolation tests
fb27626f3dfbeb8b4b2db2f1e10ea0779e2b8fa1 test(security): UDID binding, ambiguity refusal, sync binding regression tests
010315cc40a9b6574534427e03d2e180181d263c fix(security): enrollment UDID route + scoped-token revocation feed
cb68228a765cbb5170fe6a67c77bf7dfbd3495ca fix(security): create_enrollment records device_udid
efc3ea1028c20e86d5e3e36a850ea5d31e4929a2 fix(security): Enrollment.device_udid column for recorded-at-creation binding
686ee8b22443e4c2a8a8b4eeeab2ed5b144e5b6e fix(security): bind pending enrollment by UDID recorded at creation (resolve_or_bind)
7bcf5b28cd3e6e9b9fcd65cedee35cba7883804b docs(reviews): id-binding + mid-publish vs replay failure evidence
000797a0a7de5f85a8a7cda69b6fe16b4c04f32a test(security): mid-publish failure cleans only own generation, byte-verified (fix 1)
081692dfb70a9cbbf137bda46c2231887024d26c test(security): nanomdm-id binding + conflict refusal regression tests (fix 3)
f8935051961a9e039cf1b740ce57de3c87dc38bc fix(security): pass nanomdm_id binding through checkin route (fix 3)
e6d060bad7e9c311dc311b6fef8ab80343ecd588 fix(security): checkin sync binds NanoMDM enrollment ID to pending record (fix 3)
c23b76bc3630d943304f31e85942af249c25bcb6 docs(reviews): peer-evidenced activation + byte-level isolation evidence
b0a428e49bf24f4f350676084bc1b255214fdb0b test(security): ID-alone 401, peer-evidenced activation, supervision never claimed (fix 3)
5a09c3f9597e3f8576e4ffada098720f2248eb61 fix(security): activate pending enrollment on first authenticated DDM contact (fix 3)
c3271a51a548405b0eb4ab1d736f867f4eebe14b fix(security): peer-evidenced enrollment activation (ensure_active) (fix 3)
452fdadc5980a120677e7dbdbffa2c13342ddabc test(security): byte-level failed-publish isolation across tenants (fix 1)
bd454a5850b15e7a32099d37c9fb439d069a840f docs(reviews): reconcile spec - security fixes resolved, held labels cleared (c8e09bf)
c8e09bf28a6ef4758951a2d012f6cf33b0750f61 docs(reviews): final security report - three authorized fixes
f709cd2f97ae4021d4806a3aa2cd6aa7ca6fc6f8 test(security): supervision-claim rejection + idempotent checkin tests (fix 3)
d7353b50ba17947bf96c6bde77ac466b88a3f39e fix(security): checkin route records enrollment only (fix 3)
189f7155517f5016427ea21a5a7a1c1b4690bf92 fix(security): enrollment-only checkin sync; supervision never caller-claimed (fix 3)
8e2db426db9a23cab370656273b75770acbdc838 docs(reviews): milestone 2 erratum - publication isolation fix context
880118699e294fbc895af4187bdc8a28c3242b50 test(security): DDM enrollment authorization regression tests (fix 3)
6b0906091ad473fa15d9da9889829939caffe24c test(security): credential revocation registry regression tests (fix 3)
750f06a851da9bf74339f51719890490bed624fa test(security): default-mutation tighten-only + disable-guard regression tests (fix 2)
0759c42c001ec1a5c905135993391250afb949cd test(security): cross-tenant publication isolation regression tests (fix 1)
2909c36d04d651fb8cec0805d64c5c9c6985b1f5 fix(security): document the actual trusted chain; enrollment-state authorization + checkin sync (fix 3)
f3518f585baa59d555ea544a1f95dc5c9a6161f9 fix(security): default-disable guard, doh scope, revocation routes, DDM enrollment-state authorization (fixes 2+3)
05454e01ba2d0e7dd602728a54fb2b12faf7da06 fix(security): IssuedCredential issuance/revocation registry model (fix 3)
f141ebbde7d45c069ad55676cc1d2ae82b122ef0 fix(security): categories_file setting for publication exports
47c9fb683557c9da17a51a7b43565c81280aafc7 fix(security): re-prove every assignment when the default policy mutates (fix 2)
f88fd8d4c5c37fe2b6c9f3b650ebbc6e3cdec2ca fix(security): per-tenant publication roots + engine-doc validation + categories wiring (fix 1)
af763a76d56d98198264b029da6ea7703709523e fix(security): publisher cleanup only removes self-created generations (fix 1)
eaba4b69a17d17696470032bb820168bbdb96921 docs(reviews): managed-app configuration emission built (34bdb6c)
34bdb6cad9b4668fac10c103ac462c4002d3d83b test(control-plane): install with managed configuration (deviceID auto-fill, no invented URL)
56d72b58bcb1512d4e49792edb778e54a56cd0ba feat(control-plane): AppCommandBody.configuration passthrough
afe4906c04b8945b4b369e9c9b85eb87a7002c15 feat(control-plane): install passes managed configuration; deviceID filled from device record
eaebb19298b52fc309da47ea80684f96599d34bb test(mdm): managed-app configuration emission/rejection tests
4a36255ba9c9bd2a3bde5f08bd2a823ffeda981a feat(mdm): InstallApplication Configuration dict - verified Apple contract (application.install.yaml @ 9e7fdbe)
e85de5582c700efdad152042ffa14be9da5cb1f6 docs(reviews): final verification counts at b19132a, dashboard deliverable, Part 6 DDM line, Q3 bearer rule
b19132abec0e12c34b63b80c966436d0f3cc497c docs(reviews): DDM trust-boundary hardening + status receipt-vs-application correction
c34a2e674065179ff590824a75e3cc2ebf5c8d8e test(control-plane): DDM fail-closed repro guard, HMAC auth, declaration-state extraction
42e57e01158fbba7fcf18aa7e6172bae4a9210bb fix(control-plane): DDMStatusReport receipt-only semantics + declaration_states column
87211aac583411a758631e1697d8b0466895a740 fix(control-plane): DDM fail-closed HMAC (id is not auth) + status receipt-vs-application states
6b68c71f7500f8384f306ba8fac08cf6903006d5 docs(reviews): Part 10 reconciliation - Applications/filtering/status/DDM built; DNS dual-dependency split
d2b8d1a1445ee204465128e7d5b34dec5279d879 test(control-plane): DDM sync flow, token change, auth, HMAC, status storage
9c8de16d818937952a38608b653d5944d71e375c feat(control-plane): DDM DM-server ops - verified NanoMDM -dm / KMFDDM wire protocol
61d913033ba2c87e8741840a7114cd7454df4de5 feat(mdm): DeclarativeManagement command + document NanoMDM -dm DDM delivery route
86f5d6ea690a533953101cdf971d682515a58d3d feat(control-plane): /api/ddm/ serving routes (tokens, declaration-items, declaration, status)
c0591d9d80e2f857a7b849953eaeba778ab11c53 feat(control-plane): KG_DDM_HMAC_KEY setting (NanoMDM -dm-send-hmac-key peer)
47e0f78502b8cb42718a926aaf0c8caeb3da99f6 feat(control-plane): DDMStatusReport model (verbatim device status reports)
dbf3a38ad98038de5550eb38cc8270d5c90ff0ec feat(dashboard): render edge status - configured/reported/health-unknown
c2f810e2f86d28ea52447a490b9e5da41bf17fbe feat(dashboard): edge-status block in Filtering activity panel
dbfc3d249b49dbc1a81abf79f66338065369e60f test(control-plane): edge-status tests (evidenced state only, auth required)
0cac64b10fd8be1d2d3c2fcb05470d41458f4d84 feat(control-plane): GET /api/filter-status route
869f82414a413f28bb54bc9d7fe87a88a7559611 feat(control-plane): evidenced proxy/DNS edge status (configured/reported, health explicitly unknown)
ebd1e2eb57f01ad86b6e013d91a89e6261248fbd feat: filtering-decision logs (Part 10) + DDM app-settings builder
9a364c246da4b29d225a9c0cb65e0eb7ed4cef0e feat: filtering-decision logs (Part 10) + DDM app-settings builder
6f42b7b7d04cc83957db61101313ba428a5326ae feat: filtering-decision logs (Part 10) + DDM app-settings builder
0670f01be567d7421b63bc0a8079b6d971a55674 feat: filtering-decision logs (Part 10) + DDM app-settings builder
6bc72ec23ab8d6492d31409ff284dab3358a054f feat: filtering-decision logs (Part 10) + DDM app-settings builder
4752df4f426f3d200a3442a236845d339d85c610 feat: filtering-decision logs (Part 10) + DDM app-settings builder
1a434e8287edd0ff44e19a96fa23bc6d23b06a4e feat: filtering-decision logs (Part 10) + DDM app-settings builder
780cf103c6d3216d49a0c812954b98fe6df831bb feat: filtering-decision logs (Part 10) + DDM app-settings builder
c14dc57eb82588be4fa945ccc15404d3508258f2 feat: filtering-decision logs (Part 10) + DDM app-settings builder
7fa1bf09a5dc434b19f6100606046e553718b645 feat: filtering-decision logs (Part 10) + DDM app-settings builder
f9715add93a9deb2793ca6f42ecb7ac6f6991081 feat(control-plane/web): data-loss confirmation before managed-app removal
3fd6111fb61f3d123e48254315bb03de9599afbb feat(control-plane/web): data-loss confirmation before managed-app removal
668a8c155db4b4ad127518eb5cb296c9a2acb365 docs(mdm): verified Apple boundaries for app removal and restrictions keys
92533b96ad5e7f55217161d546a7008eaea1037d Delete test_app_policy.py
a6a825335c91531add91f6dd30ebc183df47931a Delete test_app_management.py
f7f645917dfa61e5471d6f1bdf7c060477f6bff2 Delete app_management.py
5e07cfb6a7395add69b855d1cad1e595b98be9e0 Delete app_ops.py
11cff40b8d4eaa4f6813d9953c9c80da6cd0b870 fix: place test_app_policy.py at control-plane/tests/test_app_policy.py (was committed at root)
8b340017db709b0ece5fda6785b81c5a6724ed43 fix: place app_ops.py at control-plane/app/app_ops.py (was committed at root)
0e433e7cba4b178d4ca6469f5f54e094a11818c1 fix: place test_app_management.py at mdm/tests/test_app_management.py (was committed at root)
b7263324adccc7c79078d429aff7988bfce3e696 fix(mdm): place app_management.py under mdm/ (was committed at root)
fb5621b76bef2b2d168f4a2d6deb1932a9dd015c feat(mdm,control-plane): application management (Part 10 Applications section)
73b06750f11eb4765aca4af927ca2271b499f0de feat(mdm,control-plane): application management (Part 10 Applications section)
b5663f699b2efa0e36f197aa741169133cd1edba feat(mdm,control-plane): application management (Part 10 Applications section)
aeb3f139e7ece11c5a7b707229dcbf7df08998f3 feat(mdm,control-plane): application management (Part 10 Applications section)
9a704468574ccc591e17beaaf861c6f9c9bfb268 feat(mdm,control-plane): application management (Part 10 Applications section)
e8dbaeb2af5e9577fdd6b0703282735db7eb6c52 feat(mdm,control-plane): application management (Part 10 Applications section)
5285bfe4f502fc599fba1408e995486b528e7987 feat(mdm,control-plane): application management (Part 10 Applications section)
3149d4d726a786beb109b381f6d3664c0806f710 feat(mdm,control-plane): application management (Part 10 Applications section)
a018aa23062b971593fd41f2b815c25dd9c61b9a feat(mdm,control-plane): application management (Part 10 Applications section)
dc816fd4b146c204dcd6404ce7835bda2e281189 feat(control-plane): tenant audit log viewer (API + admin panel)
2a31e688aecebea0afc45e593edce07de0a367fb feat(control-plane): tenant audit log viewer (API + admin panel)
32806567441ce79c723c460e112c6d9a0c593a00 feat(control-plane): tenant audit log viewer (API + admin panel)
91f8a8ac45cb148806d3e6737d5db03cbedb00cc feat(control-plane): tenant audit log viewer (API + admin panel)
ba9a377d46f38c4ff5b7f531038385c10b20caeb docs(reviews): iOS reachable-action + managed-config + cookie-contract status
f4527175537f81943825b39b2fb6c80cee1ada2e docs(ios): reachable action, managed configuration, cookie-contract fix, keychain lifecycle
ffa34b3e12c68e81dd9198d11f4364c80e5f459e build(ios): add AppConfiguration to Xcode target membership
a0439db120419def3b73ba99cbb7151eddc80df9 feat(ios): reachable sign-in action, MDM configuration, keychain lifecycle (uncompiled/untested)
f970647516a6a9f88251efb199f324b8a0295e00 fix(ios): correct session cookie name to kg_session (contract re-check)
7e272eee9a706fa057b3252bd9bb69f56d23d719 fix(ios): correct session cookie name to kg_session (contract re-check)
53017c54950c895f4a76f6ceda13c599fdb1be1c feat(ios): MDM-managed App Configuration for server URL + device ID (uncompiled/untested)
d78cc13e35920807d3ad6b30cf60d34cd373843d docs(reviews): backup/restore roundtrip evidence correction; native auth/storage code status
6c347472c705aa6ca1c5b9b39f150e156cda584f docs(ios): session acquisition + storage now real code, still no execution evidence
9fa5c3d86e411536cb9b75b0ec836f47bcd13336 build(ios): add auth + keychain clients to Xcode target membership
4c7cb9c43b7e83a826d88e20f1fe30f3a35d6c7b feat(ios): real sign-in-to-mint controller flow (uncompiled/untested, fixture URL)
aa2567feaa081eec293b7eb1e871c2f005256413 feat(ios): Keychain credential storage, ThisDeviceOnly (uncompiled/untested)
123fe7760e933030dc2f52ba08c59fbe275616f9 feat(ios): native session acquisition via published login contract (uncompiled/untested)
d54c30db3ab980cdd76414769777ce38095a872b docs(reviews): M6 security hardening follow-up with before/after evidence
2296124e668417f5995e0e98b74d1e81eabaffba docs(reviews): guardian/account UI done with rendered evidence; iOS wiring status
2420d4065fba55122d0ef8be4588d21dc07a5ba4 docs(ios): request-path wiring status (call site + target membership, still no execution evidence)
10b5266960685bf2a3e15dda078fbdce2562d336 build(ios): add credential + DoH clients to Xcode target membership
fd75d6d78ea9eb1b821a6c8f5e84c9d2c4e0c62e feat(ios): CredentialController call site for scoped-credential client (uncompiled/untested)
35565c299753f2f76d697e855cb0e1c1a71d1f94 build(ios): KosherGuard target depends on URLFilter
c7814385fe150f70888162ab9220b9366d9cb53a fix(web): refresh guardian list after MFA enrollment; confirm sends no secret
4d534eb2e896c628e4a30c16eb08aee28a7ac988 test(control-plane): MFA binding/expiry/replay/substitution + session invalidation coverage
c23d05563065d94ab5f2e1314cd1e92b924d6a3d fix(control-plane): bind MFA enrollment server-side with expiry; invalidate other sessions on password change
4a76e7e22c222ceb9f43661d326f0bc431b7694a feat(control-plane): alembic 0006 pending_mfa_enrollments table
e6915b53973ab673b7b78ad09624761597ba4665 feat(control-plane): PendingMfaEnrollment model (server-bound, expiring, single-use)
598c0434464112e62cc803311e04b626c72bc0af feat(web): guardians + account UI wiring, invite link with correct path
48ac442a2c12608b5734f40c03f6a66707753e56 feat(web): signed-out invite acceptance, guardians panel, account self-service panels
6703212a563ce52e5b06c11333cbe95020b843e9 test(control-plane): self-service password change + MFA enrollment suite
6ea447166fda84730ba60fbd6aae149e830b76b2 feat(control-plane): account self-service routes (password change, MFA enroll start/confirm)
b37999bc9540c5868e8c1938e26dd5515281e2e5 docs(reviews): iOS request-path standalone-source status + session/storage gaps
0a858593c662fc50f77ae6741eefedaed2d9051c docs(ios): standalone-source status, call-site/Xcode membership, session+storage gaps
4b836122ab4c04cf395f90febcf04fc840fe0210 feat(ios): DoH client with scoped credential header (uncompiled/untested)
606bdf4f2938a720d80e4e5dd56ffa1dc9c44a97 feat(ios): scoped credential issuance client (uncompiled/untested)
6b246bdb9d0534a8abb17ea411915b6c33bedd10 docs(ios): request-path clients in README layout
6652e8d5cca4c30d33d371b0f76f1d8823156a80 docs(reviews): correct doh-mint held status + record TCP intermittent failure as unexplained
f7b2abf931ec7fd6754a2cfbf74ec32cd3cd5d09 docs(reviews): M7 published-tree fresh-clone verification counts at bda1279 + scoped issuance/revocation-held statuses
bda127967cc512fe7fc85452ed086693e7639d41 docs(reviews): M3 review states erratum/fix prepared locally pending user decision (no dangling file reference)
edcdf2f9afffa43b16312e3f0311ab18d78d8a0e revert(control-plane): remove prematurely published held hunks from config.py
d59d98c6ea7c7c1e1b8035c3e6879f64be4251c9 revert(control-plane): remove prematurely published held hunks from main.py (restores pre-hold coherence)
b6d3254dd7d9860fce872b4c5056b380b6521419 docs(reviews): 8B + OHTTP + credentials statuses, current test counts
1e9daccdc1fce1dcb2a29c5af7a86ba3a1afed40 fix(control-plane): full-width monospace credentials textarea
00d1c276893e4ea670c8180983036a47cc1fe01a test(control-plane): proxy-scope minting coverage
bf8ba1048d3a02418902078d283d16ce22f3a01d feat(control-plane): proxy-scope issuance bound to effective policy
4ff321b911e6d706220b3e37fe294b48377e5669 docs(pir): precise interop scope distinctions
ad8af8951392fc1f0e2b3bf8791209b271e4c52f docs(ohttp): precise interop scope distinctions
8599ef473ebbe415d1d93517f16e71b1be7e59cf feat(control-plane): credentials screen wiring
6a424ca051ea1cd9adb7a1ebdd7846631a82b80e feat(control-plane): credentials screen with fixture-only banner
e304dfb3bdb5b8fb3cc03678cd4cdd0e441b76bb test(control-plane): credential lifecycle, guards, isolation
4e96c7dac8bcbce95d4bcea8f0b5605f80734182 feat(control-plane): credential upload/rotate/revoke routes
76be8d7e02ba053ac902856104c3ab82172b108e feat(control-plane): credentials root + environment stamp settings
176725ac867c770bf5935022d1966c5a172dd68c feat(control-plane): CredentialArtifact metadata model
6ab4158d38c97e09b44879b0305ec39a1bef4096 feat(control-plane): credential artifact storage (fixture-only build)
46a836ef554c207bf2e991424ba94f1f007d4d1d docs(pir): gateway wiring built + interop-tested; live traffic still Apple-gated
4fd593c7bc0e9515164b2ff5222b51401f9b58ab deploy(ohttp): executable local interop test (fixture keys)
15c5df0adfd679b178eb3ef9c47c3a0539ae10d1 deploy(ohttp): RFC 9458 round-trip interop client
e37ebd2561755fad86f241a9a4cd004f4a84d9b0 deploy(ohttp): gateway deployment layer status + production path
aae0cdbb31dd3e5e028d783339de6521490b8b14 deploy(ohttp): pinned gateway image build (unbuilt)
36390b6715960dd491418511db5aad70c3b1b401 deploy(ohttp): pinned upstream gateway reference
0aaa3830e8e4513668472db5e34be1487a0d156f docs(pir): point gateway status at the options assessment
c2c6383adc40bca7b82707843c700548032f40e8 docs(pir): OHTTP gateway options assessment
996ad65abaa7fa79b4a70eb9ef8316624305cade test(proxy-edge): proxy auth negative + stripping coverage
dc3eba1368b359f8c676813a9921c53417cc6340 feat(proxy-edge): authenticated per-device proxy access (8B)
310847c70489408330446d1758b89b7b6417ff53 test(control-plane): schedule tighten-only negative coverage
e0f59dec2291b374bba61425c10d062ac5ae2127 fix(control-plane): schedule-aware tighten-only proof (security)
083731111218ecead6fef310caba4435bb214e7f feat(control-plane): filtering schedules API (spec 8F)
173dae2d48046a45fcce29a9451315815d951782 feat(dashboard): filtering schedules panel
983424be583f32df13bbfef5c587dd4253a37d14 feat(dashboard): filtering schedules panel
c17c55c57b5392e4662c72571ad049cbfdfa6ac3 test(control-plane): schedules API coverage
fa3b52521b55e90d2ae9d3a6d79bd7193e72d940 feat(control-plane): carry _schedules through doc normalization
ad0b2a37b9b71bfc316399d63da1c07cbeb2637e feat(control-plane): schedule validation shim (spec 8F)
6f6ac407ca2052b2c78356c19da631dea5d72914 test(dns-edge): filtering schedules coverage
7df2941538099a4c9f03c56e8d3f70f90f61ae03 feat(dns-edge): filtering schedules validator + engine wrapper (spec 8F)
12377e1b26d6fd4cebd5d8088cd5ac2ba5cfa83b feat(dns-edge): schedule-aware engine wrapping at load and reload
287bf63e620451ccdc52093473881dee0378d3b5 test(control-plane): overview + admin tenants coverage
da9f3f598ab02cda355ed906eb34d81006e2d3d9 Delete scratch_probe.txt
477424062abf5fa67744dd90cebb5fb69b2aad89 feat(dashboard): overview + customers panels
515c802117056839167bae00982aca94ee73575b feat(dashboard): overview + customers panels
b52f4df969b274ce665430ed5c097a1ea47c5c59 feat(control-plane): overview + platform-admin tenant list
4896151757905bbc971eda7f94a1ad49df25a3ad feat(control-plane): overview + platform-admin tenant list
1fe7b732583b961b45ae040fece8e35fc7318225 Update scratch_probe.txt
de8ed5c1068cd202d26212b809195cd21449b630 Create scratch_probe.txt
006d1e7cecef0ae40a4d24adee908b88ee93978e feat(ops): PostgreSQL restore with service-stopped gate (M6)
08c5f52daf1baa3ae9b149ba357970729caafdda feat(ops): PostgreSQL backup, verify-then-publish, atomic no-clobber (M6)
486f772270981fe6ca9fde474dee09f3e86e316c docs(reviews): full 20-part/22-deliverable reconciliation matrix
b3559d2a28bc3fb8d91b9568d27d4dac6bfcd982 fix(admin-ui): category panel api() shape - rendered UI verified (M6)
4e2e7c57483b3acb3f62b039f9ab3ec028fada93 test(dns-edge): unauthenticated refusal + explicit fallback (M6)
99bd50a1cbe8eaeb5d5a5d7a1c56a70c18610026 feat(dns-edge): unauthenticated requests fail closed on authenticated transport (M6)
50131890f3f26b95b33a139140d6ae96b822069b test(control-plane): credential issuance roundtrip, 503, cross-tenant (M6)
528dce7ee7098604e189e4217aec962198502f91 feat(control-plane): KG_DEVICE_TOKEN_KEY setting (M6)
d5cd91169fd47e1377278ec4bc2560412f4352d9 feat(control-plane): dataset-credential issuance route (M6)
4f7596560b95e0d8fcaf6084cb056f1b08247ccd feat(admin-ui): category panel wiring (M6)
143e237643467cd044a40fdcbe40346b8bb4a16f feat(admin-ui): category dataset management panel (M6)
c106a7b612a2782b70dc5922a57e2fee91ad3e04 docs(design): URL-token option is unapproved, not a default (M6)
362c4c243ba715ce3f4a511ada2ce2640c271184 test(dns-edge): device policy selection, fail-closed negatives (M6)
b1de71545054c81000a4d2853f145be89449ca68 feat(dns-edge): per-device policy selection at DNS evaluation (M6)
7743bf91845848f2a4827d322661913d1669676e test(control-plane): MFA-reset fresh-auth and role negatives (M6)
4e9a12e96c6eb70b53bd3350acf4cfbc4b42f6db feat(control-plane): MFA reset requires fresh owner authentication (M6)
8d86185e9fb0baef9545873b72568a67b5fe0f37 test(control-plane): guardian lifecycle authz, single-use, hashing, cross-tenant (M6)
3ad51ba6c54a20b990d4e5c072a2f5c9747233b4 test(control-plane): truncate invite_tokens (M6)
235f674b9f3179430abb7f9531d485c007a9020a feat(control-plane): guardian invite/accept/role/MFA-reset routes (M6)
42f09faa84f09a119d35cddd4f435a706262e167 feat(control-plane): InviteToken model (M6)
0c9f330092c8f258bbf772ec479268022ab9ec5b docs(design): DoH iOS transport constraint, source-grounded (M6)
2e4043ca49aaad7d30cecd23bca5553c13d02206 test(url-filter): revocation, policy binding, jti uniqueness (M6)
66ca56e7efce25669928d912bac142931c755455 feat(url-filter): token revocation (jti) and policy binding (M6)
236b14efdbf7f22ded90598b8f8fe4abbb562150 test(dns-edge): DoH identity authz, traversal, redaction (M6)
60aaef3b3bedaeabf0b2b971dc4c92fed190bcf7 feat(dns-edge): DoH per-device identity binding (M6)
1f5d3156ce7901824f4a825f31a856b0062e1b53 docs(reviews): Milestone 6 review - implementation checkpoint
b294d5e30ac13bcc96b583c5d5dcbafa92141182 docs(setup): Apple credentials guide, ADE token vs MDM push cert (M6)
1a6e29c87ce461f0161cec38eb5b84458cede7b9 docs(ops): expected ongoing costs, no spend authorized (M6)
c64d7498dfd145516e492be115311d420fe94043 docs(ops): Prometheus scrape example (M6)
a5aa07a1ac2b876875951c3fd2980518d74676dc docs(ops): monitoring and logging configuration (M6)
9f9d8c9464286f8fe406496339cf760184abf73d test(url-filter): device-auth roundtrip, tamper, expiry, scope, key, endpoint authz (M6)
d974592b6b8a313fe2618fa9d14e9495313f1257 feat(url-filter): require device credential on dataset routes when key configured (M6)
ad4027f9b2adc7b425a91175a239376360bb5a0f feat(url-filter): per-device scoped dataset credentials (M6)
6d8995fbb2cb8ee2cf76fef22cb38b1651655c20 feat(admin): platform category-dataset management routes (M6)
bbcc2d92ec3515c80481663f06f9c3ddec1c970d test(admin): category-admin authz, CRUD, export, provenance, audit (M6)
ebd852d146cf3726c2505853b9a4960e3ab9f2fc test(admin): truncate category_rules between tests (M6)
db0e6b3bbac98cce1add3e7ef86df27e14fc69f8 feat(admin): CategoryRule model + is_platform_admin flag (M6)
ef1f43d0d1db646bd368ef59bba36cc5f4284539 docs(reviews): Milestone 5 review - implementation checkpoint
38ec0fd533b16b3a4b08ddb231cb7c68c4f1b693 docs(pir): PIR/OHTTP layer status - implemented vs integrated vs unimplemented vs blocked (M5)
8a1eec15b70de04e1f835ec16043954071f6e88c feat(pir): dataset preparation pipeline via Apple PIR tooling (UNVERIFIED) (M5)
09c8ada5f86559a51fe78229b13ee056694ccb61 feat(pir): Apple pir-service-example deployment image (UNVERIFIED) (M5)
a8b77364e2fcfea5f1f46b152149ad98f927b121 feat(ios): Xcode project file, app + filter extension targets (UNVERIFIED) (M5)
0a7ca9fb26c9e916b85bd613b2778104649d07cb feat(ios): Xcode project structure - extension entitlements, url-filter-provider (UNVERIFIED) (M5)
8a4be981c1bbccdce3ab7b0d5be16d9e790b6976 feat(ios): Xcode project structure - extension Info.plist (UNVERIFIED) (M5)
4e95fe6c23f117825f4c7d2382d875965ad960e8 feat(ios): Xcode project structure - app entitlements (UNVERIFIED) (M5)
9323f4bb201e9702d336cda9f510fc49c9c71c2c feat(ios): Xcode project structure - app Info.plist (UNVERIFIED) (M5)
3042ef40338ca63a78c289ed7677b05e7281bb86 test(pir): PIR export golden/roundtrip/escaping/integration tests (M5)
2d61cbf0843277ca336d591920d3be9c8b80a631 fix(pir): remove duplicate pir_export.py from repo root (moved to url-filter-server/app)
6bb7d15d74bdb9d74f6dc2d9301b8fb9675810bc feat(pir): dataset export in Apple swift-homomorphic-encryption input format (M5)
f25158a90b1791e71e51c248941c88a64b35982e Update pir_export.py
c2a932490eb854ed8f089f1792ec99b3ba9e0a0f feat(pir): dataset export in Apple swift-homomorphic-encryption input format (M5)
d86ff4b15052820edc27b2e096e01a8f1a76654d feat(mdm): APNs push-certificate lifecycle management (spec Part 7)
5ad4cdf357afd36ffe23c2dd1068cb79d9dfad7c feat(mdm): APNs push-certificate lifecycle management (spec Part 7)
c6e814900734eacbc5d81d7af9157696de13a3e5 feat(ios): iOS Swift sources (UNCOMPILED/UNSIGNED/UNTESTED)
20f382470f5fb4cd860160d9ec608ba42ffde032 feat(ios): iOS Swift sources (UNCOMPILED/UNSIGNED/UNTESTED)
a57c3f5ae06d91b35c855a60a4e63bdc71e14ba9 feat(ios): iOS Swift sources (UNCOMPILED/UNSIGNED/UNTESTED)
8d16c78f208f5402228dc0053bc2c7067630bdc3 feat(ios): iOS Swift sources (UNCOMPILED/UNSIGNED/UNTESTED)
a49b0601a3ba60a7efc8699fd8d6c96f36cb4ca4 feat(ios): iOS Swift sources (UNCOMPILED/UNSIGNED/UNTESTED)
a2c421d0843133c70b2f7f5a29308fa1639ad4f2 feat(ios): iOS Swift sources (UNCOMPILED/UNSIGNED/UNTESTED)
b10d8853f870c3c96666c0ca00526ab86489938b feat(ios): iOS Swift sources (UNCOMPILED/UNSIGNED/UNTESTED)
4c5042a095951083c4ff7a8a1fcc5322f6085a45 feat(ios): iOS Swift sources (UNCOMPILED/UNSIGNED/UNTESTED)
565439e25295e67e70b87ce4e34d93a9c1924ee5 feat(url-filter): URL-filter dataset server (M5 server side)
bafd97f498b43cf37fe172eedf81b18ae8732271 feat(url-filter): URL-filter dataset server (M5 server side)
4a0fc357420dcfa2dc2eb00250bf7a9dbac64c68 feat(url-filter): URL-filter dataset server (M5 server side)
9679f1767b9fcf6f8e6deb7a3049b7a2f30ed086 feat(url-filter): URL-filter dataset server (M5 server side)
be54cd9702c56fff5190699a460b7a75ec1afe5b feat(url-filter): URL-filter dataset server (M5 server side)
66f29b5222e06f8aa273f47f3c8b63745e3c0ce9 feat(url-filter): URL-filter dataset server (M5 server side)
8d64bc7ce52eb20e5df5ae1cb794c358ac51ca21 fix(mdm): split supervision into requested vs device-verified
e522647166ff22042a3425374060036e47f5fa73 fix(mdm): split supervision into requested vs device-verified
f14c1c08597faab4fc65290cf5f0cf9efdd512ee fix(mdm): split supervision into requested vs device-verified
ae95c9e591e7e8046dabb67f23bedf2a47f3e740 fix(mdm): split supervision into requested vs device-verified
849e129f72db433b1d0d2145400fe2c69dd3fb13 fix(mdm): split supervision into requested vs device-verified
133faaaab07075695d068d3de52ffdafdf41a95d fix(mdm): split supervision into requested vs device-verified
39219fcdd98e4841a35d9780ea62ce559047741f fix(mdm): split supervision into requested vs device-verified
f28ef7292f26c48044060eba4983fe9c8a035518 docs: Milestone 4 review report
2d5e7303d273d4b7f8a7eeffb59914c5fb2018f2 feat(mdm): admin dashboard MDM slice
9168fbdc490fa2686b54d038f169fd657333a94e feat(mdm): admin dashboard MDM slice
4cc14b381b63623d573aee335f7bf5f55a91c879 feat(mdm): real NanoDEP depserver client + contract tests
213f61fcd38f23f1068f07a4f15a0469544fbbc0 feat(mdm): real NanoDEP depserver client + contract tests
dd09c1eb19ca4d3477bca08c53f9816d6a4205ad feat(mdm): real NanoDEP depserver client + contract tests
943da833640974e4b22362468d1e699b67c92ddf feat(mdm): ADE/NanoDEP sync-plan shell + mdm package tests
b4e2d79ef78d9e120b35f9b9aedd537053752a24 feat(mdm): ADE/NanoDEP sync-plan shell + mdm package tests
ab8c23a998ab66e3bc6909a5ce9a387d4d6c2fcd feat(mdm): ADE/NanoDEP sync-plan shell + mdm package tests
8b03766ebd517c403149bf38e17659bdd8697d09 feat(mdm): enrollment-profile builder + NanoMDM status reconciler
14c0235fc7dc6bda7a8bc831c8b682a03cb91339 feat(mdm): enrollment-profile builder + NanoMDM status reconciler
f24f8703239f7d15b9b092e81bf68371c4c45749 feat(mdm): enrollment-profile builder + NanoMDM status reconciler
c3c6ea07452b1e83892bec17cf11c3bc2d19e6ff fix: remove unpublished held tenant_root call from publications/current
698d9c304cdf68a1508107117392cbcc1d7b5c7f fix: remove unpublished held category-wiring lines (internal consistency)
bb7d68cee56be5790e6b12035dc94cca67fb58d9 fix: remove unpublished held category-wiring lines (internal consistency)
cdfef93ef3671ce38a30e0d7a88822af1c1e6be0 feat(mdm): M4 foundation - MDM/ADE evaluation + enrollment/command lifecycle
8184a595b6879469fa910988ffd6a42cc0c60b19 feat(mdm): M4 foundation - MDM/ADE evaluation + enrollment/command lifecycle
9916e4d9f68c315a5b9f458daaaef3f29a47d931 feat(mdm): M4 foundation - MDM/ADE evaluation + enrollment/command lifecycle
ee3226901b36ed83cd46b035f45ba87dc36d9d6f feat(mdm): M4 foundation - MDM/ADE evaluation + enrollment/command lifecycle
b0f925bc2b978aa763aac7026101b9cf6e58ed35 feat(mdm): M4 foundation - MDM/ADE evaluation + enrollment/command lifecycle
84562e0b4b6e86aea2fb11e0533bad69ab298017 feat(mdm): M4 foundation - MDM/ADE evaluation + enrollment/command lifecycle
0c11ac5f37b1d318388fafcfb997555ab79f7c05 feat(mdm): M4 foundation - MDM/ADE evaluation + enrollment/command lifecycle
836562616656a5a9ca4d28710be722606d8118d2 feat(mdm): M4 foundation - MDM/ADE evaluation + enrollment/command lifecycle
d21323e871cdbe199bc2f8f479d8e07c810c25f9 feat(mdm): M4 foundation - MDM/ADE evaluation + enrollment/command lifecycle
3a4dcd1b1c10ca8f6f9d830bd24b46d6c1e44f38 feat(mdm): M4 foundation - MDM/ADE evaluation + enrollment/command lifecycle
71747a9b9dda01607874d6a9fda44ecf299be3aa docs: Milestone 3 review report
38f6ead97010c6a723aa8a9e89ffd933afd950f2 Milestone 3: proxy server tests
22c3d130738a63bd12aef26f8029991e3e51c85e Milestone 3: forward filtering proxy
5de1126c9bdf95310ca95450ff43f8ec669b347f Milestone 3: DNS edge runner tests
218519577d317ba79e32d2e0e643541eff2261ed Milestone 3: DNS edge runner
5fb4d7ffd5e74a644f594b5036bea0287e632426 Milestone 3: PAC tests
9981e99b9800338ea2f7c663e83d3cabaec4cbf8 Milestone 3: PAC generation
1b63bbc1435d7d9d915a554519ade6db7b85e20e Milestone 3: pipeline tests
6956a3cf72067bc6341d379f2e308531ca31a430 Milestone 3: hand-assigned seed records
4b2ddbe7d3e6863b6ae2d5db0cc70824231a8ac1 Milestone 3: category dataset builder
a78791e374ba197f5f4c2b96c670ad92a8bc3c5c Milestone 3: dataset provenance and license records
6dbe42e6cfaef8b2dfc38e67548df02cf4597bbb Milestone 3: category taxonomy
ec1dcbe30c3b7b782e576f157676a52ec2887ff4 Milestone 2: fix portal index trailing indentation
73c0d9ad5cbb4e38d71c09d20943d37460f1ec23 Milestone 2: publications root fixture
9d782d470c0a799e7ae6cf62a8f6e33c7a3dd8ed Milestone 2: publications root fixture
8eea752686338435256ab3676816937dbbd39f8f Milestone 2: publications root fixture
01d57b883548ca5a5c081e33e8f25f3763bddb68 Milestone 2: publication revision column
50dc71afb3dee1cb495876234c47bab9a0f25b08 Milestone 2: KG_PUBLICATIONS_ROOT setting
5922d68f4c22aa767988e874a4cba9b1d2e6976f Milestone 2: publications API + static mounts
95a443a700f15acd52e6548787cc4941da081ee4 docs: Milestone 2 review report
974a6c20d5d39d6c959de6e65cea72e0fc74b4a9 Milestone 2: publication tests
a6f04af7493ad408efda811b469b4b7471d96eee Milestone 2: publication revision migration
bb39f4c6674d2241bb0ede3c667b30a464e99054 Milestone 2: publication trigger ops
a9c77d483bd1cb675b4e2f0014404039e362e8da Milestone 2: generation publisher (adapted Stage 11C)
13ad6742793c0718bd33bdf9f9dfa7a7ef661911 Milestone 2: ASGI entry point
2ccd9092f1b2569f2b4d2f6d237b6d94f811934f Milestone 2: admin dashboard logic
aab0477d8715fe67b84a7de865a5e87ed18128a3 Milestone 2: admin dashboard page
693b85f081657b7684f258ee43d7015efd8d59df Milestone 2: family portal logic
121209ce773203d8eab1dbcb6428d6c1ea186ac8 Milestone 2: family portal page
9444525906c366764277edf4850c9ea79ed1c9ae Delete website/website/index.html
8a75523e97b329e12c456372c2234120668b6ab7 Milestone 2: move website to website/index.html (fix path)
e550379b7011a6db53c681730005bafc9fd89079 Milestone 2: public website (development-honest copy)
f4eb0fe9fe31cfc84038df58ca4d1a5de696505a Milestone 2: policy API tests (tighten-only, tenancy, versions)
8f0812d0e4cee696d5e8cc79ed373ea7623a2733 Milestone 2: migration 0002 policies and devices
5eb599099d47391df9b5be1ba7c428dd23755804 Milestone 2: policy operations and tighten-only proofs (engine comparison)
1ae6b0b42d8576f066950a525554ab460e857b10 Milestone 2: policy/device API with tighten-only enforcement
500d1c890ae7aa8635ffa1083a0f5cb141d9c009 Milestone 2: policy/device models (versions, assignments, publication state)
aed93b94b8bc96851e1370d2fdf4bdb2908af3f6 Milestone 1: control-plane API tests (auth, MFA, CSRF, lockout)
65c33d38859b8ddb7c9cff489a9a9f32117ad1ef Milestone 1: control-plane foundation tests (security, config, tenancy)
d7939e0dc0e198d0bde6e1c0cbb889350c7da323 Milestone 1: control-plane test fixtures (bundled PostgreSQL)
4f7469555e42e16f1be555dc1d31bd54d67e04c1 Milestone 1: control-plane test package marker
79b8d319cad78eb01d6d36b82d15dcf4265c3b28 Milestone 1: control-plane API (login, TOTP MFA, sessions, rate limiting)
8ad8d6bccd1848727a962536ded893671ee782f4 Milestone 1: control-plane data layer with tenant-isolation guard
da115bad1e7bc533744f35171222e0763f2ffbeb Milestone 1: control-plane data model (tenants, users, sessions, audit)
4da3ff6bb62d19ce84b808c48a337ce2aeddf2e5 Milestone 1: control-plane security primitives (PBKDF2, hashed sessions, TOTP)
2600a95c4091579b572817dcf3929fc9a918fa16 Milestone 1: control-plane strict env configuration
cb826d1eae86c8349bed277ca4a02b33305f9afb Milestone 1: control-plane app package marker
f384f2b39065ffe749682b2f38f8f675ee7eb334 Milestone 1: migration 0001 initial control-plane schema
1e0ea9acc09669b66da1d699ea78a527f7f31c49 Milestone 1: alembic environment
7775339737275e1e03b92c2f8c150dc039d97c2d Milestone 1: alembic configuration (URL from env, never stored)
0983d1066e822d88ac7c5272e98222e3ec4cfda4 Milestone 1: control-plane dependencies
9948296862283a493f2ccc25b7b698a1d7c31f82 Milestone 1: review report
9c647a5da1e14c026ec8abb7678b93f5adac2392 Milestone 1: requirements coverage (20 parts x milestones x deliverables)
35bd0400a8785bf65399f572593022c8b837276c Milestone 1: full-build architecture (fresh clean design)
35487a6e650c30a7fe2d7d434e70b56fa991e760 Stage 11C: load engine sets through verified directory fds (engine_set)
2e9393009fd608ccf94d2f29fc28a9dd10781dc7 Stage 11C: fix parent-directory symlink traversal in generation loader (generation_io)
4bdecbfef65f26f7f24c1900039e964bba32a9e0 Stage 11C: regression tests for generation symlink traversal fix
996aa3762e03cc161f170bd49a9b06d2d059c02f Remove file committed at a mistaken doubled path
88e93540c585099f24947e1a5724f54f2b717b4c Stage 11C: regression tests for generation symlink traversal fix
63e0ae1001dd8dcf52ddbaed36aadea3431f6d97 Move pre-start review to docs/reviews (correct doubled path)
bfcf1c739af4b25dc7103e6027f5639583632261 Add full-build pre-start review: consolidated questions on the 44 Phase 1 answers
```
