# Device and iOS compatibility matrix

Answer 15: target iOS 26 or later for the initial full-URL-filtering
product, subject to actual Apple API, entitlement, and device compatibility
tests; document a compatibility matrix for older iOS versions; older
devices must receive only the features that have actually been tested.

Nothing below claims device-side success that was not exercised in this
environment. "Tested" means covered by the repository's automated suites
in this environment (no physical iPhone was enrolled; Answers 36/40 give
no hardware, Xcode, or Apple Developer Program membership).

| Feature | iOS 26+ (target) | Older iOS (pre-26) | Evidence level today |
| --- | --- | --- | --- |
| DNS-based web filtering (per-device policy, categories, schedules) | Supported design; engine + edge covered by 337 filtering-engine tests and 85 dns-edge tests; DNS load path measured (docs/reviews/LOAD_TEST.md) | Same as iOS 26: DNS filtering is OS-version independent (works via DNS configuration/DoH profile) | Server side tested in-environment; device DNS profile delivery built-unverified on a physical device |
| MDM enrollment and command channel (queries, restrictions, app commands, erase with two-person approval) | Payloads follow Apple's documented formats | Same payloads; older supervised devices are the realistic MDM fleet | BUILT-UNVERIFIED on device: command lifecycle, queueing and approval gates are tested server-side; no physical enrollment/push was performed |
| Full URL filtering (Network Extension URL Filter, `NEURLFilterManager`) | Target feature; Swift sources carry `@available(iOS 26.0, *)`; requires supervised device for MDM-pushed configuration | NOT AVAILABLE: the API does not exist before iOS 26. Older devices must not be told they have URL-level filtering | Source written; cannot be compiled, signed, entitled, installed, or tested without Apple credentials and hardware (Answer 40 fork) |
| Non-removable enforcement (supervision, non-removable profiles, restrictions) | Designed payload set | Same design; depends on supervision state, not iOS version | Payload/restriction design documented; device behavior unverified |

Rules this matrix enforces:

1. An older (pre-26) device receives only DNS-based filtering plus whatever
   MDM capabilities are verified on that device class at deployment time.
   It must never be marked as having full URL filtering.
2. The iOS 26 URL-filter column stays "target" until the Apple entitlement,
   signing, and on-device tests actually pass; Answer 16 forbids silently
   substituting DNS-only filtering and calling it full filtering.
3. Every "tested" cell above cites suites that run in this repository;
   every "unverified" cell names the missing external step (Apple
   credentials, supervised hardware, Xcode) rather than implying coverage.
