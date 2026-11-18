# PIR/OHTTP deployment layer (KosherGuard)

STATUS: source/build/config integration written, NOT built, NOT
deployed, NOT verified end to end. What each layer is and what remains:

| Layer | What it is | Status |
| --- | --- | --- |
| Dataset export | `url-filter-server/app/pir_export.py` emits Apple's keyword-PIR textpb input format | Implemented + tested (Python) |
| Dataset processing | Apple's PIRProcessDatabase (a product of apple/swift-homomorphic-encryption, built from the revision pinned by the service's Package.resolved - NOT a product of pir-service-example; corrected) | Integrated (Dockerfile/script), never built as an image; same pinned flow exercised by the interop workflow |
| Private query service | Apple's PIRService (apple/pir-service-example @ bbb215355b87be40e081756d072f29cd8f9f000b) | Integrated (Dockerfile), never built |
| Token issuer | Privacy Pass publicly-verifiable tokens, inside Apple's PIRService example | Integrated via same image, unconfigured |
| OHTTP gateway | We host; Apple documents it for NEURLFilter | UNIMPLEMENTED - options surveyed and candidate recommended in `docs/reviews/OHTTP_GATEWAY_ASSESSMENT.md`; integration gated on Apple's relay approval |
| OHTTP relay | Apple hosts | BLOCKED on Apple approval |

Honesty notes:
- Apple's README for pir-service-example says the example "should not
  be run in production." Treat this image as the protocol-correct
  reference deployment pending a production-readiness review, not as
  production infrastructure.
- No homomorphic-encryption or OHTTP cryptography is implemented in
  this repository. All private-query crypto runs in Apple's binaries;
  we implement only dataset export, build glue, and (separately) the
  fail-open/fail-closed shard fallback in url-filter-server for
  pre-PIR operation.
- Remaining before any real traffic: build the image, run Apple's
  documented config with a processed KosherGuard dataset, pick/host an
  OHTTP gateway, obtain Apple's OHTTP relay approval, and run the
  end-to-end device test on a supervised device with the approved
  url-filter-provider entitlement.
