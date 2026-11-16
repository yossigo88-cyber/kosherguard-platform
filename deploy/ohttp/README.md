# OHTTP gateway deployment layer (KosherGuard)

STATUS: deployment wiring + local interop test, written and executed
locally. NEVER built as an image, NEVER deployed, NO live traffic.
Live NEURLFilter traffic remains blocked on Apple's OHTTP relay
approval (see `deploy/pir/README.md`).

## What this is

The OHTTP gateway is the KosherGuard-operated half of the RFC 9458
pair (Apple operates the relay): it decapsulates encrypted device
requests and forwards them to the PIR service, learning WHAT was
requested but never WHO asked.

No gateway code or OHTTP cryptography is implemented in this
repository. We integrate the vetted third-party gateway
`thibmeu/ohttp-gateway`, pinned by commit in `PINNED` (MIT license).
Selection rationale: `docs/reviews/OHTTP_GATEWAY_ASSESSMENT.md`.

## Contents

| File | What |
| --- | --- |
| `PINNED` | Upstream source + commit SHA + license + date checked |
| `Dockerfile` | Image build for the pinned gateway. UNBUILT. `OHTTP_KEY_SEED` is a runtime secret from the secret store, never baked in. |
| `interop/run-local-interop.sh` | Executable local proof: fetches the pinned gateway, runs it with an ephemeral fixture seed against a stub target, and completes a full RFC 9458 round trip |
| `interop/interop-client.mjs` | The OHTTP client half of that proof (fetches the well-known key config, encapsulates, decapsulates, asserts) |

## Running the local interop test

Requires node >= 24.7 on PATH (upstream `engines`; the sandbox proof
ran node v26.13.1, matching the Dockerfile's node:26-alpine). Node
22 fails at ML-KEM-768 native key derivation - that is an
environment requirement, not a code defect.

```sh
deploy/ohttp/interop/run-local-interop.sh
```

Last local run: 2026-11-16, node v26.13.1, pinned commit b071b966 -
PASS ("decapsulated request reached target and response decapsulated
intact"). The fixture seed is generated per run by
`crypto.randomBytes`, passed only via environment, never stored or
logged.

## Production path (when Apple's relay approval lands)

1. Build the image from `Dockerfile`; the build fetches exactly the
   pinned commit.
2. Generate one master seed (`npm run keygen` upstream), store it in
   the secret store - never in Git, never in the image.
3. Deploy with `OHTTP_KEY_SEED` from the secret store and
   `TARGET_URL` pointing at the PIR service (`deploy/pir`).
4. Record the gateway's `/.well-known/ohttp-gateway` URL in the
   NEURLFilter configuration delivered to devices.
5. Re-run the interop test against the deployed instance before any
   device is pointed at it.

## Explicitly not done

- No real key material exists anywhere in this repository.
- No image build, no deployment, no Apple relay, no device traffic.
- No claim of end-to-end NEURLFilter privacy operation.
