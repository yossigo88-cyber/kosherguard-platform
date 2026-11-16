# OHTTP gateway assessment (Milestone 8 follow-up)

Status: **gateway not operated; deployment wiring built and
interop-tested locally** (updated 2026-11-16 after the owner's
direction to complete all pre-approval preparation). No OHTTP
cryptography is implemented in this repository and none may be
invented here. This document records the gateway options survey, the
selected candidate, and what remains blocked.

Sources checked 2026-11-16:

- Apple `pir-service-example` (the vetted PIR service we integrate in
  `deploy/pir`), including `Sources/PIRService/PIRService.docc/TestingInstructionsNEURLFilter.md`
  - covers running the PIR service for NEURLFilter; the OHTTP gateway
    is an operator-supplied component in front of it.
- RFC 9458 (Oblivious HTTP).
- Gateway candidates below.

## Architecture reminder

OHTTP splits knowledge between two parties:

| Role | Who operates it | Learns |
| --- | --- | --- |
| Relay | Apple (for NEURLFilter on-device fetches) | WHO asked (client IP) |
| Gateway (this assessment) | KosherGuard | WHAT was requested (decapsulated inner request) |
| Target | KosherGuard PIR service (`deploy/pir`) | the PIR query itself |

Apple's relay is what makes the privacy guarantee hold for our users;
without Apple's relay approval a self-hosted gateway serves no
NEURLFilter traffic at all, so gateway integration remains gated on
that approval first (already tracked in `deploy/pir/README.md`).

## Candidates surveyed

| Candidate | Form | Notes |
| --- | --- | --- |
| `thibmeu/ohttp-gateway` | Deployable gateway (TypeScript; Cloudflare Workers, Vercel, Netlify, Railway) | RFC 9458 decapsulate/forward/encapsulate. Stateless: key config derived deterministically from one master seed (`OHTTP_KEY_SEED`), so the same config is served from every region. Hybrid key config: X25519 (DHKEM-X25519-HKDF-SHA256) plus post-quantum ML-KEM-768. Serves its key config at the RFC 9458 well-known endpoint. **Leading candidate.** |
| `martinthomson/ohttp` | Rust library (Apache-2.0), maintained by the RFC 9458 editor, with chris-wood (WG editor) among contributors | Reference-grade implementation, but it is a *library*, not a deployable gateway; adopting it means writing and operating our own server around it. Best used for interop/conformance testing of whichever gateway we deploy. |
| `openpcc/ohttp`, `gruberb/ohttp-gateway`, Guardian Project `ohttp-gp` | Libraries / niche gateways | Surveyed; no advantage over the two above for our deployment model. |

## Decision and current state

`thibmeu/ohttp-gateway` selected (RFC 9458, stateless seed-derived key
config, X25519 + ML-KEM-768 hybrid, deployable on our edge). Following
the owner's direction that all code/deployment preparation be
completed before external approvals, the integration is built at
`deploy/ohttp/`:

1. **Pinned**: commit b071b966ba75379230355b8ce6a74a300fb8bbd9 (no
   upstream tags exist), MIT license, recorded in
   `deploy/ohttp/PINNED`.
2. **Deployment wiring**: `deploy/ohttp/Dockerfile` (node:26-alpine,
   fetches exactly the pinned commit; seed injected at runtime from
   the secret store, never baked in). Image never built, never
   deployed.
3. **Local interop test, executed**: full RFC 9458 round trip
   (well-known key config -> encapsulate -> gateway decapsulate/forward
   -> stub target -> encapsulated response -> client decapsulate)
   against the pinned gateway running with an ephemeral fixture seed.
   PASS 2026-11-16 on node v26.13.1 via
   `deploy/ohttp/interop/run-local-interop.sh`. Requires node >= 24.7
   (upstream engines; node 22 fails ML-KEM-768 native derivation).

   Exactly what this proves, and what it does not:
   - PROVEN: the pinned gateway builds and runs as wired, serves its
     key config, and completes a standards-correct round trip with an
     ohttp-ts client against a STUB target.
   - NOT proven: the Docker image build (never run); interop with
     Apple's actual PIR service as the target (never attempted);
     ciphersuite/protocol compatibility with Apple's OHTTP relay and
     the on-device NEURLFilter client (Apple's exact requirements are
     unverified - the gateway's X25519 + ML-KEM-768 key config may or
     may not match what Apple accepts); any behavior on a real device.
   These are separate validation steps, not one item collapsible into
   "waiting on Apple's relay approval."
4. **Still gated on Apple**: live NEURLFilter traffic requires Apple's
   OHTTP relay approval; the gateway has no production traffic until
   then. `martinthomson/ohttp` remains the conformance reference.
5. Keep the constraint: any deviation (e.g. Apple requiring an
   Apple-operated or specifically vetted gateway) must be discovered
   from Apple's current NEURLFilter documentation at integration time,
   not assumed from this document.

## Explicitly not done

- No real OHTTP key material exists (fixture seeds are ephemeral and
  per-test-run only).
- No gateway image build, no deployment, no relay, no device traffic.
- No claim that NEURLFilter end-to-end privacy is operational; the
  honest status remains: PIR service integrated (Apple's example),
  dataset export implemented, gateway wiring ready and
  interop-tested locally, live OHTTP operation pending Apple's relay
  approval.
