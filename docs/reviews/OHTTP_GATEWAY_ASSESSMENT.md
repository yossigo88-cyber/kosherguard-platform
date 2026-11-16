# OHTTP gateway assessment (Milestone 8 follow-up)

Status: **UNIMPLEMENTED - assessment only.** No OHTTP cryptography is
implemented in this repository and none may be invented here. This
document records the gateway options survey, a recommendation, and
what remains blocked. It changes no runtime behavior.

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

## Recommendation

1. **Do not build a gateway now.** The blocking dependency is Apple's
   OHTTP relay approval; until that exists, a deployed gateway carries
   operational cost and a key-management burden with zero traffic.
2. **When Apple approval lands, deploy `thibmeu/ohttp-gateway`** on our
   edge with `TARGET_URL` pointing at the PIR service, a seed generated
   once and stored in the secret store (never in Git), and the
   well-known key-config endpoint recorded in the NEURLFilter
   configuration delivered to devices.
3. **Interop-test** the deployment against `martinthomson/ohttp`'s
   client tooling before pointing any device at it.
4. Keep the current constraint: any deviation (e.g. Apple requiring an
   Apple-operated or specifically vetted gateway) must be discovered
   from Apple's current NEURLFilter documentation at integration time,
   not assumed from this document.

## Explicitly not done

- No OHTTP key material generated or stored.
- No relay, gateway, or decapsulation code written.
- No claim that NEURLFilter end-to-end privacy is operational; the
  honest status remains: PIR service integrated (Apple's example),
  dataset export implemented, OHTTP layer pending Apple's relay
  approval.
