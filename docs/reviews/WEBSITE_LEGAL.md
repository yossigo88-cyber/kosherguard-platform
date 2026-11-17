# Website, legal drafts, baseline story (Answers 35/32/11)

## Answer 35 - brand and website

Retains the KosherGuard name, domain and brand identity, with the
preferred tagline "The best filtering solution for our technical
generation." The new website lives in `website/` (developed
separately; nothing here replaces the live website or touches its
DNS - deployment is out of scope and gated). Pages:

- `index.html` - homepage with How it works, Features, Contact,
  customer login (`/portal/`) and a SEPARATE administrator login
  (`/web/`).
- `support.html` - support channels (Answer 34): in-product support
  requests, verified email support, escalation to an authorized
  administrator; states support cannot casually remove protection and
  advertises no hours or 24/7 service.
- `enrollment.html` - enrollment information, including the honest
  Apple-side limitations (approval pending, no real-device validation
  yet, restore/Activation Lock/eSIM not promised).
- `privacy.html` / `terms.html` - legal DRAFTS (see Answer 32).
- `status.html` - status/help information; no availability target or
  SLA is promised before the service is deployed, measured and funded.

English initially. No untested capabilities or unsupported marketing
claims: pre-launch status is stated on every page; enrollment claims
carry the Apple-pending disclaimer. Structural tests:
`control-plane/tests/test_website.py` (8 tests).

## Answer 32 - legal and privacy documents

Privacy and terms pages are labeled DRAFT - pending professional legal
review. They are not represented as legal approval or binding
agreements. The KosherGuard owner approves the final business/privacy
decisions; before launch the pages need professional review for the
actual customer model, children's data, jurisdictions, Apple
requirements and any future TLS inspection.

## Answer 11 - protected baseline story

Backend enforcement landed earlier (role-based permissions, protected
baseline, tighten-only proof). The website now reflects the same
story: KosherGuard administrators control the protected baseline;
families manage delegated settings and approved exceptions; ordinary
dashboard controls cannot weaken the baseline.
