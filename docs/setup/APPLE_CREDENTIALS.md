# Apple credentials and setup guide (spec Part 16)

STATUS: preparation only. No credentials exist in this repository, none
were provided, and none may be hardcoded. The user provides account
access, certificates and tokens when the software is ready.

## Two different integrations - do not confuse them

1. **Apple Business Manager ADE server token** (`.p7m` from ABM):
   authorizes the MDM server to sync Automated Device Enrollment
   records (device list, profile assignment). Managed by the mdm
   module's ADE sync (NanoDEP-compatible client) and stored hashed at
   rest. Upload: admin MDM panel (dashboard) -> "ADE token".
2. **MDM push certificate** (CSR -> Apple Push Certificates Portal ->
   signed certificate): authorizes the MDM server to wake devices via
   APNs. Managed by `mdm/apns.py` (certificate lifecycle: CSR
   generation, upload, renewal tracking, expiry states).

## Checklist before first real enrollment

| Item | Where it lands | Gate |
| --- | --- | --- |
| Apple Business Manager account | ABM portal | user creates |
| ADE server token (.p7m) | admin MDM panel upload | ABM admin role |
| MDM push certificate | admin MDM panel upload | Apple ID + CSR from mdm/apns.py |
| APNs topic configuration | mdm config | follows push cert |
| TLS certificate for MDM URL | deploy/Caddyfile.example | public domain + DNS (NOT authorized yet) |
| Apple Developer account | developer.apple.com | user creates, paid |
| url-filter-provider entitlement | Apple approval request | Apple review |
| OHTTP relay | Apple-hosted | Apple approval |

## Rules

- Never invent credentials. Never hardcode credentials. Configuration
  screens accept them at runtime; storage is hashed/encrypted at rest.
- Distinguish the ABM enrollment token from the MDM push certificate
  in every screen and log line - they expire and renew independently.
