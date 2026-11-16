# Expected ongoing costs (spec Part 15 - identified before any spend)

STATUS: estimates only. No purchases are authorized; the user approves
any paid service separately. Prices need re-verification at decision
time - they change.

| Item | Expected monthly cost | Notes |
| --- | --- | --- |
| VPS for control-plane + MDM (4 vCPU) | $20-40 | e.g. Hetzner/DigitalOcean class |
| PostgreSQL hosting | $0-15 | same VPS initially |
| Object storage for dataset shards + backups | $1-5 | S3-compatible |
| Proxy/DNS edge nodes (2x small VPS) | $10-24 | anycast later |
| Domain + TLS | ~$1 | Caddy automates TLS |
| Apple Developer Program | $99/year | required for entitlements |
| Apple Business Manager | free | requires organization D-U-N-S |
| PIR service host | $10-20 | Swift binary, moderate RAM |
| Commercial category feed (OPTIONAL) | varies | NOT approved; seed dataset fallback in use |

Free tiers do not support production MDM/proxy traffic (spec
requirement); the above assumes paid-but-small infrastructure once the
user explicitly approves spend.
