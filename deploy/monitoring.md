# Monitoring and logging configuration (M6)

STATUS: configuration only - nothing here is deployed or running.
No hosting has been purchased and no live infrastructure changes.

## Services to monitor

| Service | Health endpoint | Notes |
| --- | --- | --- |
| control-plane | GET /health | auth, policies, publications, category admin |
| mdm | module-level | ADE sync, command queue depth, APNs cert expiry state |
| url-filter-server | GET /v1/dataset/manifest | device-credential protected in production |
| proxy-edge | service-specific | see proxy-edge/ |
| dns-edge | service-specific | per-device DNS identity (DoH) |
| PostgreSQL | pg_isready | backups via deploy/backup.sh |

## Metrics (Prometheus example)

prometheus.yml.example scrapes the service health endpoints on a
30s interval. Alert rules worth enabling before production:
- APNs push certificate expiring within 30 days (mdm.apns state).
- Publication lag: newest tenant generation older than its latest
  policy version.
- 401 rate on /v1/dataset/* spiking (credential or issuance bug).
- Backup job age > 26 hours.

## Logging

- JSON structured logs, one event per line, per service.
- NEVER log: device tokens, session tokens, DoH credentials, APNs
  private keys, ADE tokens, password hashes (user requirement:
  credentials redacted from logs). The device_auth module never logs
  token values; keep it that way in every service.
- Audit events that belong to the business record (policy changes,
  publications, category administration, MDM commands) go to the
  append-only audit_events table, not only to logs.
