# PostgreSQL backup and recovery (platform control-plane)

STATUS: the scripts below exist and are exercised end-to-end by the
automated test suite on disposable PostgreSQL. No production
deployment exists yet, so nothing here is a live procedure and no SLA
is promised (Answer 37: no availability target or SLA before the
service is deployed, measured and funded). The one-hour recovery time
and 15-minute recovery-point figures below are FUTURE planning
targets only, subject to budget and successful recovery testing.

Scope: the platform control-plane PostgreSQL database. The legacy
dashboard SQLite backup (`deploy/backup.sh`) has its own section in
`docs/deployment/RUNBOOK.md` and is not covered here.

## What is backed up

`deploy/pg_backup.sh` takes a consistent logical dump of the whole
platform database with one deliberate exception: browsing history
(`filter_decisions` rows) is EXCLUDED from every new backup. A backup
that leaks a child's blocked-domain history into long-lived archives
is a privacy failure, so history is treated as non-archivable:
it lives only in the live database under its retention window and is
physically deleted on schedule. The test suite proves a new archive
contains no history table data, and that restoring a LEGACY archive
that does contain history strips it on the way in
(`control-plane/tests/test_privacy_backups.py`).

Safety properties of the script (keep them):

- The dump is verified readable (`pg_restore --list`) BEFORE it is
  published; a failed run never leaves a partial file that looks
  complete.
- Publication is atomic and never overwrites an existing backup
  (hard-link publication with collision retry); concurrent runs
  cannot clobber each other.
- The backup directory is forced to 0700 and every archive to 0600;
  archives contain the full control-plane database including
  credential metadata, so they are sensitive.
- `KEEP` (default 14) is validated as a positive integer before
  anything happens.

## Current schedule (development environment)

Run nightly as the service user, plus before any risky change:

    bash deploy/pg_backup.sh "$DATABASE_URL" /var/lib/kosherguard/backups
    # cron example: 23 4 * * * bash /opt/kosherguard/deploy/pg_backup.sh \
    #     "$DATABASE_URL" /var/lib/kosherguard/backups

A backup on the same machine is not recovery: copy the archives to a
second location owned by the operator. That copy step is operational
and is not automated by this repository today.

## Restore procedure (drill)

Never restore into the live database. Restore into a scratch
database, verify, then repoint:

1. Stop the platform services.
2. Restore with the supported script - it refuses without the
   explicit flag, verifies the archive first, and strips any legacy
   browsing-history table data before loading:

       bash deploy/pg_restore.sh /var/lib/kosherguard/backups/FILE.dump \
           postgresql://...scratch-db... --service-stopped

3. Run migrations against the scratch database
   (`alembic upgrade head`) so an older archive lands on the current
   schema before any service reads it.
4. Run the privacy maintenance pass (blocked-log purge) so no
   expired rows ride back in.
5. Verify: spot-check tenant, user, policy and device counts against
   expectations; sign in with a known account.
6. Only then repoint services at the restored database (or promote
   it) and start them.

## Drill cadence and evidence

Run the full drill on a scratch database before launch, after every
schema-affecting change, and at least quarterly once live. Record
the date, archive name, target environment and result in the
operations audit channel. The automated test
(`test_privacy_backups.py`) runs the real `pg_dump`/`pg_restore`
binaries through these scripts on disposable PostgreSQL on every
suite run, so script breakage fails CI; the drill additionally
exercises the human steps (migrations, verification, cutover).

## Future production targets (Answer 37)

The owner's future planning targets - recovery within one hour,
15-minute database recovery-point objective - become meaningful only
after deployment is funded:

- A 15-minute RPO cannot be met by nightly `pg_dump`. It requires
  WAL archiving / point-in-time recovery (managed PostgreSQL PITR or
  self-hosted WAL archiving). Choosing and funding that is a
  deployment decision, deliberately not made here.
- A one-hour RTO requires the drill above to be rehearsed against
  production-like infrastructure with measured timings, plus a
  documented cutover. The procedure above is the rehearsal base.

Until then the development environment is best-effort: nightly
logical backups, 14 kept, restore tested by the suite and by drill.
