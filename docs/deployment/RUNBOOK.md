# KosherGuard dashboard - deployment runbook

**Status: deployment PREPARATION.** These steps describe how a first
private deployment would be performed. Nothing has been deployed yet,
no hosting account exists, and this runbook's systemd unit and proxy
config are reviewed but NOT yet tested on a live server - the
pre-launch checklist (PRELAUNCH_CHECKLIST.md) includes verifying them.

The dashboard is a development application: it manages local policy
data only. There is NO Apple MDM connection, no APNs push, no enrolled
devices, and no remote iPhone management. Do not describe a deployment
of it as having those capabilities.

## Architecture

One small Linux server runs two things:

- the dashboard itself (`dashboard/src/server.py`, Python standard
  library only), bound to `127.0.0.1:8080` - never exposed directly;
- Caddy, which terminates HTTPS on a domain you own and reverse-proxies
  to the dashboard.

The dashboard trusts `X-Forwarded-For` only from `KG_TRUSTED_PROXIES`
(the Caddy peer, `127.0.0.1`), and it refuses to start in this
configuration without `KG_SECURE_COOKIES=1` (its cookie deployment
guard). SQLite data lives in `/var/lib/kosherguard/dashboard.db` and is
backed up by `deploy/backup.sh` on a schedule.

## Prerequisites

- A small always-on Linux server (an always-free VM tier such as Oracle
  Cloud Always Free works; the account is created by the owner, not by
  this project).
- Python 3.10+ (`python3 --version`). No pip packages are needed.
- Caddy (`caddy version`), installed via your distribution or
  caddyserver.com's repository.
- A domain name pointing at the server (a free DuckDNS name works).
- systemd (any mainstream distro).

## Step-by-step

### 1. Create a dedicated user

```bash
sudo useradd --system --home /var/lib/kosherguard --shell /usr/sbin/nologin kosherguard
sudo mkdir -p /var/lib/kosherguard
sudo chown kosherguard:kosherguard /var/lib/kosherguard
sudo chmod 0700 /var/lib/kosherguard
```

The state directory and everything in it stays private to the service
user: the database holds session tokens and password hashes. The
systemd unit also creates it with mode 0700 (`StateDirectoryMode`)
when it does not exist.

### 2. Install the code

```bash
sudo mkdir -p /opt/kosherguard
sudo git clone --branch stage-9b-deployment-preparation \
    https://github.com/yossigo88-cyber/kosherguard-platform /opt/kosherguard
```

The `--branch stage-9b-deployment-preparation` is required: the
deployment files this runbook installs live on that branch. Cloning
without it checks out the repository's default branch, which does not
contain the Stage 9B deployment files, and would produce an
installation without the files this runbook tells you to install.

### 3. Create the secrets file

The admin password is never in the unit file or the repo. Put it in a
root-only environment file:

```bash
sudo mkdir -p /etc/kosherguard
sudo tee /etc/kosherguard/dashboard.env > /dev/null <<'EOF'
KG_ADMIN_PASSWORD=choose-a-strong-password-of-at-least-12-characters
EOF
sudo chmod 0600 /etc/kosherguard/dashboard.env
sudo chown root:root /etc/kosherguard/dashboard.env
```

The first start seeds the first administrator from this password
(minimum 12 characters, enforced). Store the password somewhere safe;
there is no self-service recovery.

### 4. Install and start the service

```bash
sudo cp /opt/kosherguard/deploy/kosherguard-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now kosherguard-dashboard
systemctl status kosherguard-dashboard
```

Verify it is listening on localhost only:

```bash
curl -s http://127.0.0.1:8080/api/health   # expect: {"status":"ok"}
ss -tlnp | grep 8080                        # expect: 127.0.0.1:8080 only
```

### 5. Put Caddy in front (HTTPS)

```bash
sudo cp /opt/kosherguard/deploy/Caddyfile.example /etc/caddy/Caddyfile
sudo $EDITOR /etc/caddy/Caddyfile   # replace dashboard.example.com with your domain
sudo systemctl reload caddy
```

Caddy obtains the TLS certificate automatically once DNS resolves to
the server. The unit already sets `KG_TRUSTED_PROXIES=127.0.0.1` and
`KG_SECURE_COOKIES=1`, matching the proxy. If you change the proxy's
address, change `KG_TRUSTED_PROXIES` to match and restart.

Verify:

```bash
curl -s https://YOUR-DOMAIN/api/health   # expect: {"status":"ok"}
```

Then sign in at `https://YOUR-DOMAIN/` and change nothing else.

### 6. Schedule backups

Run `deploy/backup.sh` as the service user, nightly (or more often):

```bash
sudo -u kosherguard bash /opt/kosherguard/deploy/backup.sh /var/lib/kosherguard
```

To schedule it, a cron entry for the kosherguard user:

```bash
sudo -u kosherguard crontab -e
# add: 17 3 * * * bash /opt/kosherguard/deploy/backup.sh /var/lib/kosherguard
```

Backups land in `/var/lib/kosherguard/backups/` and are rotated (keep
14 by default; `KEEP=` environment). `backup.sh` forces the backup
directory to 0700 and every backup file to 0600 (a backup is the full
database, session tokens and password hashes included), writes to a
temporary file and publishes it only after an integrity check passes,
and validates `KEEP` as a positive integer before rotating - an
invalid value fails without taking or deleting any backup. A backup
on the same machine is not enough for real recovery: copy the backups
somewhere else you own (on another machine: `scp`/`rsync` over SSH,
or Tailscale between your own machines).

### 7. Test a restore BEFORE you need it

```bash
sudo systemctl stop kosherguard-dashboard
sudo -u kosherguard bash /opt/kosherguard/deploy/restore.sh \
    /var/lib/kosherguard/backups/LATEST-FILE.db /var/lib/kosherguard \
    --force --service-stopped
sudo systemctl start kosherguard-dashboard
curl -s http://127.0.0.1:8080/api/health   # expect: {"status":"ok"}
```

`restore.sh` refuses to run without `--service-stopped`, an explicit
confirmation that the dashboard service has been stopped. `--force`
only covers overwriting the existing database; it does not imply the
service is stopped. The restored database file is owner-only (0600).

Sign in and confirm your data is the backup-time state. The automated
test suite (`dashboard/tests/test_backup_restore.py`) performs this
whole round trip against throwaway databases; run it after any change
to the scripts.

## Updating

```bash
cd /opt/kosherguard
sudo git fetch origin
sudo git pull origin stage-9b-deployment-preparation
sudo systemctl restart kosherguard-dashboard
curl -s http://127.0.0.1:8080/api/health
```

Always name the branch explicitly on update; do not rely on the
repository's default branch.

Back up before updating.

## If something is wrong

- Logs: `journalctl -u kosherguard-dashboard -e`
- The server refuses to start with a clear message when a security
  setting is ambiguous or missing for the deployment shape (cookie
  guard, bad proxy IP, bad timeout values). Read the message; do not
  work around it by weakening the configuration.
- The dashboard is single-admin; a lost password means re-seeding the
  admin row by hand (delete the row in SQLite while stopped, then start
  with `KG_ADMIN_PASSWORD` set) - treat the password accordingly.


---

## Stage 10: the publication loop (dashboard -> engine)

The dashboard and the DNS engine connect through a shared publication
directory (default: `/var/lib/kosherguard/published` in the systemd
units). The dashboard writes immutable configuration generations; the
engine reads them through the `current` pointer.

Directory layout:

    published/
        generations/<revision>/   policy.json, categories.json,
                                  manifest.json (revision + SHA-256s)
        current -> generations/<N>   atomic symlink pointer
        engine-status.json           written by the engine after every load

Publishing (from the dashboard UI or API):

1. Select a policy for publication (Publication page, or
   `POST /api/policies/<id>/select`).
2. Publish (`POST /api/config/publish` or the Publish button). The
   dashboard validates the complete configuration with the engine's own
   validators, writes a new generation, verifies it from disk, and
   atomically switches `current`. A failed publish keeps the previous
   generation live.
3. The engine picks up the new generation within `--watch` seconds, or
   immediately on `sudo systemctl reload kosherguard-engine` (SIGHUP).
   An invalid or corrupted generation is rejected and the engine keeps
   serving the last valid configuration; the rejection is in the engine
   log and in `engine-status.json` (`last_error`).
4. The dashboard's Publication page shows the engine as live only when
   the engine's status file confirms it is enforcing the published
   revision.

Rollback: `POST /api/config/rollback {"revision": N}` (or the button on
the Publication page) publishes the complete stored content of revision
N as a NEW revision. History is never modified.

Operational rules:

- Both services must run as the same user (the units use `kosherguard`):
  generations are 0700 directories with 0600 files.
- Never edit files under `generations/` by hand; publish or roll back
  through the dashboard.
- If `current` is ever missing or broken, the engine keeps its last
  valid configuration; publish again from the dashboard to restore it.
