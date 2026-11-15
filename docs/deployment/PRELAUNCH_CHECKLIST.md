# KosherGuard dashboard - pre-launch checklist

Complete every item before calling any deployment live. This checklist
is part of deployment PREPARATION; completing it produces a private
deployment of a development application, not a certified production
service. The dashboard manages local policy data only: no Apple MDM, no
APNs push, no enrolled devices, no remote iPhone management.

## Security

- [ ] Admin password is at least 12 characters and stored only in
      `/etc/kosherguard/dashboard.env` (0600, root:root) and in your
      own password store. It is in NO file in the repository, unit
      file, or proxy config.
- [ ] `KG_SECURE_COOKIES=1` is set (the server refuses to start in a
      deployment shape without it - verify you saw no such refusal).
- [ ] `KG_TRUSTED_PROXIES` contains exactly the proxy's address
      (normally `127.0.0.1`) and nothing else.
- [ ] The dashboard binds `127.0.0.1` only: `ss -tlnp | grep 8080`
      shows no public address.
- [ ] The site answers ONLY over HTTPS: `http://YOUR-DOMAIN` redirects
      or fails; `https://YOUR-DOMAIN/api/health` returns
      `{"status":"ok"}`.
- [ ] Signing in over HTTPS sets a cookie with `Secure`, `HttpOnly`,
      `SameSite=Strict` (browser dev tools, Application > Cookies).
- [ ] Failed logins are rate-limited per client address behind the
      proxy (5 failures lock that client for 60 seconds) and appear in
      the audit log without any password material.
- [ ] The dashboard runs as the unprivileged `kosherguard` user, with
      the systemd hardening options from the unit in effect
      (`systemctl show kosherguard-dashboard | grep -E 'NoNewPrivileges|ProtectSystem'`).

## Configuration

- [ ] `/etc/systemd/system/kosherguard-dashboard.service` matches the
      reviewed unit, and any local change is written down.
- [ ] `/etc/caddy/Caddyfile` serves exactly your domain and proxies to
      `127.0.0.1:8080`; Caddy's certificate was issued (check
      `journalctl -u caddy -e` on first load).
- [ ] `KG_REQUEST_TIMEOUT` and `KG_TOTAL_REQUEST_TIMEOUT` are set
      (defaults 30 and 60 seconds) and the total is not smaller than
      the per-read timeout.
- [ ] `systemctl is-enabled kosherguard-dashboard` prints `enabled`.

## Backups

- [ ] `backup.sh` ran at least once by hand and produced a backup file
      that passed its integrity check (the script checks; look for
      `backup: wrote ...`).
- [ ] A schedule (cron or timer) runs `backup.sh` nightly as the
      `kosherguard` user.
- [ ] A RESTORE DRILL was performed on the server: stop, restore the
      newest backup, start, sign in, confirm the data is the
      backup-time state (RUNBOOK.md step 7).
- [ ] At least one backup copy exists OFF the server (another machine
      you own).

## Operational readiness

- [ ] The service restarts cleanly: `systemctl restart
      kosherguard-dashboard` then `curl -s http://127.0.0.1:8080/api/health`.
- [ ] The service comes back after a reboot (reboot once, check
      `systemctl status` and sign in).
- [ ] You know where the logs are: `journalctl -u kosherguard-dashboard`.
- [ ] You know the single-admin recovery procedure (RUNBOOK.md, "If
      something is wrong") and accept that it is manual.
- [ ] The full test suite passes on the deployed revision
      (`python3 -m pytest dashboard/tests/ -q` and
      `python3 -m pytest filtering-engine/tests/ -q`).
- [ ] Everyone who will use the dashboard understands it manages local
      policy data only - no device management exists.
