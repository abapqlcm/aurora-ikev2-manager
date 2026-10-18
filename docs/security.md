# Security

- Admin password: pbkdf2 (600k iterations), never displayed after creation, never logged.
- Sessions: signed cookies (HttpOnly, SameSite=Lax, Secure unless localhost dev), 8h expiry.
- CSRF: per-session token required on all POSTs (400 on mismatch).
- Login rate limit: 5 failures / 10 min per IP (HTTP 429).
- Subprocess: argv lists only, never `shell=True`; usernames validated `[A-Za-z0-9._@+-]{2,64}`.
- Files: secrets/backups/DB at 0600/0700; panel runs on 127.0.0.1 — expose only behind TLS proxy.
- CSP `default-src 'self'`, X-Frame-Options DENY, nosniff, no-referrer.
- Firewall: installer never disables ufw; cloud firewall (UDP 500/4500) must be opened at the provider level.
- No endpoint is unauthenticated; private keys are never served by the web panel.

## Privilege separation (v1.1)

The panel service runs as the dedicated unprivileged system user `aurora`
(system user, nologin shell, owned venv under /opt/aurora-ikev2). Elevated
operations go exclusively through `sudo -n` with an exact-command whitelist in
`/etc/sudoers.d/aurora-panel`:

- `/usr/sbin/ipsec rereadsecrets|update|statusall`
- `/usr/bin/systemctl restart|reload strongswan-starter`

The whitelist is validated with `visudo -c` at install time. Any other
privileged command is rejected in application code (`aurora.privileged`) before
sudo is ever invoked, so even a code-injection bug cannot run arbitrary
commands as root. systemd hardening: `ProtectSystem=strict`,
`ProtectHome=yes`, `PrivateTmp=yes`, `ReadWritePaths` limited to the data dir.
(`NoNewPrivileges` must stay false because sudo requires setuid.)

## Administrator credential handling

- Initial password is generated with /dev/urandom, hashed (pbkdf2, 260k
  iterations) and written once to `/var/lib/aurora-ikev2/.admin_bootstrap.txt`
  (0600, aurora-owned) — never in argv, logs or shell history. Delete the file
  after reading.
- Reinstalling the panel over an existing database PRESERVES the existing
  admin account. A reset is always explicit:
  `sudo -u aurora /opt/aurora-ikev2/venv/bin/python /opt/aurora-ikev2/reset_admin.py`
- The Flask secret key is generated once and stored (0600) so panel
  reinstalls don't invalidate active sessions silently.
