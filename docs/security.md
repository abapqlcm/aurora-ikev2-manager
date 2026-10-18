# Security

## Summary

- Admin password: PBKDF2-HMAC-SHA256, 600,000 iterations (OWASP 2023 minimum).
  Hashes made with fewer iterations still verify and are upgraded on the next
  successful login.
- Sessions: signed cookies (HttpOnly, SameSite=Lax, Secure unless
  `AURORA_INSECURE_COOKIES=1`), 8 hour expiry.
- CSRF: per-session token required on every POST (HTTP 400 on mismatch). The
  token is rotated after a password change.
- Login rate limit: 5 failures per remote address within 10 minutes (HTTP 429).
  Counters live in the SQLite database, so every worker process shares them.
- Post-login redirects: only same-site paths are accepted. Absolute URLs,
  `//host`, backslash tricks, encoded variants and control characters fall back
  to the dashboard.
- Forced password change: a bootstrap or reset account (`must_change=1`) can
  reach only the login, logout and change-password pages until it changes its
  password.
- Content Security Policy: `default-src 'self'`, `script-src 'self'`,
  `style-src 'self'`. There are no inline scripts or event handlers. Destructive
  forms use `data-confirm` with `static/confirm.js`, and the server validates
  every destructive request independently.
- X-Frame-Options DENY, `nosniff`, `Referrer-Policy: no-referrer`.
- Private keys are never served by the web panel.

## Privilege separation

The panel runs as the unprivileged `aurora` system user (nologin shell) under
systemd with `ProtectSystem=strict`, `ProtectHome=yes`, and `PrivateTmp=yes`.
Its writable area is the data directory only. `NoNewPrivileges` must stay
`false` because sudo needs setuid.

The panel never reads or writes the strongSwan secrets files. Credential
operations go through a single root helper, `/usr/local/libexec/aurora-secrets-helper`
(root:root 0755, source `aurora/secrets_helper.py`). It is stdlib-only and runs
under the system `python3`, so no writable virtualenv is ever executed as root.

Elevation is limited to exact argv matches in `/etc/sudoers.d/aurora-panel`.
The policy is generated from `aurora/privileged.py` (`SUDO_WHITELIST`), so the
Python whitelist and sudoers cannot drift apart. The current entries are:

- the helper, for `classic` and `swanctl`, with ops `list`, `add`, `delete`,
  `enable`, `disable`, `passwd`
- `/usr/sbin/ipsec update`, `rereadsecrets`, `statusall`
- `/usr/bin/systemctl restart strongswan-starter`

Extra arguments, alternate paths and unlisted subcommands are rejected by the
panel before sudo runs, and sudo itself rejects them too.

Passwords reach the helper on stdin as JSON. They never appear in argv, logs
or helper stdout.

## Credential rules (both backends)

- Usernames: 2–64 characters from `[A-Za-z0-9._@-]`.
- Passwords: 8–128 printable ASCII characters. Quotation marks (`"`) and
  backslashes (`\`) are rejected rather than escaped, so the stored secret is
  always byte-identical to what was typed. Leading and trailing spaces are
  rejected. Inner spaces are allowed.
- A rejected request changes nothing.
- Every mutation runs: validate, then back up, then write atomically (temp file,
  fsync, rename, mode 0600), then reload, then roll back if the reload fails.
- If the backup cannot be created, the change is refused.
- Disabling a user keeps the entry as a commented line. Deleting a user removes
  both the active and the disabled line. Changing a password keeps the user's
  enabled or disabled state.

## Backups

- Location: `/var/lib/aurora-secrets-backups`, owned by root, mode 0700. It is
  outside the service user's data directory, so the panel cannot delete or
  tamper with rollback copies.
- Files: mode 0600, named `<file>.<timestamp>.<pid>.bak`.
- Retention: the newest 10 backups per secrets file are kept. Only files matching
  that naming pattern are ever deleted.
- The installer's own backups of `/etc/ipsec.conf` and `/etc/ipsec.secrets` are
  kept under `$BASE_DIR/backups` with the same 10-file retention.
- Backups contain plaintext EAP credentials by design (they are needed for
  rollback). Protect the root account accordingly.

## Administrator credentials

- The installer creates the `admin` account with `must_change=1`. The password
  is generated with Python's `secrets.token_urlsafe` and written to
  `/var/lib/aurora-ikev2/.admin_bootstrap.txt` (mode 600). It is never printed to
  the terminal or the installer log.
- Read the file once, delete it, then sign in and change the password. The panel
  blocks every other page until the change is made.
- Reinstalling over an existing database preserves the admin account. To reset:
  `sudo -u aurora /opt/aurora-ikev2/venv/bin/python /opt/aurora-ikev2/reset_admin.py [username]`.
  The new password is written to `.admin_reset.txt` (mode 600), and the account
  must change it at the next login.
- The Flask secret key is generated once and stored (mode 0600), so panel
  reinstalls do not invalidate active sessions silently.

## Known limitations

- Deleting or disabling a user does not terminate an established IKE SA.
  Authentication is re-checked only at (re)authentication.
- Behind a reverse proxy the rate limiter sees the proxy's address for every
  client, so one attacker can lock out everyone. Use an address-preserving proxy
  configuration if you need per-client limits.
- Installer-side validation (`ipsec` configuration checks) is static only. Run
  `ipsec statusall` or `swanctl --list-conns` after a change to confirm runtime
  state.
