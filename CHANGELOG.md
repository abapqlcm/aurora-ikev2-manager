# Changelog

## 1.3.0 — 2026-10-18 (automation + standard CA naming)
- Standard CA filename `aurora-manager-ca.pem` across installer, storage,
  dashboard download, setup instructions and docs; legacy /ca.crt kept as an
  alias serving the same certificate.
- New aurora/pki.py: automated CA/server-cert generation with SAN validation,
  chain verification (openssl verify), cert/key modulus match, expiry check,
  restrictive permissions, explicit-approval CA replacement.
- Installer: certificate validation step after generation; conflict detection
  on fresh installs over existing non-Aurora configs; identity-mismatch
  server-cert regeneration.
- Dashboard /ca.pem: fixed path (no traversal), auth required, PEM content
  check, clear 404/500 errors; never serves private keys.
- Backend detection hardening (AURORA_FORCE_BACKEND test override; swanctl
  wins only with swanctl.conf present).
- Tests: 58 -> 76 unit + new E2E sandbox script (tests/e2e_clean_install.sh,
  15 checks) run against REAL strongSwan pki/openssl on this host.
- Not verified on a live server: actual Android app connection, real IKE
  session establishment.

## 1.2.0 — 2026-10-18 (swanctl user management)
- NEW: EAP-MSCHAPv2 user management for swanctl/VICI deployments
  (aurora/swanctl_users.py): add/delete/disable/enable/password change via
  the swanctl secrets directory + `swanctl --load-secrets` (no daemon
  restart, established SAs untouched).
- Server-side enforcement: user management requires an EAP auth round in
  swanctl.conf; Aurora never edits swanctl.conf.
- Recovery: pre-change content restored atomically on failed reload;
  per-change backups (0600).
- sudoers whitelist extended with `/usr/sbin/swanctl --load-secrets`.
- +16 tests (58 total): isolated secrets files, unrelated-user
  preservation, backup-on-mutation, reload-failure restore, EAP-precondition,
  dashboard dispatch for swanctl.
- Known limitation (documented): active sessions of deleted/disabled users
  persist until rekey/reconnect.

## 1.1.0 — 2026-10-18 (hardening)
- Privilege separation: panel runs as unprivileged `aurora` user; exact-command
  sudoers whitelist (validated with visudo -c); systemd hardening
  (ProtectSystem=strict, PrivateTmp, ProtectHome).
- existing mode: never restarts strongSwan; conn name no longer required for
  panel-only installs (verification queries any responding daemon).
- swanctl installs: read-only panel instead of hard refusal; user management
  blocked server-side; support NOT claimed for swanctl user management.
- Public IP detection: classifies public/private/NAT and requires an explicit
  --public-ip behind cloud NAT (certificate SAN/leftid correctness).
- Reinstall: preserves admin account and existing EAP users; stable secret key
  across reinstalls; reset_admin.py helper for explicit resets.
- Certificate identity: SAN + leftid both derived from the same validated
  public IP; documented in client setup.
- Installer: ERR trap with rollback guidance, backups before every modification,
  firewall/cloud-firewall distinction documented, NAT/sysctl skipped in
  panel-only mode.
- Tests: 26 -> 42 (privilege separation, address classification, swanctl
  detection/blocked management, installer static assertions).

## 1.0.0 — 2026-10-18
- Initial release.
- Installer with fresh / existing / reinstall modes.
- Flask dashboard (dark, mobile-first) with auth, CSRF, rate limiting.
- Per-user EAP management on classic ipsec.secrets.
- Live session monitoring via ipsec statusall parsing.
- Automatic pre-modification backups; diagnostics page.
- 26 automated tests (unit, no privileged operations).
