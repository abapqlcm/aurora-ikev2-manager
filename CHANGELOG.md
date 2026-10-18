# Changelog

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
