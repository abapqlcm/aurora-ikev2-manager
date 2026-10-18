# Installation guide

## Modes
- `--mode fresh` — full install on a clean server (strongSwan + CA + panel).
- `--mode existing` — inspect an existing strongSwan; installs only the panel if compatible. Existing users and certs are preserved. Refuses swanctl-based installs.
- `--mode reinstall` — DESTRUCTIVE. Backs up first, asks you to type REINSTALL.

## Flags
- `--public-ip 1.2.3.4` — skip auto-detection.
- Idempotent: re-running skips already-done steps; firewall/NAT rules are never duplicated.

## Partial failure
Every modified file is backed up to `/var/lib/aurora-ikev2/backups/` before changes. If a later step fails, restore from there and re-run the installer.
