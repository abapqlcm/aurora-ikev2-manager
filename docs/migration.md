# Migration: existing strongSwan server

1. Run `sudo ./install.sh --mode existing`.
2. The installer inspects `/etc/ipsec.conf`, `/etc/ipsec.secrets`, certs, pools, firewall and service state — before modifying anything.
3. Compatible (classic EAP-MSCHAPv2) → panel only is installed; VPN config untouched.
4. swanctl (vici) installs → user management IS supported for EAP-MSCHAPv2
   credentials via the swanctl secrets directory (v1.2+). See below.
5. Non-EAP auth methods are reported; Aurora manages only EAP users.
6. The existing strongSwan daemon is never restarted by this mode — it is
   only queried (`ipsec statusall` / `swanctl --list-sas`).


# swanctl (VICI) user management

## How it works
- EAP credentials live in the swanctl secrets directory
  (`/etc/swanctl/secrets/`; Aurora prefers `aurora.secrets`, otherwise the
  first `*.secrets` containing EAP entries).
- Add / delete / disable / enable / password-change edit ONLY that file,
  then run `swanctl --load-secrets` (exact-command sudoers whitelist).
- `swanctl --load-secrets` does NOT restart charon and does NOT touch
  established SAs. New authentications see changes immediately.

## Preconditions (enforced server-side, not just UI)
- `swanctl.conf` must already contain an EAP auth round
  (`remote { auth = eap-mschapv2; eap_id = %any; }`). Aurora NEVER edits
  swanctl.conf — if EAP is not configured it refuses user management with
  an explanation.

## Recovery
- Before every change the secrets file is backed up
  (`AURORA_BACKUP_DIR`, 0600). If `--load-secrets` fails, the pre-change
  content is restored atomically and re-applied.

## Limitations
- **Active sessions:** disabling/deleting a user does NOT terminate an
  already-established IKE SA. strongSwan re-authenticates on rekey
  (default rekey time hours) or reconnect; until then the old session
  keeps working. This is stated in the UI on every disable/delete.
- **Existing secrets formats:** Aurora only parses
  `"user" : EAP "secret"` lines (with its disable-prefix convention).
  Other entry types (RSA, PSK, private keys) in the same file are
  preserved byte-for-byte but never listed or modified.
- **eap_id mapping:** works with `eap_id = %any`; static per-connection
  `eap_id` pinning to one user is out of scope.
- Tested with unit/integration tests against temp files and mocked vici;
  live verification on a real swanctl server is still pending (see README).
