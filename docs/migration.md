# Migration: existing strongSwan server

1. Run `sudo ./install.sh --mode existing`.
2. The installer inspects `/etc/ipsec.conf`, `/etc/ipsec.secrets`, certs, pools, firewall and service state — before modifying anything.
3. Compatible (classic EAP-MSCHAPv2) → panel only is installed; VPN config untouched.
4. swanctl (vici) installs → panel installed READ-ONLY: monitoring and
   diagnostics work, user management is disabled (both in the UI and enforced
   server-side). swanctl config/secrets/certs are never modified. Aurora does
   NOT claim swanctl user management support in this version.
5. Non-EAP auth methods are reported; Aurora manages only EAP users.
6. The existing strongSwan daemon is never restarted by this mode — it is
   only queried (`ipsec statusall` / `swanctl --list-sas`).
