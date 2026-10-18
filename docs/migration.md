# Migration: existing strongSwan server

1. Run `sudo ./install.sh --mode existing`.
2. The installer inspects `/etc/ipsec.conf`, `/etc/ipsec.secrets`, certs, pools, firewall and service state — before modifying anything.
3. Compatible (classic EAP-MSCHAPv2) → panel only is installed; VPN config untouched.
4. Incompatible (e.g. swanctl) → stops with an explanation; nothing is changed.
5. Non-EAP auth methods are reported; Aurora manages only EAP users.
