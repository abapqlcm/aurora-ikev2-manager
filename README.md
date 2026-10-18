# Aurora IKEv2 Manager

![license](https://img.shields.io/badge/license-MIT-blue) ![platform](https://img.shields.io/badge/platform-Ubuntu%2020.04%2B-orange) ![tests](https://img.shields.io/badge/tests-26%20passing-brightgreen)

A self-hosted, mobile-friendly web manager for **strongSwan IKEv2 VPN servers** on Ubuntu.
One installer, one dark-themed dashboard, per-user credentials, live sessions, backups, diagnostics — no third-party SaaS.

## Features

- **Fresh install mode** — detects Ubuntu version/arch/public IP/interface, installs strongSwan, generates a CA + server cert, configures IKEv2 with EAP-MSCHAPv2, sets up NAT/forwarding, verifies the daemon actually loads the connection.
- **Existing server mode** — inspects the current strongSwan config first, preserves users/certs, and *refuses* to touch incompatible setups (e.g. swanctl-based).
- **Reinstall mode** — explicit, interactive confirmation, automatic backup first, never deletes by default.
- **User management** — create / delete / enable / disable / change password; duplicate and injection-safe input validation; passwords never displayed or logged; disabled users are revoked by commenting their secret.
- **Dashboard** — service status, user count, active sessions, pool usage, CPU/RAM/disk/uptime.
- **Live connections** — parsed from `ipsec statusall`; nothing is fabricated when the daemon is down.
- **Security** — pbkdf2-hashed admin, CSRF on every POST, login rate limiting, secure cookies, strict CSP/XFO/nosniff headers, shell-injection-safe subprocess calls, 0600 file permissions.
- **Backups** — every modification of `ipsec.secrets` / `ipsec.conf` is backed up first to `/var/lib/aurora-ikev2/backups` (mode 0700).

## Requirements

- Ubuntu 20.04 / 22.04 / 24.04 (amd64 or arm64), root
- UDP 500 + 4500 reachable (check your **cloud firewall** separately from ufw)
- A public IP

## Install

```bash
git clone https://github.com/abapqlcm/aurora-ikev2-manager.git
cd aurora-ikev2-manager
sudo ./install.sh --mode fresh                # new server
sudo ./install.sh --mode existing             # add panel to existing strongSwan
sudo ./install.sh --mode reinstall            # destructive, asks confirmation, backs up first
sudo ./install.sh --mode fresh --public-ip 1.2.3.4   # when auto-detection fails
```

The installer prints the generated admin password **once** — change it after first login.

The panel listens on `127.0.0.1:8080`. For remote access put it behind nginx with TLS:

<details><summary>nginx TLS reverse proxy example</summary>

```nginx
server {
    listen 443 ssl;
    server_name vpn.example.com;
    ssl_certificate     /etc/letsencrypt/live/vpn.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/vpn.example.com/privkey.pem;
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
    }
}
```

Enable TLS with `sudo certbot --nginx -d vpn.example.com`.
</details>

## Android client setup

1. Install the official **strongSwan VPN Client** from Google Play.
2. Download the CA cert from the panel's *Client* page (login required) and install it via Android Settings → CA certificate.
3. Add a profile: server = your server IP, type = **IKEv2 EAP**, your username/password, CA = Aurora VPN CA.

Full guide: [docs/android-setup.md](docs/android-setup.md)

## Documentation

| Document | Contents |
|---|---|
| [docs/installation.md](docs/installation.md) | Modes, flags, troubleshooting during install |
| [docs/migration.md](docs/migration.md) | Adding the panel to an existing strongSwan |
| [docs/security.md](docs/security.md) | Threat model, hardening checklist |
| [docs/backup-restore.md](docs/backup-restore.md) | What is backed up, how to restore |
| [docs/troubleshooting.md](docs/troubleshooting.md) | Common failures and fixes |
| [docs/uninstall.md](docs/uninstall.md) | Clean removal |
| [CHANGELOG.md](CHANGELOG.md) | Release history |

## Test results

| Test | Status |
|---|---|
| Environment detection (OS/arch/IP/interface/strongSwan presence) | ✅ 26/26 automated tests pass |
| User add / duplicate rejection / delete / disable / enable / password change | ✅ unit-tested |
| Invalid & malicious input (shell metacharacters, unicode, length) | ✅ unit-tested |
| Secrets file permissions (0600) | ✅ unit-tested |
| `ipsec statusall` parsing | ✅ unit-tested against real output format |
| Login, CSRF, rate limiting, security headers, XSS escaping | ✅ unit-tested (Flask test client) |
| Real VPN connect / simultaneous sessions / NAT traversal | ⚠️ requires a real Ubuntu server with public IP — **not verified in the dev environment** |

## Limitations

- Targets the **classic** `ipsec.conf`/`ipsec.secrets` layout. Existing swanctl (vici) installs are detected and refused rather than migrated.
- Only one admin account.
- Connection duration/traffic counters depend on strongSwan plugin availability.

## License

MIT — see [LICENSE](LICENSE).
