# Backup & restore

## What is backed up
- **Credential changes** (add / delete / disable / enable / password change):
  the helper copies the secrets file to `/var/lib/aurora-secrets-backups/`
  before every write. The directory is root-owned (0700), files are 0600, and
  the newest 10 per file are kept. Restores need root (`sudo`).
- **Installer changes** to `/etc/ipsec.conf` and `/etc/ipsec.secrets` are copied
  to `/var/lib/aurora-ikev2/backups/` (0600), with the same 10-file retention.

## Manual backup
```bash
sudo tar czf aurora-backup.tar.gz /etc/ipsec.conf /etc/ipsec.secrets \
  /etc/ipsec.d/private /etc/ipsec.d/cacerts /etc/ipsec.d/certs /var/lib/aurora-ikev2
```

## Restore
```bash
sudo systemctl stop strongswan-starter
sudo tar xzf aurora-backup.tar.gz -C /
sudo ipsec restart
```
