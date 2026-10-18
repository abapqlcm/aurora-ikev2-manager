# Backup & restore

## What is backed up
Every write to `/etc/ipsec.conf` or `/etc/ipsec.secrets` first copies the file to
`/var/lib/aurora-ikev2/backups/<name>.<pid>.bak` (0600).

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
