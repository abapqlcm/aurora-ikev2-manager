# Uninstall

```bash
sudo systemctl disable --now aurora-panel.service
sudo rm -rf /opt/aurora-ikev2 /etc/systemd/system/aurora-panel.service
sudo systemctl daemon-reload
# keep or remove VPN itself:
sudo apt remove strongswan            # removes VPN too
sudo rm -rf /var/lib/aurora-ikev2     # removes panel data/backups
```
The installer never deletes users/certs automatically — removal is always manual.
