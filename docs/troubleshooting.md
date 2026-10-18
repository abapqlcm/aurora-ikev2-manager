# Troubleshooting

| Symptom | Check |
|---|---|
| Connection times out | Cloud security group allows UDP 500+4500? `sudo ufw status` |
| `ipsec statusall` missing conn | Config syntax: `sudo ipsec restart` then `journalctl -u strongswan-starter -n 50` |
| Auth fails for one user | Disabled? `sudo grep user /etc/ipsec.secrets` (a `# disabled by aurora:` line = disabled) |
| Connected but no internet | `sysctl net.ipv4.ip_forward` must be 1; NAT rule present: `iptables -t nat -S POSTROUTING` |
| Panel unreachable | `systemctl status aurora-panel`; it binds 127.0.0.1:8080 only |
| Forgot admin password | Delete the DB row and re-run the admin-creation block from install.sh |
