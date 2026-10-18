# Security

- Admin password: pbkdf2 (600k iterations), never displayed after creation, never logged.
- Sessions: signed cookies (HttpOnly, SameSite=Lax, Secure unless localhost dev), 8h expiry.
- CSRF: per-session token required on all POSTs (400 on mismatch).
- Login rate limit: 5 failures / 10 min per IP (HTTP 429).
- Subprocess: argv lists only, never `shell=True`; usernames validated `[A-Za-z0-9._@+-]{2,64}`.
- Files: secrets/backups/DB at 0600/0700; panel runs on 127.0.0.1 — expose only behind TLS proxy.
- CSP `default-src 'self'`, X-Frame-Options DENY, nosniff, no-referrer.
- Firewall: installer never disables ufw; cloud firewall (UDP 500/4500) must be opened at the provider level.
- No endpoint is unauthenticated; private keys are never served by the web panel.
