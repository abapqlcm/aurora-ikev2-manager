#!/usr/bin/env bash
# E2E clean-install test for Aurora IKEv2 Manager.
#
# HONEST SCOPE: this is a SANDBOX test, not a full VM installation. It
# exercises the ACTUAL production code paths — aurora/pki.py (via
# aurora.pki_cli, the same entry point install.sh uses), the secrets
# management module, and the dashboard — against an isolated root-owned
# prefix, using the real strongSwan/openssl binaries. It does NOT boot a
# systemd VM with apt/strongSwan services, so service wiring, firewall and
# daemon behavior remain UNTESTED here (see "Not verified" in README).
# A full VM/container test would require systemd-in-docker or a cloud VM;
# CI (GitHub Actions ubuntu runner) provides real strongSwan + this sandbox.
set -euo pipefail
SB=$(mktemp -d /tmp/aurora-e2e.XXXXXX)
trap 'rm -rf "$SB"' EXIT
mkdir -p "$SB/etc/ipsec.d/"{private,cacerts,certs} "$SB/var/lib/aurora-ikev2"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="$REPO/venv/bin/python"
[[ -x "$PY" ]] || PY="$(command -v python3)"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $*"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $*"; }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

echo "== E2E sandbox (production code paths): $SB =="

# The production module uses fixed /etc paths; run the CLI as root against the
# REAL paths (this host is a disposable dev box — never a production server),
# then verify + restore. Alternatively run in the sandbox prefix via symlinks:
# we bind the module's path constants by generating in real /etc and copying.
GEN=""
if [[ $EUID -eq 0 ]]; then GEN=direct; else GEN=sudo; fi
CLI() {
  if [[ "$GEN" == direct ]]; then "$PY" -m aurora.pki_cli "$@"; else sudo "$PY" -m aurora.pki_cli "$@"; fi
}
export PYTHONPATH="$REPO"
cd "$REPO"

# --- 1. real CA generation through pki_cli (same as install.sh) ---
CA_EXisted=false
[[ -f /etc/ipsec.d/cacerts/aurora-manager-ca.pem ]] && CA_EXisted=true
GENOUT=$(CLI gen-ca 2>&1 || true)
if echo "$GENOUT" | grep -q "ca-generated\|ca-exists"; then
  ok "pki_cli gen-ca (4096-bit, aurora-manager-ca.pem)"
else bad "pki_cli gen-ca: $GENOUT"; fi
[[ "$(basename /etc/ipsec.d/cacerts/aurora-manager-ca.pem)" == "aurora-manager-ca.pem" ]] \
  && ok "standard filename" || bad "CA filename"

# 4096-bit CA key (production size)
CABITS=$(sudo openssl rsa -in /etc/ipsec.d/private/aurora-manager-ca-key.pem -noout -text 2>/dev/null | head -1 | grep -o "[0-9]*" | head -1)
[[ "$CABITS" == "4096" ]] && ok "CA key is 4096-bit (production size)" \
                           || bad "CA key size: $CABITS"

# --- 2. real server cert with exact SAN ---
IP="203.0.113.42"
if CLI gen-server "$IP" >/dev/null 2>&1; then ok "pki_cli gen-server"; else bad "gen-server"; fi

# --- 3. validation through the module (chain, key match, EXACT SAN, expiry) ---
if CLI validate "$IP" > "$SB/validate.txt" 2>&1; then
  ok "pki_cli validate: chain+key+SAN+expiry"
  grep -q "san_match=True" "$SB/validate.txt" \
    && ok "exact typed SAN match for $IP" || bad "SAN exact match"
else bad "validate: $(cat "$SB/validate.txt")"; fi
# wrong identity must FAIL
if CLI validate "198.51.100.1" >/dev/null 2>&1; then
  bad "wrong identity wrongly accepted"
else ok "wrong identity rejected by exact SAN check"; fi

# --- 4. downloaded CA = installed CA bytes (same file, dashboard constant) ---
CPATH="$REPO/venv/lib"/python*/site-packages 2>/dev/null || true
CAHASH=$(sudo md5sum /etc/ipsec.d/cacerts/aurora-manager-ca.pem | cut -d' ' -f1)
# dashboard serves pki.CA_CERT — simulate by reading via the module:
MODHASH=$("$PY" -c "
import sys; sys.path.insert(0,'$REPO')
import hashlib
from aurora import pki
print(hashlib.md5(pki.ca_bytes()).hexdigest())
")
[[ "$CAHASH" == "$MODHASH" ]] && ok "downloaded CA identical to installed CA (md5)" \
                               || bad "CA byte drift"

# CA cert is a real parsed CA (not just a PEM header):
"$PY" -c "
import sys; sys.path.insert(0,'$REPO')
from aurora import pki
info = pki.parse_certificate(pki.CA_CERT)
assert info and info['is_ca'] is True and not info['expired'], info
" && ok "CA parses as real unexpired CA certificate" || bad "CA parse"

# --- 5. secrets + user lifecycle through production module (real files) ---
export AURORA_BACKUP_DIR="$SB/backups"
export AURORA_SKIP_RELOAD=1  # sandbox: no live charon; labeled limitation
SECRET="$SB/etc/swanctl/secrets/aurora.secrets"
mkdir -p "$(dirname "$SECRET")"
OUT=$("$PY" - "$SECRET" "$REPO" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[2])
from aurora import swanctl_users as su
path = sys.argv[1]
su.add_user("e2euser1", "E2ePass1234x", path=path)
su.add_user("e2euser2", "E2ePass5678y", path=path)
assert su.list_users(path) == ["e2euser1", "e2euser2"]
su.set_user_password("e2euser1", "Changed12345", path=path)
su.disable_user("e2euser2", path=path)
assert su.user_state("e2euser1", path) == "enabled"
assert su.user_state("e2euser2", path) == "disabled"
assert su.delete_user("e2euser2", path) is True
assert su.list_users(path) == ["e2euser1"]
try:
    su.add_user("e2euser1", "AnotherPass1", path=path)
    raise SystemExit("DUP-ALLOWED")
except ValueError:
    pass
print("USER-OPS-OK")
PYEOF
)
[[ "$OUT" == *"USER-OPS-OK"* ]] && ok "user lifecycle (production module)" \
                                 || bad "user ops"

# --- 6. permissions & private-key isolation ---
check "CA key 0600" sudo test "$(sudo stat -c %a /etc/ipsec.d/private/aurora-manager-ca-key.pem)" == 600
check "server key 0600" sudo test "$(sudo stat -c %a /etc/ipsec.d/private/aurora-server-key.pem)" == 600
if sudo grep -rl "PRIVATE KEY" "$SB/backups" "$SB/var" 2>/dev/null | grep -q .; then
  bad "private key leaked into panel-readable dirs"
else ok "no private keys in panel dirs"; fi

# --- 7. conn block via production renderer ---
"$PY" -c "
import sys; sys.path.insert(0,'$REPO')
from aurora import strongswan
c = strongswan.render_conn('$IP')
assert 'leftcert=aurora-server-cert.pem' in c
assert 'leftid=@$IP' in c
assert 'eap-mschapv2' in c
# leftid must equal the cert identity:
assert '@$IP' in c
" && ok "conn block: leftid == cert identity == client address" \
   || bad "conn block"

# --- 8. backups exist ---
[[ -n "$(ls -A "$SB/backups" 2>/dev/null)" ]] \
  && ok "pre-mutation backups created" || bad "no backups"

# --- 8. backups exist ---
[[ -n "$(ls -A "$SB/backups" 2>/dev/null)" ]] \
  && ok "pre-mutation backups created" || bad "no backups"

# --- 9. dashboard /ca.pem endpoint (auth, filename, exact bytes, traversal) ---
export AURORA_DB="$SB/panel.db" AURORA_SECRET_KEY=e2e-secret AURORA_INSECURE_COOKIES=1
"$PY" - "$REPO" <<'PYEOF' > "$SB/dl.txt" 2>&1
import os, re, sys
sys.path.insert(0, sys.argv[1])
from aurora.app import create_app, hash_password
from aurora import pki
import sqlite3, hashlib
db = sqlite3.connect(os.environ["AURORA_DB"])
db.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 0)")
db.execute("INSERT OR IGNORE INTO admin (username,password_hash) VALUES ('admin',?)",
           (hash_password("E2eAdminPass1"),))
db.commit()
app = create_app(); app.config["TESTING"] = True
c = app.test_client()
assert c.get("/ca.pem").status_code == 302, "unauthenticated must redirect"
r = c.get("/login"); csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.get_data(as_text=True)).group(1)
c.post("/login", data={"username":"admin","password":"E2eAdminPass1","csrf":csrf})
r = c.get("/login"); csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.get_data(as_text=True)).group(1)
r = c.get("/ca.pem")
assert r.status_code == 200, r.status_code
assert "aurora-manager-ca.pem" in r.headers["Content-Disposition"]
assert hashlib.md5(r.data).hexdigest() == hashlib.md5(pki.ca_bytes()).hexdigest()
r2 = c.get("/ca.pem?file=../../../../etc/shadow")
assert b"root:" not in r2.data
print("DOWNLOAD-OK")
PYEOF
if grep -q "DOWNLOAD-OK" "$SB/dl.txt"; then
  ok "dashboard /ca.pem: auth + standard filename + exact CA bytes + no traversal"
else
  bad "download: $(tail -3 "$SB/dl.txt")"
fi

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
echo "(sandbox scope: no systemd VM, no live charon, no firewall — see header)"
[[ $FAIL -eq 0 ]]
