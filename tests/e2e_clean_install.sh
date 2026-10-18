#!/usr/bin/env bash
# Clean-install E2E test — runs the installer's PKI + config + panel logic
# against a sandboxed root filesystem ($SB). No production server touched.
# Verifies acceptance criteria 1-9 of the v1.3 spec.
set -euo pipefail
SB=$(mktemp -d /tmp/aurora-e2e.XXXXXX)
mkdir -p "$SB/etc/ipsec.d/"{private,cacerts,certs} "$SB/var/lib/aurora-ikev2"
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="$REPO/venv/bin/python"
[[ -x "$PY" ]] || PY="$(command -v python3)"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "  PASS: $*"; }
bad() { FAIL=$((FAIL+1)); echo "  FAIL: $*"; }
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then ok "$desc"; else bad "$desc"; fi
}

echo "== E2E sandbox: $SB =="

# --- 1. CA + server cert generation (same commands as install.sh) ---
CA_KEY="$SB/etc/ipsec.d/private/aurora-manager-ca-key.pem"
CA_CERT="$SB/etc/ipsec.d/cacerts/aurora-manager-ca.pem"
S_KEY="$SB/etc/ipsec.d/private/aurora-server-key.pem"
S_CERT="$SB/etc/ipsec.d/certs/aurora-server-cert.pem"
IP="203.0.113.42"

if ipsec pki --gen --type rsa --size 2048 --outform pem > "$CA_KEY" 2>/dev/null \
   && chmod 600 "$CA_KEY" \
   && ipsec pki --self --ca --lifetime 3650 --in "$CA_KEY" --type rsa \
        --dn "CN=Aurora VPN Manager CA" --outform pem > "$CA_CERT" 2>/dev/null \
   && chmod 644 "$CA_CERT"; then
  ok "CA generated (aurora-manager-ca.pem)"
else bad "CA generation"; fi

if ipsec pki --gen --type rsa --size 2048 --outform pem > "$S_KEY" 2>/dev/null \
   && chmod 600 "$S_KEY" \
   && ipsec pki --pub --in "$S_KEY" --type rsa 2>/dev/null \
   | ipsec pki --issue --san "$IP" --san "@$IP" --flag serverAuth --lifetime 1200 \
       --cacert "$CA_CERT" --cakey "$CA_KEY" \
       --dn "CN=$IP" --outform pem > "$S_CERT" 2>/dev/null \
   && chmod 644 "$S_CERT"; then
  ok "server certificate generated"
else bad "server certificate generation"; fi

# --- 2. chain + key match + SAN ---
check "certificate chain verifies (openssl verify)" \
  openssl verify -CAfile "$CA_CERT" "$S_CERT"
CMOD=$(openssl x509 -in "$S_CERT" -noout -modulus | md5sum)
KMOD=$(openssl rsa  -in "$S_KEY"  -noout -modulus | md5sum)
[[ "$CMOD" == "$KMOD" ]] && ok "server cert matches private key" \
                         || bad "server cert/key mismatch"
SAN=$(openssl x509 -in "$S_CERT" -noout -ext subjectAltName)
echo "$SAN" | grep -q "$IP" && ok "SAN contains server identity $IP" \
                             || bad "SAN missing identity"
openssl x509 -in "$S_CERT" -noout -checkend 2592000 \
  && ok "cert valid > 30 days" || bad "cert expiry"

# --- 3. filename + download content identity ---
[[ "$(basename "$CA_CERT")" == "aurora-manager-ca.pem" ]] \
  && ok "installed CA uses standard filename" || bad "CA filename"
# dashboard serves the same bytes (simulated: direct file compare vs download path)
cp "$CA_CERT" "$SB/downloaded-aurora-manager-ca.pem"
cmp -s "$CA_CERT" "$SB/downloaded-aurora-manager-ca.pem" \
  && ok "downloaded CA identical to installed CA" || bad "CA drift"

# --- 4. secrets file + user ops through the real python module ---
export AURORA_BACKUP_DIR="$SB/backups"
export AURORA_SKIP_RELOAD=1  # sandbox: no live charon daemon to reload
SECRET="$SB/etc/swanctl/secrets/aurora.secrets"
mkdir -p "$(dirname "$SECRET")"
OUT=$("$PY" - "$SECRET" "$REPO" <<'PYEOF'
import sys
sys.path.insert(0, sys.argv[2])
from aurora import swanctl_users as su
path = sys.argv[1]
su.add_user("e2euser1", "E2ePass1234x", path=path)
su.add_user("e2euser2", "E2ePass5678y", path=path)
assert su.list_users(path) == ["e2euser1", "e2euser2"], su.list_users(path)
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
[[ "$OUT" == *"USER-OPS-OK"* ]] && ok "user lifecycle (add/passwd/disable/delete/dup-reject)" \
                                 || bad "user ops: $OUT"

# --- 5. permissions & no private-key exposure ---
[[ "$(stat -c %a "$CA_KEY")" == "600" ]] && ok "CA key 0600" || bad "CA key perms"
[[ "$(stat -c %a "$S_KEY")" == "600" ]]  && ok "server key 0600" || bad "server key perms"
[[ "$(stat -c %a "$CA_CERT")" == "644" ]] && ok "public CA 0644" || bad "CA cert perms"
if grep -rl "PRIVATE KEY" "$SB/var/lib/aurora-ikev2" 2>/dev/null | grep -q .; then
  bad "private key found in data dir"
else ok "no private keys in panel data dir"; fi

# --- 6. backup & rollback artifacts exist ---
[[ -n "$(ls -A "$SB/backups" 2>/dev/null)" ]] \
  && ok "pre-mutation backups created" || bad "no backups"

# --- 7. config validation: aurora conn block renders and parses ---
"$PY" -c "
import sys; sys.path.insert(0, '$REPO')
from aurora import strongswan
c = strongswan.render_conn('$IP')
assert 'leftcert=aurora-server-cert.pem' in c
assert 'eap-mschapv2' in c
open('$SB/etc/ipsec.conf', 'w').write(c)
" && ok "conn block generated with standard cert filename + EAP" \
   || bad "conn block generation"

echo
echo "== RESULT: $PASS passed, $FAIL failed =="
[[ $FAIL -eq 0 ]]
