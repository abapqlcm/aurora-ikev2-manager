#!/usr/bin/env bash
# Aurora IKEv2 Manager — installer (fresh / existing / reinstall)
# Usage: sudo ./install.sh [--mode fresh|existing|reinstall] [--public-ip IP]
set -euo pipefail

MODE="fresh"
PUBLIC_IP=""
CONN="aurora-ikev2"
BACKUP_DIR="/var/lib/aurora-ikev2/backups"

log()  { printf '\033[1;36m[aurora]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[aurora]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[aurora]\033[0m %s\n' "$*" >&2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --public-ip) PUBLIC_IP="$2"; shift 2 ;;
    *) err "unknown option: $1"; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then err "run as root (sudo)"; exit 1; fi

# ---------- environment detection ----------
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
else
  err "cannot read /etc/os-release"; exit 1
fi
if [[ "${ID:-}" != "ubuntu" ]]; then err "unsupported distribution: ${ID:-unknown}"; exit 1; fi
MAJOR="${VERSION_ID%%.*}"
if (( MAJOR < 20 )); then err "Ubuntu ${VERSION_ID} too old (20.04+)"; exit 1; fi

IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
if [[ -z "$PUBLIC_IP" ]]; then
  PUBLIC_IP=$(curl -4 -fs --max-time 8 https://api.ipify.org 2>/dev/null || echo "")
fi
if [[ -z "$PUBLIC_IP" ]]; then
  err "could not determine public IP — pass --public-ip"
  exit 1
fi
log "mode=$MODE  iface=$IFACE  public-ip=$PUBLIC_IP  ubuntu=${VERSION_ID}"

backup() {
  local f="$1"
  if [[ -f "$f" ]]; then
    mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
    cp -a "$f" "$BACKUP_DIR/$(basename "$f").$(date +%s).bak"
    chmod 600 "$BACKUP_DIR"/$(basename "$f").*.bak 2>/dev/null || true
  fi
}

# ---------- EXISTING SERVER INSPECTION ----------
if [[ "$MODE" == "existing" ]]; then
  log "inspecting existing strongSwan installation..."
  HAS_IPSEC_CONF=false; HAS_SWANCTL=false
  [[ -f /etc/ipsec.conf ]] && HAS_IPSEC_CONF=true
  [[ -f /etc/swanctl/swanctl.conf ]] && HAS_SWANCTL=true
  if ! $HAS_IPSEC_CONF && ! $HAS_SWANCTL; then
    err "no strongSwan configuration found — use --mode fresh"
    exit 1
  fi
  if $HAS_SWANCTL; then
    err "existing install uses swanctl (vici) layout; Aurora panel supports the classic"
    err "ipsec.secrets layout. Safe co-existence is not guaranteed — stopping."
    exit 1
  fi
  if ! grep -q "eap-mschapv2" /etc/ipsec.conf; then
    warn "existing conn does not use EAP-MSCHAPv2; Aurora user management"
    warn "only manages EAP users. Panel will be installed read-only for users."
  fi
  log "existing installation looks compatible; installing panel only."
  MODE="panel-only"
fi

# ---------- REINSTALL (explicit, destructive, confirmed) ----------
if [[ "$MODE" == "reinstall" ]]; then
  warn "REINSTALL will REPLACE /etc/ipsec.conf and /etc/ipsec.secrets."
  warn "Existing users and certificates will be backed up, then removed."
  read -r -p "Type REINSTALL to continue: " ANSWER
  [[ "$ANSWER" == "REINSTALL" ]] || { err "aborted"; exit 1; }
fi

backup /etc/ipsec.conf
backup /etc/ipsec.secrets

# ---------- package installation ----------
log "installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq strongswan strongswan-pki libcharon-extra-plugins \
  libstrongswan-extra-plugins python3-venv python3-pip curl >/dev/null

# ---------- certificates ----------
if [[ ! -f /etc/ipsec.d/cacerts/ca-cert.pem ]]; then
  log "generating CA and server certificate..."
  mkdir -p /etc/ipsec.d/{private,cacerts,certs}
  ipsec pki --gen --type rsa --size 4096 --outform pem > /etc/ipsec.d/private/ca-key.pem
  chmod 600 /etc/ipsec.d/private/ca-key.pem
  ipsec pki --self --ca --lifetime 3650 --in /etc/ipsec.d/private/ca-key.pem \
    --type rsa --dn "CN=Aurora VPN CA" --outform pem > /etc/ipsec.d/cacerts/ca-cert.pem
  ipsec pki --gen --type rsa --size 2048 --outform pem > /etc/ipsec.d/private/server-key.pem
  chmod 600 /etc/ipsec.d/private/server-key.pem
  ipsec pki --pub --in /etc/ipsec.d/private/server-key.pem --type rsa \
    --san "$PUBLIC_IP" --san "@$PUBLIC_IP" \
    --flag serverAuth --lifetime 1200 \
    --cacert /etc/ipsec.d/cacerts/ca-cert.pem \
    --dn "CN=$PUBLIC_IP" --outform pem > /etc/ipsec.d/certs/server-cert.pem
else
  log "CA already exists — keeping it."
fi

# ---------- ipsec.conf ----------
if [[ "$MODE" != "panel-only" ]]; then
  if grep -q "# aurora-begin $CONN" /etc/ipsec.conf 2>/dev/null; then
    log "conn block already present — skipping (idempotent)."
  else
    log "writing $CONN conn block..."
    cat >> /etc/ipsec.conf <<EOF

# aurora-begin $CONN
conn %default
    keyexchange=ikev2
    dpdaction=clear
    dpddelay=300s

conn $CONN
    left=%any
    leftid=@${PUBLIC_IP}
    leftsubnet=0.0.0.0/0
    leftauth=pubkey
    leftcert=server-cert.pem
    right=%any
    rightsourceip=10.99.0.0/24
    rightauth=eap-mschapv2
    eap_identity=%any
    dns=1.1.1.1,1.0.0.1
    auto=add
# aurora-end $CONN
EOF
  fi
fi

# ---------- sysctl + NAT (idempotent) ----------
if ! sysctl -n net.ipv4.ip_forward | grep -q '^1$'; then
  log "enabling IPv4 forwarding..."
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
  ufw route allow in on "$IFACE" 2>/dev/null || true
  ufw allow 500/udp >/dev/null 2>&1 || true
  ufw allow 4500/udp >/dev/null 2>&1 || true
fi
if ! iptables -t nat -C POSTROUTING -s 10.99.0.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null; then
  log "adding NAT rule for 10.99.0.0/24 via $IFACE"
  iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o "$IFACE" -j MASQUERADE
fi

# ---------- validate & start ----------
ipsec restart >/dev/null 2>&1 || true
sleep 3
if ! ipsec statusall 2>/dev/null | grep -q "$CONN"; then
  err "conn $CONN did not load — check /etc/ipsec.conf (backup in $BACKUP_DIR)"
  exit 1
fi
log "strongSwan loaded conn '$CONN'."

# ---------- web panel ----------
log "installing web panel..."
INSTALL_DIR="/opt/aurora-ikev2"
mkdir -p "$INSTALL_DIR"
cp -r aurora templates aurora_wsgi.py requirements.txt "$INSTALL_DIR/" 2>/dev/null || true
cd "$INSTALL_DIR"
python3 -m venv venv
./venv/bin/pip -q install flask >/dev/null

DB=/var/lib/aurora-ikev2/aurora.db
mkdir -p /var/lib/aurora-ikev2 && chmod 700 /var/lib/aurora-ikev2
if [[ ! -f "$DB" ]]; then
  ADMIN_USER="admin"
  ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
  AURORA_DB="$DB" ./venv/bin/python - <<PYEOF
from aurora.app import hash_password
import sqlite3, os
db = sqlite3.connect("$DB")
db.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 0)")
db.execute("INSERT INTO admin (username, password_hash) VALUES (?,?)", ("$ADMIN_USER", "${PYTHONHASHSEED:+}" and __import__('os').environ.get('X','') or ""))
db.commit()
PYEOF
  # hash generated in a separate process to keep the password out of argv:
  HASH=$(AURORA_PW="$ADMIN_PASS" ./venv/bin/python -c "import os; from aurora.app import hash_password; print(hash_password(os.environ['AURORA_PW']))")
  sqlite3 "$DB" "UPDATE admin SET password_hash='$HASH' WHERE username='admin';" 2>/dev/null || \
    ./venv/bin/python -c "import sqlite3; db=sqlite3.connect('$DB'); db.execute(\"UPDATE admin SET password_hash=? WHERE username='admin'\", ('$HASH',)); db.commit()"
  log "admin user: $ADMIN_USER / $ADMIN_PASS   (CHANGE THIS AFTER FIRST LOGIN)"
fi

# ---------- systemd service ----------
cat > /etc/systemd/system/aurora-panel.service <<EOF
[Unit]
Description=Aurora IKEv2 Manager panel
After=network.target strongswan-starter.service

[Service]
User=root
WorkingDirectory=$INSTALL_DIR
Environment=AURORA_DB=$DB
Environment=AURORA_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
ExecStart=$INSTALL_DIR/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:8080 aurora_wsgi:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
./venv/bin/pip -q install gunicorn >/dev/null
systemctl daemon-reload
systemctl enable --now aurora-panel.service

log "done."
log "panel:  http://127.0.0.1:8080  (put behind nginx+TLS for remote access)"
log "CA cert for clients: /etc/ipsec.d/cacerts/ca-cert.pem"
log "rollback: restore files from $BACKUP_DIR"
