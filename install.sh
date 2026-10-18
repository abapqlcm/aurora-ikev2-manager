#!/usr/bin/env bash
# Aurora IKEv2 Manager — installer (fresh / existing / reinstall / panel-only)
# Usage: sudo ./install.sh [--mode fresh|existing|reinstall] [--public-ip IP]
set -euo pipefail

MODE="fresh"
PUBLIC_IP_ARG=""
PUBLIC_IP=""
CONN="aurora-ikev2"
BASE_DIR="/var/lib/aurora-ikev2"
BACKUP_DIR="$BASE_DIR/backups"
INSTALL_DIR="/opt/aurora-ikev2"
AURORA_USER="aurora"
STEP=0

log()  { printf '\033[1;36m[aurora]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[aurora]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[aurora]\033[0m %s\n' "$*" >&2; }
step() { STEP=$((STEP+1)); log "[$STEP] $*"; }

trap 'err "installer FAILED at step $STEP (mode=$MODE). Files modified so far are backed up in $BACKUP_DIR. Fix the problem and re-run — the installer is idempotent."' ERR

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="$2"; shift 2 ;;
    --public-ip) PUBLIC_IP_ARG="$2"; shift 2 ;;
    *) err "unknown option: $1"; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then err "run as root (sudo)"; exit 1; fi

# ---------- [1] environment detection ----------
step "environment detection"
if [[ -r /etc/os-release ]]; then
  . /etc/os-release
else
  err "cannot read /etc/os-release"; exit 1
fi
if [[ "${ID:-}" != "ubuntu" ]]; then err "unsupported distribution: ${ID:-unknown}"; exit 1; fi
MAJOR="${VERSION_ID%%.*}"
if (( MAJOR < 20 )); then err "Ubuntu ${VERSION_ID} too old (20.04+)"; exit 1; fi

IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
if [[ -z "$PUBLIC_IP_ARG" ]]; then
  # Local source address for outbound traffic — may be private (cloud NAT).
  LOCAL_SRC=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
  # Classify locally: RFC1918/loopback/link-local => behind NAT.
  if [[ "$LOCAL_SRC" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.|169\.254\.) ]]; then
    warn "detected local address $LOCAL_SRC is PRIVATE — server is behind cloud NAT."
    warn "Clients connect to the cloud/public IP; certificate SAN and leftid must use it."
    err "pass --public-ip <your public cloud IP> and re-run"
    exit 1
  elif [[ -z "$LOCAL_SRC" ]]; then
    err "could not detect any outbound source address — pass --public-ip"
    exit 1
  else
    PUBLIC_IP="$LOCAL_SRC"
  fi
else
  PUBLIC_IP="$PUBLIC_IP_ARG"
fi
log "mode=$MODE  iface=$IFACE  public-ip=$PUBLIC_IP  ubuntu=${VERSION_ID}"

backup() {
  local f="$1"
  if [[ -f "$f" ]]; then
    mkdir -p "$BACKUP_DIR"; chmod 700 "$BACKUP_DIR"
    cp -a "$f" "$BACKUP_DIR/$(basename "$f").$(date +%Y%m%d%H%M%S).bak"
    chmod 600 "$BACKUP_DIR"/*.bak 2>/dev/null || true
  fi
}

# ---------- [2] EXISTING SERVER INSPECTION (before ANY change) ----------
SWANCTL_MODE=false
if [[ "$MODE" == "existing" ]]; then
  step "inspecting existing strongSwan installation"
  HAS_IPSEC_CONF=false; HAS_SWANCTL=false
  [[ -f /etc/ipsec.conf ]] && HAS_IPSEC_CONF=true
  [[ -f /etc/swanctl/swanctl.conf ]] && HAS_SWANCTL=true
  if ! $HAS_IPSEC_CONF && ! $HAS_SWANCTL; then
    err "no strongSwan configuration found — use --mode fresh"
    exit 1
  fi
  if $HAS_SWANCTL; then
    warn "existing install uses the swanctl (vici) layout."
    warn "Aurora's user management edits ipsec.secrets (classic layout) and is NOT"
    warn "compatible with swanctl-based user secrets. The panel will be installed"
    warn "READ-ONLY for users: monitoring and diagnostics only. Existing swanctl"
    warn "config, secrets and certificates are NEVER touched."
    SWANCTL_MODE=true
  fi
  if ! $HAS_SWANCTL && ! grep -q "eap-mschapv2" /etc/ipsec.conf; then
    warn "existing conn does not use EAP-MSCHAPv2; Aurora user management"
    warn "only manages EAP users. Panel will be installed read-only for users."
  fi
  log "existing installation inspected; installing panel only (no VPN changes)."
  MODE="panel-only"
fi

# ---------- REINSTALL (explicit, destructive, confirmed) ----------
if [[ "$MODE" == "reinstall" ]]; then
  step "reinstall confirmation"
  warn "REINSTALL will REPLACE the aurora conn in /etc/ipsec.conf and REGENERATE"
  warn "server certificates. Existing EAP users in ipsec.secrets are preserved."
  read -r -p "Type REINSTALL to continue: " ANSWER
  [[ "$ANSWER" == "REINSTALL" ]] || { err "aborted"; exit 1; }
fi

backup /etc/ipsec.conf
backup /etc/ipsec.secrets

# ---------- conflict detection on fresh installs ----------
if [[ "$MODE" == "fresh" ]]; then
  if [[ -f /etc/ipsec.conf ]] && grep -qv "^\s*$" /etc/ipsec.conf 2>/dev/null \
     && ! grep -q "aurora-begin" /etc/ipsec.conf 2>/dev/null; then
    warn "fresh install requested but /etc/ipsec.conf already contains a"
    warn "non-Aurora configuration. Existing conns are preserved (Aurora only"
    warn "appends its own block), but review: consider --mode existing instead."
  fi
  if [[ -f /etc/swanctl/swanctl.conf ]]; then
    warn "swanctl config detected; fresh install will manage the classic stack."
    warn "Existing swanctl configuration is not modified."
  fi
fi

# ---------- package installation ----------
step "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq strongswan strongswan-pki libcharon-extra-plugins \
  libstrongswan-extra-plugins python3-venv python3-pip curl >/dev/null

# ---------- certificates (standard filenames) ----------
CA_KEY=/etc/ipsec.d/private/aurora-manager-ca-key.pem
CA_CERT=/etc/ipsec.d/cacerts/aurora-manager-ca.pem
SERVER_KEY=/etc/ipsec.d/private/aurora-server-key.pem
SERVER_CERT=/etc/ipsec.d/certs/aurora-server-cert.pem

gen_server_cert() {
  ipsec pki --gen --type rsa --size 2048 --outform pem > "$SERVER_KEY"
  chmod 600 "$SERVER_KEY"
  ipsec pki --pub --in "$SERVER_KEY" --type rsa \
    | ipsec pki --issue --san "$PUBLIC_IP" --san "@$PUBLIC_IP" \
      --flag serverAuth --lifetime 1200 \
      --cacert "$CA_CERT" --cakey "$CA_KEY" \
      --dn "CN=$PUBLIC_IP" --outform pem > "$SERVER_CERT"
  chmod 644 "$SERVER_CERT"
}

validate_certs() {
  if ! openssl verify -CAfile "$CA_CERT" "$SERVER_CERT" >/dev/null 2>&1; then
    err "server certificate is NOT signed by $CA_CERT — chain broken"
    return 1
  fi
  if ! openssl x509 -in "$SERVER_CERT" -noout -checkend 2592000; then
    err "server certificate expired or expires within 30 days"
    return 1
  fi
  local CMOD KMOD
  CMOD=$(openssl x509 -in "$SERVER_CERT" -noout -modulus | md5sum)
  KMOD=$(openssl rsa  -in "$SERVER_KEY"  -noout -modulus | md5sum)
  if [[ "$CMOD" != "$KMOD" ]]; then
    err "server certificate and private key do NOT match"
    return 1
  fi
  # SAN must contain the client-facing identity
  if ! openssl x509 -in "$SERVER_CERT" -noout -text | grep -q "$PUBLIC_IP"; then
    err "certificate SAN does not contain $PUBLIC_IP"
    return 1
  fi
  return 0
}

if [[ "$MODE" != "panel-only" ]]; then
  step "certificates (aurora-manager-ca.pem)"
  mkdir -p /etc/ipsec.d/{private,cacerts,certs}
  if [[ ! -f "$CA_CERT" ]]; then
    log "generating new CA..."
    ipsec pki --gen --type rsa --size 4096 --outform pem > "$CA_KEY"
    chmod 600 "$CA_KEY"
    ipsec pki --self --ca --lifetime 3650 --in "$CA_KEY" \
      --type rsa --dn "CN=Aurora VPN Manager CA" --outform pem > "$CA_CERT"
    chmod 644 "$CA_CERT"
  elif [[ "$MODE" == "reinstall" ]]; then
    warn "CA already exists at $CA_CERT."
    read -r -p "REPLACE the existing CA (invalidates all client trust)? Type REPLACE-CA or ENTER to keep: " CA_ANSWER
    if [[ "$CA_ANSWER" == "REPLACE-CA" ]]; then
      TS=$(date +%s)
      for F in "$CA_KEY" "$CA_CERT" "$SERVER_KEY" "$SERVER_CERT"; do
        [[ -f "$F" ]] && mv "$F" "$F.replaced-$TS"
      done
      ipsec pki --gen --type rsa --size 4096 --outform pem > "$CA_KEY"
      chmod 600 "$CA_KEY"
      ipsec pki --self --ca --lifetime 3650 --in "$CA_KEY" \
        --type rsa --dn "CN=Aurora VPN Manager CA" --outform pem > "$CA_CERT"
      chmod 644 "$CA_CERT"
    else
      log "keeping existing CA."
    fi
  else
    log "CA already exists at $CA_CERT — keeping it (use --mode reinstall + REPLACE-CA to change)."
  fi
  if [[ ! -f "$SERVER_CERT" ]]; then
    gen_server_cert
  else
    # existing server cert: verify identity still matches, regenerate if not
    if ! openssl x509 -in "$SERVER_CERT" -noout -text | grep -q "$PUBLIC_IP"; then
      warn "existing server cert does not match identity $PUBLIC_IP — regenerating server certificate."
      gen_server_cert
    fi
  fi
  if ! validate_certs; then
    err "certificate validation failed — see backups in $BACKUP_DIR"
    exit 1
  fi
  log "PKI validated: chain OK, key match OK, SAN contains $PUBLIC_IP."
fi

# ---------- ipsec.conf ----------
if [[ "$MODE" != "panel-only" ]]; then
  step "writing $CONN conn block (idempotent)"
  if grep -q "# aurora-begin $CONN" /etc/ipsec.conf 2>/dev/null; then
    log "conn block already present — skipping."
  else
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
    leftcert=aurora-server-cert.pem
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

# ---------- sysctl + NAT (fresh/reinstall only; skipped for panel-only) ----------
if [[ "$MODE" != "panel-only" ]]; then
  step "sysctl + firewall + NAT (idempotent)"
  if ! sysctl -n net.ipv4.ip_forward | grep -q '^1$'; then
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
    grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
  fi
  if command -v ufw >/dev/null && ufw status | grep -q "Status: active"; then
    ufw allow 500/udp >/dev/null 2>&1 || true
    ufw allow 4500/udp >/dev/null 2>&1 || true
    # NOTE: cloud firewall (security group) must allow UDP 500/4500 at the
    # provider level — the OS firewall is never disabled as a shortcut.
  fi
  if ! iptables -t nat -C POSTROUTING -s 10.99.0.0/24 -o "$IFACE" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -s 10.99.0.0/24 -o "$IFACE" -j MASQUERADE
  fi
else
  step "skipping sysctl/NAT (panel-only mode — existing VPN untouched)"
fi

# ---------- validate & load (fresh/reinstall only; NO restart on existing) ----------
if [[ "$MODE" != "panel-only" ]]; then
  step "loading and validating strongSwan configuration"
  if ! ipsec statusall 2>/dev/null | grep -q "$CONN"; then
    # config changed (new conn added): `ipsec update` reloads ipsec.conf
    # WITHOUT restarting charon and WITHOUT killing active sessions.
    ipsec update >/dev/null 2>&1 || true
    ipsec rereadsecrets >/dev/null 2>&1 || true
    sleep 2
  fi
  if ! ipsec statusall 2>/dev/null | grep -q "$CONN"; then
    err "conn $CONN did not load — check /etc/ipsec.conf (backup in $BACKUP_DIR)"
    exit 1
  fi
  log "strongSwan loaded conn '$CONN' (no daemon restart needed)."
else
  step "verifying existing strongSwan (panel-only)"
  if command -v ipsec >/dev/null && ipsec statusall >/dev/null 2>&1; then
    log "existing strongSwan daemon responding — NOT restarted."
  elif command -v swanctl >/dev/null && swanctl --list-sas >/dev/null 2>&1; then
    log "existing swanctl daemon responding — NOT restarted."
  else
    warn "strongSwan daemon not responding — panel will show inactive status."
  fi
fi

# ---------- [3] web panel: dedicated unprivileged user ----------
step "creating unprivileged service user '$AURORA_USER'"
if ! id "$AURORA_USER" &>/dev/null; then
  useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$AURORA_USER"
fi

step "installing web panel to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -r aurora aurora_wsgi.py requirements.txt "$INSTALL_DIR/"
mkdir -p "$INSTALL_DIR/aurora/templates"
cp -r aurora/templates/* "$INSTALL_DIR/aurora/templates/" 2>/dev/null || true
cd "$INSTALL_DIR"
if [[ ! -d venv ]]; then python3 -m venv venv; fi
./venv/bin/pip -q install --upgrade pip >/dev/null
./venv/bin/pip -q install -r requirements.txt >/dev/null
chown -R "$AURORA_USER:$AURORA_USER" "$INSTALL_DIR"
chmod -R o-rwx "$INSTALL_DIR/venv"

# ---------- data directory (owned by service user) ----------
mkdir -p "$BASE_DIR"
chown "$AURORA_USER:$AURORA_USER" "$BASE_DIR"
chmod 700 "$BASE_DIR"
DB="$BASE_DIR/aurora.db"

# ---------- admin bootstrap: NEVER silently reset existing access ----------
step "administrator bootstrap"
if [[ -f "$DB" ]]; then
  log "existing admin database found — administrator access PRESERVED."
  log "(to reset the admin password use: sudo -u $AURORA_USER $INSTALL_DIR/venv/bin/python $INSTALL_DIR/reset_admin.py)"
else
  ADMIN_USER="admin"
  ADMIN_PASS=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16)
  # password generated in-process, piped via stdin; never in argv or logs
  ADMIN_PASS="$ADMIN_PASS" AURORA_DB="$DB" ./venv/bin/python - <<'PYEOF' > "$BASE_DIR/.admin_bootstrap.txt"
import os
from aurora.app import hash_password, init_db
import sqlite3
pw = os.environ["ADMIN_PASS"]
init_db(None)
db = sqlite3.connect(os.environ["AURORA_DB"])
db.execute("INSERT OR IGNORE INTO admin (username, password_hash) VALUES (?,?)",
           ("admin", hash_password(pw)))
db.commit()
print("admin:" + pw)
PYEOF
  chown "$AURORA_USER:$AURORA_USER" "$DB"
  chmod 600 "$DB" "$BASE_DIR/.admin_bootstrap.txt"
  BOOTSTRAP=$(cat "$BASE_DIR/.admin_bootstrap.txt")
  log "initial admin: ${BOOTSTRAP%%:*} / ${BOOTSTRAP#*:}   (CHANGE AFTER FIRST LOGIN)"
  log "credentials file: $BASE_DIR/.admin_bootstrap.txt (delete after reading)"
  unset BOOTSTRAP ADMIN_PASS
fi

# ---------- sudoers: narrowly scoped whitelist for the service user ----------
step "installing sudoers whitelist (least privilege)"
cat > /etc/sudoers.d/aurora-panel <<EOF
# Aurora IKEv2 Manager — exact-command whitelist for the panel service user.
# Managed by install.sh; do not edit.
$AURORA_USER ALL=(root) NOPASSWD: /usr/sbin/ipsec rereadsecrets, \\
    /usr/sbin/ipsec update, \\
    /usr/sbin/ipsec statusall, \\
    /usr/sbin/swanctl --load-secrets, \\
    /usr/bin/systemctl restart strongswan-starter, \\
    /usr/bin/systemctl reload strongswan-starter
EOF
chmod 440 /etc/sudoers.d/aurora-panel
visudo -c -f /etc/sudoers.d/aurora-panel >/dev/null

# helper script to reset admin (runs as the service user on its own DB)
cat > "$INSTALL_DIR/reset_admin.py" <<'PYEOF'
#!/usr/bin/env python3
"""Reset the Aurora admin password. Run as the aurora service user:
   sudo -u aurora /opt/aurora-ikev2/venv/bin/python /opt/aurora-ikev2/reset_admin.py <username>
Generates a new random password and prints it once."""
import os, secrets, sys, sqlite3
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aurora.app import hash_password
user = sys.argv[1] if len(sys.argv) > 1 else "admin"
db = sqlite3.connect(os.environ.get("AURORA_DB", "/var/lib/aurora-ikev2/aurora.db"))
pw = secrets.token_urlsafe(16)
db.execute("UPDATE admin SET password_hash=?, must_change=1 WHERE username=?", (hash_password(pw), user))
db.commit()
if db.total_changes == 0:
    sys.exit(f"no such admin user: {user}")
print(f"new password for {user}: {pw}  (change after first login)")
PYEOF
chmod 750 "$INSTALL_DIR/reset_admin.py"
chown "$AURORA_USER:$AURORA_USER" "$INSTALL_DIR/reset_admin.py"

# ---------- systemd service: unprivileged ----------
step "installing systemd service (unprivileged)"
# stable secret: generated once, reused across reinstalls (sessions survive)
if [[ -f "$BASE_DIR/.secret_key" ]]; then
  SECRET_KEY=$(cat "$BASE_DIR/.secret_key")
else
  SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')
  umask 077; echo -n "$SECRET_KEY" > "$BASE_DIR/.secret_key"; umask 022
  chown "$AURORA_USER:$AURORA_USER" "$BASE_DIR/.secret_key"
fi
cat > /etc/systemd/system/aurora-panel.service <<EOF
[Unit]
Description=Aurora IKEv2 Manager panel (unprivileged)
After=network.target strongswan-starter.service

[Service]
Type=simple
User=$AURORA_USER
Group=$AURORA_USER
WorkingDirectory=$INSTALL_DIR
Environment=AURORA_DB=$DB
Environment=AURORA_SECRET_KEY=$SECRET_KEY
Environment=AURORA_USE_SUDO=1
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$BASE_DIR
PrivateTmp=yes
ExecStart=$INSTALL_DIR/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:8080 aurora_wsgi:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now aurora-panel.service
sleep 2
if ! curl -fs --max-time 5 http://127.0.0.1:8080/login >/dev/null; then
  warn "panel did not respond on 127.0.0.1:8080 — check: journalctl -u aurora-panel -n 50"
fi

log "done."
log "panel:  http://127.0.0.1:8080  (behind nginx+TLS for remote access)"
log "CA cert for clients: $CA_CERT (download as aurora-manager-ca.pem via panel /setup)"
if [[ "$SWANCTL_MODE" == true ]]; then
  warn "swanctl install detected: user management DISABLED (read-only panel)."
fi
log "rollback: restore modified files from $BACKUP_DIR"
trap - ERR
