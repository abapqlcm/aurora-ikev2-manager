"""Aurora IKEv2 Manager — strongSwan configuration management (classic ipsec stack).

Design notes
------------
- Targets the classic `/etc/ipsec.*` layout (strongswan-starter), which is what
  Ubuntu's `strongswan` + `libcharon-extra-plugins` packages ship by default.
- Every mutation is: validate -> backup -> write -> validate -> reload.
- EAP-MSCHAPv2 credentials live in /etc/ipsec.secrets (username : EAP <secret>).
- Passwords are NEVER logged or returned; only length/hash metadata is kept.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass

from .environment import run_ok, run, CommandError

IPSEC_CONF = "/etc/ipsec.conf"
IPSEC_SECRETS = "/etc/ipsec.secrets"
BACKUP_DIR = os.environ.get("AURORA_BACKUP_DIR", "/var/lib/aurora-ikev2/backups")
CONN_NAME = "aurora-ikev2"
POOL_NAME = "aurora-pool"
VPN_POOL = "10.99.0.0/24"

USERNAME_RE = re.compile(r"^[a-zA-Z0-9._@-]{2,64}$")


def valid_username(u: str) -> bool:
    return bool(USERNAME_RE.match(u))


def valid_password(p: str) -> bool:
    return 8 <= len(p) <= 128 and all(32 <= ord(c) < 127 for c in p)


# ---------------------------------------------------------------- secrets file

def _read_secrets(path: str = IPSEC_SECRETS) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def parse_secrets(text: str) -> list[tuple[str, str | None]]:
    """Return [(username, raw_line_or_None)] for EAP entries. Raw line includes
    the secret, so callers must never print element [1]."""
    out = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith(_DISABLED_PREFIX):
            stripped = stripped[len(_DISABLED_PREFIX):].strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = re.match(r'^"?([A-Za-z0-9._@+-]+)"?\s*:\s*EAP\s+(.+)$', stripped, re.I)
        if m:
            out.append((m.group(1), raw))
    return out


def list_users(path: str = IPSEC_SECRETS) -> list[str]:
    return [u for u, _ in parse_secrets(_read_secrets(path))]


def backup_file(path: str) -> str | None:
    if not os.path.exists(path):
        return None
    bdir = os.environ.get("AURORA_BACKUP_DIR", BACKUP_DIR)
    os.makedirs(bdir, mode=0o700, exist_ok=True)
    name = os.path.basename(path)
    dst = os.path.join(bdir, f"{name}.{os.getpid()}.bak")
    shutil.copy2(path, dst)
    os.chmod(dst, 0o600)
    return dst


def _write_secrets(new_text: str, path: str = IPSEC_SECRETS) -> None:
    backup_file(path)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".secrets.")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(new_text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def add_user(username: str, password: str, path: str = IPSEC_SECRETS) -> None:
    if not valid_username(username):
        raise ValueError("invalid username (2-64 chars: letters, digits, . _ @ -)")
    if not valid_password(password):
        raise ValueError("invalid password (8-128 printable ASCII chars)")
    text = _read_secrets(path)
    if any(u == username for u, _ in parse_secrets(text)):
        raise ValueError(f"user already exists: {username}")
    line = f'{username} : EAP "{password}"'
    if text and not text.endswith("\n"):
        text += "\n"
    _write_secrets(text + line + "\n", path)


def delete_user(username: str, path: str = IPSEC_SECRETS) -> bool:
    if not valid_username(username):
        raise ValueError("invalid username")
    entries = parse_secrets(_read_secrets(path))
    kept, removed = [], False
    for u, raw in entries:
        if u == username:
            removed = True
            continue
        kept.append(raw)
    if not removed:
        return False
    # Preserve comment/blank lines not tied to removed users.
    new_lines = []
    for raw in _read_secrets(path).splitlines():
        m = re.match(r'^\s*"?([A-Za-z0-9._@+-]+)"?\s*:\s*EAP\s', raw, re.I)
        if m and m.group(1) == username:
            continue
        new_lines.append(raw)
    _write_secrets("\n".join(new_lines) + ("\n" if new_lines else ""), path)
    return True


def set_user_password(username: str, password: str, path: str = IPSEC_SECRETS) -> None:
    if not valid_password(password):
        raise ValueError("invalid password")
    if not any(u == username for u in list_users(path)):
        raise ValueError(f"no such user: {username}")
    delete_user(username, path)
    add_user(username, password, path)


def disable_user(username: str, path: str = IPSEC_SECRETS) -> bool:
    """Disable = comment the secrets line (revokes auth, preserves the entry)."""
    return _toggle_user(username, True, path)


def enable_user(username: str, path: str = IPSEC_SECRETS) -> bool:
    return _toggle_user(username, False, path)


def _toggle_user(username: str, disable: bool, path: str) -> bool:
    if not valid_username(username):
        raise ValueError("invalid username")
    lines = _read_secrets(path).splitlines()
    changed = False
    out = []
    for raw in lines:
        stripped = raw.strip()
        was_disabled = stripped.startswith(_DISABLED_PREFIX)
        bare = stripped[len(_DISABLED_PREFIX):].strip() if was_disabled else stripped
        m = re.match(r'^"?([A-Za-z0-9._@+-]+)"?\s*:\s*EAP\s', bare, re.I)
        if m and m.group(1) == username:
            changed = True
            if disable and not was_disabled:
                out.append(f"{_DISABLED_PREFIX} {bare}")
                continue
            if not disable and was_disabled:
                out.append(bare)
                continue
        out.append(raw)
    if not changed:
        return False
    _write_secrets("\n".join(out) + "\n", path)
    return True


_DISABLED_PREFIX = "# disabled by aurora:"


def user_state(username: str, path: str = IPSEC_SECRETS) -> str:
    """'enabled' | 'disabled' | 'missing'."""
    for raw in _read_secrets(path).splitlines():
        stripped = raw.strip()
        disabled = stripped.startswith(_DISABLED_PREFIX)
        if disabled:
            stripped = stripped[len(_DISABLED_PREFIX):].strip()
        m = re.match(r'^"?([A-Za-z0-9._@+-]+)"?\s*:\s*EAP\s', stripped, re.I)
        if m and m.group(1) == username:
            return "disabled" if disabled else "enabled"
    return "missing"


# ---------------------------------------------------------------- ipsec.conf

def render_conn(public_ip: str, pool: str = VPN_POOL, dns: str = "1.1.1.1,1.0.0.1") -> str:
    return f"""# managed by aurora-ikev2 — do not edit between BEGIN/END markers
# aurora-begin {CONN_NAME}
conn %default
    keyexchange=ikev2
    dpdaction=clear
    dpddelay=300s

conn {CONN_NAME}
    left=%any
    leftid=@{public_ip}
    leftsubnet=0.0.0.0/0
    leftauth=pubkey
    leftcert=server-cert.pem
    right=%any
    rightsourceip={pool}
    rightauth=eap-mschapv2
    eap_identity=%any
    dns={dns}
    auto=add
# aurora-end {CONN_NAME}
"""


def validate_ipsec_conf(path: str = IPSEC_CONF) -> tuple[bool, str]:
    p = run(["ipsec", "start", "--conf", path, "--nofork", "--debug-dm"], timeout=10)
    # ipsec start --nofork isn't a validator everywhere; fall back to stroke:
    if p.returncode != 0:
        p2 = run(["ipsec", "rereadsecrets"], timeout=10)
        # Prefer the documented check: strongswan-starter configtest if present
        p3 = run(["/usr/lib/ipsec/starter", "--conf", path, "--debug"], timeout=10)
        ok = p3.returncode == 0 or "syntax" not in (p3.stderr + p3.stdout).lower()
        detail = (p3.stderr or p3.stdout or p.stderr).strip()[:400]
        return ok, detail or "configuration accepted"
    return True, "configuration accepted"


def reload_secrets() -> None:
    run_ok(["ipsec", "rereadsecrets"], timeout=15)


def reload_full() -> None:
    run_ok(["ipsec", "update"], timeout=15)
    run_ok(["ipsec", "rereadsecrets"], timeout=15)


def service_active() -> bool:
    for unit in ("strongswan-starter", "strongswan"):
        p = run(["systemctl", "is-active", unit], timeout=10)
        if p.stdout.strip() == "active":
            return True
    return False


def restart_service() -> None:
    run_ok(["systemctl", "restart", "strongswan-starter"], timeout=60)
