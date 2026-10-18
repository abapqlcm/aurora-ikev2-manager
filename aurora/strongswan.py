"""Aurora IKEv2 Manager — strongSwan configuration management (classic stack).

Design notes
------------
- Targets the classic `/etc/ipsec.*` layout (strongswan-starter).
- The panel never reads or writes the strongSwan secrets files. Credential operations go
  through the root secrets helper (aurora/secrets_client.py), which validates,
  backs up, writes atomically, reloads and rolls back on failure.
- Passwords are never logged or returned; only names and states are listed.
"""
from __future__ import annotations

import re

from . import secrets_client
from .environment import run, run_ok
from .privileged import effective_cmd

IPSEC_CONF = "/etc/ipsec.conf"
CONN_NAME = "aurora-ikev2"
SWANCTL_CONF = "/etc/swanctl/swanctl.conf"
POOL_NAME = "aurora-pool"
VPN_POOL = "10.99.0.0/24"


def stack_layout(
        swanctl_conf: str = "/etc/swanctl/swanctl.conf",
        ipsec_conf: str = IPSEC_CONF) -> str:
    """'classic' | 'swanctl' | 'none' — reliable backend detection.

    swanctl wins only when swanctl.conf exists; classic when ipsec.conf exists.
    An env override (AURORA_FORCE_BACKEND) exists for testing.
    """
    import os
    forced = os.environ.get("AURORA_FORCE_BACKEND")
    if forced in ("classic", "swanctl"):
        return forced
    if os.path.exists(swanctl_conf):
        return "swanctl"
    if os.path.exists(ipsec_conf):
        return "classic"
    return "none"


# ------------------------------------------------- credentials (via helper)

def list_entries() -> list[tuple[str, str]]:
    """[(username, 'enabled'|'disabled')] — names and states only."""
    return [(e["name"], e["state"]) for e in secrets_client.call("classic", "list")]


def list_users() -> list[str]:
    return [name for name, _ in list_entries()]


def user_state(username: str) -> str:
    for name, state in list_entries():
        if name == username:
            return state
    return "missing"


def add_user(username: str, password: str) -> None:
    secrets_client.call("classic", "add", username, password)


def delete_user(username: str) -> bool:
    return bool(secrets_client.call("classic", "delete", username))


def set_user_password(username: str, password: str) -> None:
    secrets_client.call("classic", "passwd", username, password)


def disable_user(username: str) -> bool:
    return bool(secrets_client.call("classic", "disable", username))


def enable_user(username: str) -> bool:
    return bool(secrets_client.call("classic", "enable", username))


# ------------------------------------------------------------- ipsec.conf

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
    leftcert=aurora-server-cert.pem
    right=%any
    rightsourceip={pool}
    rightauth=eap-mschapv2
    eap_identity=%any
    rightdns={dns}
    auto=add
# aurora-end {CONN_NAME}
"""


def validate_conf_static(text: str) -> tuple[bool, str]:
    """Non-disruptive static validation of the Aurora block in ipsec.conf.

    Never starts, stops or restarts any daemon. Checks that the managed block
    markers are paired and that the connection block is present exactly once.
    """
    begins = re.findall(rf"^# aurora-begin {re.escape(CONN_NAME)}$", text, re.M)
    ends = re.findall(rf"^# aurora-end {re.escape(CONN_NAME)}$", text, re.M)
    if len(begins) != len(ends):
        return False, "unbalanced aurora-begin/aurora-end markers"
    if len(begins) > 1:
        return False, "aurora block appears more than once"
    if begins and not re.search(rf"^conn {re.escape(CONN_NAME)}$", text, re.M):
        return False, f"missing 'conn {CONN_NAME}' inside managed block"
    return True, "static checks passed (no daemon was contacted)"


# ---------------------------------------------------------- service control

def reload_full() -> None:
    # `ipsec update` re-reads ipsec.conf without restarting charon, so
    # established sessions survive.
    run_ok(effective_cmd(["/usr/sbin/ipsec", "update"]), timeout=15)
    run_ok(effective_cmd(["/usr/sbin/ipsec", "rereadsecrets"]), timeout=15)


def service_active() -> bool:
    for unit in ("strongswan-starter", "strongswan"):
        p = run(["systemctl", "is-active", unit], timeout=10)
        if p.stdout.strip() == "active":
            return True
    return False


def restart_service() -> None:
    run_ok(effective_cmd(["/usr/bin/systemctl", "restart", "strongswan-starter"]), timeout=60)
