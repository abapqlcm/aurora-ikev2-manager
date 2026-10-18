"""Aurora IKEv2 Manager — user management for swanctl (vici) deployments.

- Credentials are changed only through the root secrets helper (see
  aurora/secrets_helper.py), which resolves the swanctl secrets file itself and
  applies changes with `swanctl --load-secrets`. The daemon is never restarted
  and established SAs are not touched.
- swanctl.conf (connections/pools/auth rounds) is NEVER rewritten by the panel.
  If EAP is not already configured, the panel refuses user management.

Active-session limitation: deleting or disabling a user does NOT terminate an
established IKE SA. Authentication is re-checked only at (re)authentication.
"""
from __future__ import annotations

import re

from . import secrets_client

SWANCTL_CONF = "/etc/swanctl/swanctl.conf"


def check_eap_configured(swanctl_conf: str = SWANCTL_CONF) -> tuple[bool, str]:
    """Verify that the existing swanctl.conf has EAP auth. Returns (ok, detail)."""
    try:
        with open(swanctl_conf, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except FileNotFoundError:
        return False, f"{swanctl_conf} not found"
    except OSError as exc:
        return False, f"cannot read {swanctl_conf}: {exc.strerror or exc}"
    clean = re.sub(r"#.*$", "", text, flags=re.M)
    if re.search(r"auth\s*=\s*eap[-\w]*", clean, re.I):
        return True, "EAP authentication present in swanctl.conf"
    return False, ("no EAP auth round found in swanctl.conf — add "
                   "remote { auth = eap-mschapv2; eap_id = %any; } to your "
                   "connection first; Aurora does not edit swanctl.conf")


def list_entries() -> list[tuple[str, str]]:
    return [(e["name"], e["state"]) for e in secrets_client.call("swanctl", "list")]


def list_users() -> list[str]:
    return [name for name, _ in list_entries()]


def user_state(username: str) -> str:
    for name, state in list_entries():
        if name == username:
            return state
    return "missing"


def add_user(username: str, password: str) -> None:
    secrets_client.call("swanctl", "add", username, password)


def delete_user(username: str) -> bool:
    return bool(secrets_client.call("swanctl", "delete", username))


def set_user_password(username: str, password: str) -> None:
    secrets_client.call("swanctl", "passwd", username, password)


def disable_user(username: str) -> bool:
    return bool(secrets_client.call("swanctl", "disable", username))


def enable_user(username: str) -> bool:
    return bool(secrets_client.call("swanctl", "enable", username))
