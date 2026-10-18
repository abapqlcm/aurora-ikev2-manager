"""Privilege separation for Aurora IKEv2 Manager.

The web panel runs as the unprivileged `aurora` user. Only a narrow,
explicitly whitelisted set of commands may be elevated, via a sudoers rule
that matches EXACT command lines (no wildcards on arguments beyond the
whitelisted ones). Nothing else runs as root, ever.

Whitelisted elevated commands (see install.sh sudoers block):
    /usr/sbin/ipsec rereadsecrets
    /usr/sbin/ipsec update
    /usr/sbin/ipsec restart
    /usr/sbin/ipsec statusall
    /usr/bin/systemctl restart strongswan-starter
    /usr/sbin/swanctl --load-secrets
    /usr/bin/systemctl restart strongswan-starter
    /usr/bin/systemctl reload strongswan-starter
"""
from __future__ import annotations

import os

from .environment import CommandError, run

# Commands the unprivileged panel may elevate through sudo (exact argv).
SUDO_WHITELIST: list[list[str]] = [
    ["/usr/sbin/ipsec", "rereadsecrets"],
    ["/usr/sbin/ipsec", "update"],
    ["/usr/sbin/ipsec", "restart"],
    ["/usr/sbin/ipsec", "statusall"],
    ["/usr/sbin/swanctl", "--load-secrets"],
    ["/usr/bin/systemctl", "restart", "strongswan-starter"],
    ["/usr/bin/systemctl", "reload", "strongswan-starter"],
]


def _resolve(name: str) -> str:
    """Resolve a bare command name to its absolute path via PATH."""
    if name.startswith("/"):
        return name
    for d in os.environ.get("PATH", "/usr/sbin:/usr/bin:/sbin:/bin").split(":"):
        p = os.path.join(d, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return name


def effective_cmd(cmd: list[str]) -> list[str]:
    """Return the argv that should actually be executed.

    - running as root: execute directly
    - unprivileged with AURORA_USE_SUDO=1: prefix `sudo -n` (whitelisted in
      sudoers by exact argv; sudo itself rejects anything not whitelisted)
    - unprivileged without sudo mode: refuse to run privileged commands
      rather than failing silently.
    """
    if os.geteuid() == 0:
        return cmd
    if os.environ.get("AURORA_USE_SUDO") == "1":
        if not is_whitelisted(cmd):
            raise CommandError(
                f"command not in privilege whitelist: {' '.join(cmd)}"
            )
        return ["sudo", "-n", *cmd]
    raise CommandError(
        f"insufficient privileges for {' '.join(cmd)}; "
        "the panel must run as root, or with AURORA_USE_SUDO=1 and the "
        "aurora sudoers whitelist installed"
    )


def is_whitelisted(cmd: list[str]) -> bool:
    """True if the exact absolute-path argv is in SUDO_WHITELIST."""
    abs_cmd = [_resolve(c) for c in cmd]
    return any(abs_cmd[: len(w)] == w for w in SUDO_WHITELIST)
