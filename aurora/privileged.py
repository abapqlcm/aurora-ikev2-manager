"""Privilege separation for Aurora IKEv2 Manager.

The web panel runs as the unprivileged `aurora` user. The ONLY elevated
operations are the exact argv lists in SUDO_WHITELIST. install.sh generates
/etc/sudoers.d/aurora-panel from this module (sudoers_text), so the Python
whitelist and the sudo policy cannot drift apart. Tests verify both.

Matching is EXACT: the full argv must equal a whitelist entry. Extra
arguments, alternate paths and unlisted subcommands are rejected here, before
sudo is invoked.
"""
from __future__ import annotations

import os

from .environment import CommandError

HELPER_PATH = "/usr/local/libexec/aurora-secrets-helper"
HELPER_OPS = ("list", "add", "delete", "enable", "disable", "passwd")
HELPER_BACKENDS = ("classic", "swanctl")

# Exact argv lists.
SUDO_WHITELIST: list[list[str]] = [
    # Credential writes: the root helper validates input, backs up, writes
    # atomically and reloads. The panel never touches the secrets files.
    *[[HELPER_PATH, backend, op]
      for backend in HELPER_BACKENDS for op in HELPER_OPS],
    # Non-disruptive config re-read (never kills established SAs).
    ["/usr/sbin/ipsec", "update"],
    ["/usr/sbin/ipsec", "rereadsecrets"],
    ["/usr/sbin/ipsec", "statusall"],
    # Full service restart, only from the explicit "Restart" button.
    ["/usr/bin/systemctl", "restart", "strongswan-starter"],
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


def is_whitelisted(cmd: list[str]) -> bool:
    """True only if the argv matches a whitelist entry EXACTLY."""
    if not cmd:
        return False
    abs_cmd = [_resolve(cmd[0]), *cmd[1:]]
    return abs_cmd in SUDO_WHITELIST


def effective_cmd(cmd: list[str]) -> list[str]:
    """Return the argv that should actually be executed.

    - running as root: execute directly
    - unprivileged with AURORA_USE_SUDO=1: `sudo -n` + exact whitelisted argv
    - otherwise: refuse rather than failing silently later
    """
    if os.geteuid() == 0:
        return cmd
    if os.environ.get("AURORA_USE_SUDO") == "1":
        if not is_whitelisted(cmd):
            raise CommandError(
                f"command not in privilege whitelist: {' '.join(cmd)}")
        return ["sudo", "-n", *cmd]
    raise CommandError(
        f"insufficient privileges for {' '.join(cmd)}; "
        "the panel must run as root, or with AURORA_USE_SUDO=1 and the "
        "aurora sudoers whitelist installed")


def sudoers_commands() -> list[str]:
    return [" ".join(argv) for argv in SUDO_WHITELIST]


def sudoers_text(user: str) -> str:
    """The complete /etc/sudoers.d/aurora-panel policy for `user`."""
    if not user or not all(c.isalnum() or c in "-_" for c in user):
        raise ValueError("invalid service user name")
    commands = ", ".join(sudoers_commands())
    return (
        "# Aurora IKEv2 Manager — generated from aurora/privileged.py.\n"
        "# Managed by install.sh; do not edit. Exact-argv whitelist only.\n"
        f"{user} ALL=(root) NOPASSWD: {commands}\n"
    )
