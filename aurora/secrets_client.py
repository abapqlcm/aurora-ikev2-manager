"""Panel-side client for the root secrets helper.

The panel never reads or writes strongSwan secrets directly. Every credential
operation is one exact-argv call to the helper through privileged.effective_cmd.
Passwords are passed on stdin, never in argv.
"""
from __future__ import annotations

import json
import subprocess

from .environment import CommandError
from .privileged import HELPER_PATH, effective_cmd

OPS_WITH_CREDENTIALS = ("add", "passwd")


def _default_runner(argv: list[str], stdin_text: str):
    return subprocess.run(argv, input=stdin_text, capture_output=True,
                          text=True, timeout=60)


# Replaceable in tests; production always uses _default_runner.
RUNNER = _default_runner


def call(backend: str, op: str, username: str | None = None,
         password: str | None = None):
    """Run one helper operation. Returns the helper's `result` field.

    Raises ValueError for input the helper rejected (exit 2) and CommandError
    for system failures (exit 3, missing helper, malformed output).
    """
    argv = effective_cmd([HELPER_PATH, backend, op])
    payload = ""
    if op != "list":
        payload = json.dumps({"username": username or "",
                              "password": password or ""})
    try:
        proc = RUNNER(argv, payload)
    except OSError as exc:
        raise CommandError(f"secrets helper unavailable: {exc.strerror or exc}") from exc
    try:
        data = json.loads(proc.stdout or "{}")
    except ValueError as exc:
        raise CommandError("secrets helper returned malformed output") from exc
    if proc.returncode == 0 and data.get("ok") is True:
        return data.get("result")
    message = data.get("error") or (proc.stderr or "").strip()[:200] or "helper failed"
    if proc.returncode == 2:
        raise ValueError(message)
    raise CommandError(message)
