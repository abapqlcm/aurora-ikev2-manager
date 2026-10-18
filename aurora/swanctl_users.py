"""Aurora IKEv2 Manager — user management for swanctl (vici) deployments.

Scope and guarantees
--------------------
- Manages EAP-MSCHAPv2 credentials stored in the swanctl secrets directory
  (default /etc/swanctl/secrets/aurora.secrets or existing secrets files).
- Applies changes with `swanctl --load-secrets` — this NEVER restarts the
  charon daemon and NEVER touches established SAs. New authentications see
  the changes immediately.
- swanctl.conf (connections/pools/auth rounds) is NEVER rewritten by the
  panel: if EAP is not already configured in the existing connection, the
  panel reports that instead of editing the file.
- Every mutation: validate -> backup -> atomic write -> reload -> verify.
- Recovery: on failed reload the pre-change backup is restored and reloaded.

Active-session limitation (documented, tested as far as unit testing allows):
- Deleting/disabling a user does NOT terminate an established IKE SA that
  authenticated earlier. StrongSwan only re-validates at (re)authentication
  time. To revoke immediately, an admin may delete the SA via the dashboard
  once terminate-SA support is enabled; until then the limitation is stated
  in the UI and docs.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile

from .environment import run, run_ok, CommandError
from .privileged import effective_cmd

DEFAULT_SECRETS_DIR = "/etc/swanctl/secrets"
DEFAULT_SECRETS_FILE = os.path.join(DEFAULT_SECRETS_DIR, "aurora.secrets")
SWANCTL_CONF = "/etc/swanctl/swanctl.conf"

USERNAME_RE = re.compile(r"^[a-zA-Z0-9._@-]{2,64}$")
_DISABLE_PREFIX = "# disabled by aurora:"
_ENTRY_RE = re.compile(r'^"?([A-Za-z0-9._@+-]+)"?\s*:\s*EAP\s+(.+)$', re.I)


def valid_username(u: str) -> bool:
    return bool(USERNAME_RE.match(u))


def valid_password(p: str) -> bool:
    return 8 <= len(p) <= 128 and all(32 <= ord(c) < 127 for c in p)


# ------------------------------------------------------------- discovery

def find_secrets_file(secrets_dir: str = DEFAULT_SECRETS_DIR,
                      explicit: str | None = None) -> str:
    """Pick the swanctl secrets file Aurora manages.

    Priority: explicit override > aurora.secrets > first *.secrets with EAP
    entries > aurora.secrets (created on first write).
    """
    if explicit:
        return explicit
    preferred = os.path.join(secrets_dir, "aurora.secrets")
    if os.path.isfile(preferred):
        return preferred
    if os.path.isdir(secrets_dir):
        for name in sorted(os.listdir(secrets_dir)):
            path = os.path.join(secrets_dir, name)
            if name.endswith(".secrets") and os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        if _ENTRY_RE.search(fh.read()):
                            return path
                except OSError:
                    continue
    return preferred


def check_eap_configured(swanctl_conf: str = SWANCTL_CONF) -> tuple[bool, str]:
    """Verify the existing swanctl.conf actually has EAP auth somewhere.

    Returns (ok, detail). Aurora never edits swanctl.conf; if EAP is not
    configured the panel refuses user management with an explanation.
    """
    try:
        with open(swanctl_conf, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except FileNotFoundError:
        return False, f"{swanctl_conf} not found"
    clean = re.sub(r"#.*$", "", text, flags=re.M)
    if re.search(r"auth\s*=\s*eap[-\w]*", clean, re.I):
        return True, "EAP authentication present in swanctl.conf"
    return False, ("no EAP auth round found in swanctl.conf — add "
                   "remote { auth = eap-mschapv2; eap_id = %any; } to your "
                   "connection first; Aurora does not edit swanctl.conf")


# ------------------------------------------------------------- file layer

def backup_file(path: str, backup_dir: str | None = None) -> str | None:
    if not os.path.exists(path):
        return None
    bdir = backup_dir or os.environ.get(
        "AURORA_BACKUP_DIR",
        os.path.join(os.path.dirname(path), ".aurora-backups"))
    os.makedirs(bdir, mode=0o700, exist_ok=True)
    dst = os.path.join(bdir, f"{os.path.basename(path)}."
                             f"{os.getpid()}.{int(os.path.getmtime(path))}.bak")
    shutil.copy2(path, dst)
    os.chmod(dst, 0o600)
    return dst


def _read(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _write_atomic(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".",
                               prefix=".swanctl-secrets.")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def parse_entries(text: str) -> list[tuple[str, bool]]:
    """[(username, disabled)] — names and state only, never secrets."""
    out = []
    for raw in text.splitlines():
        stripped = raw.strip()
        disabled = stripped.startswith(_DISABLE_PREFIX)
        if disabled:
            stripped = stripped[len(_DISABLE_PREFIX):].strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = _ENTRY_RE.match(stripped)
        if m:
            out.append((m.group(1), disabled))
    return out


def list_users(path: str = DEFAULT_SECRETS_FILE) -> list[str]:
    return [u for u, _ in parse_entries(_read(path))]


def user_state(username: str, path: str = DEFAULT_SECRETS_FILE) -> str:
    for u, disabled in parse_entries(_read(path)):
        if u == username:
            return "disabled" if disabled else "enabled"
    return "missing"


# ------------------------------------------------------------- operations

def add_user(username: str, password: str,
             path: str = DEFAULT_SECRETS_FILE) -> None:
    if not valid_username(username):
        raise ValueError("invalid username (2-64 chars [A-Za-z0-9._@+-])")
    if not valid_password(password):
        raise ValueError("invalid password (8-128 printable ASCII)")
    text = _read(path)
    if any(u == username for u, _ in parse_entries(text)):
        raise ValueError(f"user {username!r} already exists")
    backup_file(path)
    _write_atomic(path, text + f'"{username}" : EAP "{password}"\n')
    _reload(path, pre_change_text=text)


def delete_user(username: str, path: str = DEFAULT_SECRETS_FILE) -> bool:
    """Remove exactly this user's entry; unrelated users untouched."""
    if not valid_username(username):
        raise ValueError("invalid username")
    text = _read(path)
    out, changed = [], False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith(_DISABLE_PREFIX):
            stripped = stripped[len(_DISABLE_PREFIX):].strip()
        m = _ENTRY_RE.match(stripped)
        if m and m.group(1) == username:
            changed = True
            continue
        out.append(raw)
    if not changed:
        return False
    backup_file(path)
    _write_atomic(path, "\n".join(out) + ("\n" if out else ""))
    _reload(path, pre_change_text=text)
    return True


def set_user_password(username: str, password: str,
                      path: str = DEFAULT_SECRETS_FILE) -> None:
    if not valid_username(username):
        raise ValueError("invalid username")
    if not valid_password(password):
        raise ValueError("invalid password (8-128 printable ASCII)")
    text = _read(path)
    out, changed = [], False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith(_DISABLE_PREFIX):
            stripped = stripped[len(_DISABLE_PREFIX):].strip()
        m = _ENTRY_RE.match(stripped)
        if m and m.group(1) == username:
            changed = True
            out.append(f'"{username}" : EAP "{password}"')
            continue
        out.append(raw)
    if not changed:
        raise ValueError(f"user {username!r} not found")
    backup_file(path)
    _write_atomic(path, "\n".join(out) + "\n")
    _reload(path, pre_change_text=text)


def _toggle(username: str, disable: bool, path: str) -> bool:
    if not valid_username(username):
        raise ValueError("invalid username")
    text = _read(path)
    out, changed = [], False
    for raw in text.splitlines():
        stripped = raw.strip()
        was_disabled = stripped.startswith(_DISABLE_PREFIX)
        bare = stripped[len(_DISABLE_PREFIX):].strip() if was_disabled else stripped
        m = _ENTRY_RE.match(bare)
        if m and m.group(1) == username:
            changed = True
            if disable and not was_disabled:
                out.append(f"{_DISABLE_PREFIX} {bare}")
                continue
            if not disable and was_disabled:
                out.append(bare)
                continue
        out.append(raw)
    if not changed:
        return False
    backup_file(path)
    _write_atomic(path, "\n".join(out) + "\n")
    _reload(path, pre_change_text=text)
    return True


def disable_user(username: str, path: str = DEFAULT_SECRETS_FILE) -> bool:
    return _toggle(username, True, path)


def enable_user(username: str, path: str = DEFAULT_SECRETS_FILE) -> bool:
    return _toggle(username, False, path)


# ------------------------------------------------------------- apply/recover

def load_secrets() -> None:
    """`swanctl --load-secrets` — no daemon restart, no SA disruption."""
    run_ok(effective_cmd(["/usr/sbin/swanctl", "--load-secrets"]), timeout=30)


def _reload(path: str, pre_change_text: str | None = None) -> None:
    """Apply via vici. On failure, restore pre-change content and re-apply.

    Callers pass the file content that was on disk BEFORE the mutation so a
    failed `swanctl --load-secrets` leaves the host in the original state.
    """
    try:
        load_secrets()
    except CommandError:
        if pre_change_text is not None:
            _write_atomic(path, pre_change_text)
            try:
                load_secrets()
            except CommandError:
                pass  # report original failure; on-disk state is restored
        raise
    if not os.path.isfile(path):
        raise CommandError("secrets file disappeared after reload")


def daemon_active() -> bool:
    p = run(["systemctl", "is-active", "strongswan-swanctl"])
    if p.stdout.strip() != "active":
        p = run(["systemctl", "is-active", "strongswan-starter"])
    if p.stdout.strip() != "active":
        p = run(["systemctl", "is-active", "strongswan"])
    return p.stdout.strip() == "active"
