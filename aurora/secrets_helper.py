#!/usr/bin/python3
"""Aurora secrets helper — the ONLY code that writes strongSwan EAP secrets.

The web panel runs unprivileged and cannot read or write /etc/ipsec.secrets or
the swanctl secrets directory. It calls this helper through `sudo -n` with an
exact-argv rule generated from aurora/privileged.py. Nothing else is elevated.

Design constraints
------------------
- Stdlib only. install.sh copies this single file to
  /usr/local/libexec/aurora-secrets-helper (root:root 0755) and runs it with
  the system python3, so no writable virtualenv is ever executed as root.
- Passwords arrive on stdin as JSON. They are never placed in argv, never
  logged and never echoed to stdout.
- Every mutation: validate -> backup (root-only, rotated) -> atomic write ->
  reload -> on reload failure restore the backup and reload again.

CLI
---
    aurora-secrets-helper <classic|swanctl> <list|add|delete|enable|disable|passwd>

    stdin  (mutating ops): {"username": "...", "password": "..."}
    stdout: {"ok": true, "result": ...}  or  {"ok": false, "error": "..."}
    exit:   0 success, 2 invalid request, 3 system / IO / reload failure
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time

CLASSIC_SECRETS = "/etc/ipsec.secrets"
SWANCTL_SECRETS_DIR = "/etc/swanctl/secrets"
BACKUP_DIR = "/var/lib/aurora-secrets-backups"
DEFAULT_KEEP = 10
DISABLE_PREFIX = "# disabled by aurora:"
OPS = ("list", "add", "delete", "enable", "disable", "passwd")
BACKENDS = ("classic", "swanctl")
MAX_STDIN = 4096
SAFE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

USERNAME_RE = re.compile(r"^[a-zA-Z0-9._@-]{2,64}$")
# Parser is slightly wider than the username policy so that existing
# hand-written entries with '+' are still listed and preserved.
ENTRY_RE = re.compile(r'^"?([A-Za-z0-9._@+-]+)"?\s*:\s*EAP\s+(.+)$', re.I)


class ValidationError(ValueError):
    """Input rejected by policy; nothing was written."""


class SecretsError(RuntimeError):
    """System-level failure (I/O, backup, reload). Files are restored when possible."""


# ------------------------------------------------------------------ policy

def username_error(username: str) -> str | None:
    if not isinstance(username, str) or not USERNAME_RE.match(username):
        return "invalid username (2-64 chars: letters, digits, . _ @ -)"
    return None


def password_error(password: str) -> str | None:
    """Single password policy shared by both backends and the admin UI.

    Quotation marks and backslashes are REJECTED rather than escaped: the
    secrets-file grammar has no escape rules that every strongSwan version
    agrees on, so rejecting is the only way to guarantee that the stored
    secret is byte-identical to what the operator typed.
    """
    if not isinstance(password, str):
        return "password must be text"
    if not (8 <= len(password) <= 128):
        return "password must be 8-128 characters"
    if any(not (32 <= ord(c) < 127) for c in password):
        return "password may contain printable ASCII characters only"
    if '"' in password or "\\" in password:
        return "password may not contain quotation marks or backslashes"
    if password != password.strip():
        return "password may not start or end with a space"
    return None


def validate_username(username: str) -> None:
    err = username_error(username)
    if err:
        raise ValidationError(err)


def validate_password(password: str) -> None:
    err = password_error(password)
    if err:
        raise ValidationError(err)


# ----------------------------------------------------------------- parsing

def parse_line(raw: str) -> tuple[str, bool] | None:
    """(username, disabled) for an EAP entry line, else None.

    Lines are classified without ever returning the secret.
    """
    stripped = raw.strip()
    disabled = stripped.startswith(DISABLE_PREFIX)
    if disabled:
        stripped = stripped[len(DISABLE_PREFIX):].strip()
    if not stripped or stripped.startswith("#"):
        return None
    m = ENTRY_RE.match(stripped)
    if not m:
        return None
    return m.group(1), disabled


def format_entry(style: str, username: str, password: str) -> str:
    validate_username(username)
    validate_password(password)
    if style == "swanctl":
        return f'"{username}" : EAP "{password}"'
    return f'{username} : EAP "{password}"'


def resolve_swanctl_path(secrets_dir: str = SWANCTL_SECRETS_DIR) -> str:
    """Pick the swanctl secrets file Aurora manages.

    Priority: aurora.secrets > first *.secrets containing EAP entries >
    aurora.secrets (created on first write).
    """
    preferred = os.path.join(secrets_dir, "aurora.secrets")
    if os.path.isfile(preferred):
        return preferred
    if os.path.isdir(secrets_dir):
        for name in sorted(os.listdir(secrets_dir)):
            path = os.path.join(secrets_dir, name)
            if name.endswith(".secrets") and os.path.isfile(path):
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        if any(parse_line(line) for line in fh):
                            return path
                except OSError:
                    continue
    return preferred


# -------------------------------------------------------- file primitives

def _write_atomic(path: str, text: str) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o755, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".aurora-secrets.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _prune_backups(backup_dir: str, basename: str, keep: int) -> None:
    """Delete the oldest backups *created by Aurora for this file* beyond `keep`.

    Only names matching <basename>.<ns-timestamp>.<pid>.bak are candidates;
    unrelated files in the directory are never touched.
    """
    pattern = re.compile(rf"^{re.escape(basename)}\.\d+\.\d+\.bak$")
    managed = sorted(n for n in os.listdir(backup_dir) if pattern.match(n))
    for stale in managed[: max(0, len(managed) - keep)]:
        try:
            os.unlink(os.path.join(backup_dir, stale))
        except OSError:
            pass


def create_backup(path: str, text: str, backup_dir: str, keep: int = DEFAULT_KEEP) -> str:
    """Create a root-only backup of `text` (the pre-change content) BEFORE any write.

    Raises SecretsError if the backup cannot be created: the caller must then
    refuse to change the secrets file at all (rollback safety).
    """
    basename = os.path.basename(path)
    try:
        os.makedirs(backup_dir, mode=0o700, exist_ok=True)
        os.chmod(backup_dir, 0o700)
        name = f"{basename}.{time.time_ns()}.{os.getpid()}.bak"
        full = os.path.join(backup_dir, name)
        fd = os.open(full, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as exc:
        raise SecretsError(f"cannot create backup, change not applied: {exc}") from exc
    _prune_backups(backup_dir, basename, keep)
    return full


# ------------------------------------------------------------- the store

class SecretsFile:
    """One strongSwan secrets file plus its backend-specific reload hook.

    `reload` is called after every successful write. It may be None (tests
    or pure file operations). The store performs the rollback itself.
    """

    def __init__(self, path: str, style: str = "classic", reload=None,
                 backup_dir: str | None = BACKUP_DIR, keep: int = DEFAULT_KEEP):
        if style not in ("classic", "swanctl"):
            raise ValueError("unknown style")
        self.path = path
        self.style = style
        self.reload = reload
        self.backup_dir = backup_dir
        self.keep = keep

    # -- reads (names and states only; secrets never leave this module)

    def _read(self) -> str:
        try:
            with open(self.path, encoding="utf-8") as fh:
                return fh.read()
        except FileNotFoundError:
            return ""
        except PermissionError as exc:
            raise SecretsError(f"cannot read {self.path}: permission denied") from exc
        except (OSError, UnicodeDecodeError) as exc:
            raise SecretsError(f"cannot read {self.path}: {exc}") from exc

    def entries(self) -> list[tuple[str, str]]:
        out = []
        for line in self._read().splitlines():
            parsed = parse_line(line)
            if parsed:
                name, disabled = parsed
                out.append((name, "disabled" if disabled else "enabled"))
        return out

    def list_names(self) -> list[str]:
        return [name for name, _ in self.entries()]

    def state(self, username: str) -> str:
        for name, st in self.entries():
            if name == username:
                return st
        return "missing"

    # -- mutations

    def _apply(self, transform) -> bool:
        """transform(lines) -> (new_lines, changed). Atomic, backed up, reload-safe."""
        old = self._read()
        new_lines, changed = transform(old.splitlines())
        if not changed:
            return False
        new_text = "\n".join(new_lines) + "\n" if new_lines else ""
        if self.backup_dir is None:
            raise SecretsError("no backup directory configured; refusing to change secrets")
        create_backup(self.path, old, self.backup_dir, self.keep)
        _write_atomic(self.path, new_text)
        if self.reload is not None:
            try:
                self.reload()
            except Exception as exc:  # noqa: BLE001 - any reload failure triggers rollback
                _write_atomic(self.path, old)
                try:
                    self.reload()
                except Exception:  # noqa: BLE001 - original failure is what matters
                    pass
                raise SecretsError(
                    f"reload failed, change rolled back: {exc}") from exc
        return True

    def add(self, username: str, password: str) -> None:
        entry = format_entry(self.style, username, password)  # validates first

        def transform(lines):
            if any(parse_line(line) and parse_line(line)[0] == username for line in lines):
                raise ValidationError(f"user {username!r} already exists")
            return lines + [entry], True

        self._apply(transform)

    def delete(self, username: str) -> bool:
        validate_username(username)

        def transform(lines):
            kept = [line for line in lines
                    if not (parse_line(line) and parse_line(line)[0] == username)]
            return kept, len(kept) != len(lines)

        return self._apply(transform)

    def set_password(self, username: str, password: str) -> None:
        validate_username(username)
        validate_password(password)

        def transform(lines):
            out, found = [], False
            for line in lines:
                parsed = parse_line(line)
                if parsed and parsed[0] == username:
                    found = True
                    prefix = DISABLE_PREFIX + " " if parsed[1] else ""
                    out.append(prefix + format_entry(self.style, username, password))
                else:
                    out.append(line)
            if not found:
                raise ValidationError(f"user {username!r} not found")
            return out, True

        self._apply(transform)

    def _toggle(self, username: str, disable: bool) -> bool:
        validate_username(username)

        def transform(lines):
            out, changed = [], False
            for line in lines:
                parsed = parse_line(line)
                if parsed and parsed[0] == username and parsed[1] != disable:
                    changed = True
                    bare = line.strip()
                    if disable:
                        out.append(f"{DISABLE_PREFIX} {bare}")
                    else:
                        out.append(bare[len(DISABLE_PREFIX):].strip())
                else:
                    out.append(line)
            return out, changed

        return self._apply(transform)

    def disable(self, username: str) -> bool:
        return self._toggle(username, True)

    def enable(self, username: str) -> bool:
        return self._toggle(username, False)


# -------------------------------------------------------- real backends

def _run_reload(argv: list[str]) -> None:
    env = {"PATH": SAFE_PATH}
    p = subprocess.run(argv, capture_output=True, text=True, timeout=30, env=env)
    if p.returncode != 0:
        raise SecretsError((p.stderr or p.stdout).strip()[:200] or f"{argv[0]} failed")


def backend_factory(backend: str) -> SecretsFile:
    """Map a backend name to its real file and reload command (root only)."""
    if backend == "classic":
        return SecretsFile(
            CLASSIC_SECRETS, "classic",
            reload=lambda: _run_reload(["/usr/sbin/ipsec", "rereadsecrets"]))
    if backend == "swanctl":
        return SecretsFile(
            resolve_swanctl_path(), "swanctl",
            reload=lambda: _run_reload(["/usr/sbin/swanctl", "--load-secrets"]))
    raise ValidationError("unknown backend")


# ------------------------------------------------------------- dispatcher

def dispatch(argv: list[str], stdin_text: str, factory=backend_factory) -> tuple[int, dict]:
    """Pure dispatcher used by the CLI and by tests. Returns (exit_code, payload)."""
    if len(argv) != 2 or argv[0] not in BACKENDS or argv[1] not in OPS:
        return 2, {"ok": False, "error": "usage: <classic|swanctl> <op>"}
    backend, op = argv
    try:
        store = factory(backend)
        if op == "list":
            return 0, {"ok": True, "result": [
                {"name": n, "state": s} for n, s in store.entries()]}
        if len(stdin_text) > MAX_STDIN:
            raise ValidationError("request too large")
        req = json.loads(stdin_text or "{}")
        if not isinstance(req, dict):
            raise ValidationError("request must be a JSON object")
        username = req.get("username", "")
        password = req.get("password", "")
        validate_username(username)
        if op == "add":
            store.add(username, password)
            result = None
        elif op == "passwd":
            store.set_password(username, password)
            result = None
        elif op == "delete":
            result = store.delete(username)
        elif op == "disable":
            result = store.disable(username)
        else:  # enable
            result = store.enable(username)
        return 0, {"ok": True, "result": result}
    except ValidationError as exc:
        return 2, {"ok": False, "error": str(exc)}
    except json.JSONDecodeError:
        return 2, {"ok": False, "error": "malformed request"}
    except SecretsError as exc:
        return 3, {"ok": False, "error": str(exc)}
    except OSError as exc:
        return 3, {"ok": False, "error": f"system error: {exc.strerror or exc}"}


def cli(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    stdin_text = ""
    if len(argv) == 2 and argv[1] != "list":
        stdin_text = sys.stdin.read(MAX_STDIN + 1)
    code, payload = dispatch(argv, stdin_text)
    sys.stdout.write(json.dumps(payload) + "\n")
    return code


if __name__ == "__main__":
    sys.exit(cli())
