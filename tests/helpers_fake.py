"""Test harness: routes panel->helper calls to real SecretsFile objects on temp files.

Exercises the exact helper dispatch (JSON in/out, exit codes) without root and
without touching /etc. The panel's privilege check is bypassed only here.
"""
import json
import types

from aurora import secrets_client, secrets_helper


class FakeHelper:
    def __init__(self, tmp_path, monkeypatch):
        self.classic_path = tmp_path / "ipsec.secrets"
        self.swanctl_path = tmp_path / "swanctl" / "aurora.secrets"
        self.swanctl_path.parent.mkdir(parents=True, exist_ok=True)
        self.backup_dir = str(tmp_path / "backups")
        self.reload_calls = []
        self.fail_reload = False
        self.calls = []
        monkeypatch.setattr(secrets_client, "effective_cmd", lambda argv: list(argv))
        monkeypatch.setattr(secrets_client, "RUNNER", self._run)

    def store_for(self, backend):
        path = self.classic_path if backend == "classic" else self.swanctl_path
        style = "classic" if backend == "classic" else "swanctl"

        def reload():
            self.reload_calls.append(backend)
            if self.fail_reload:
                raise secrets_helper.SecretsError("simulated reload failure")
        return secrets_helper.SecretsFile(str(path), style, reload=reload,
                                          backup_dir=self.backup_dir)

    def _run(self, argv, stdin_text):
        _, backend, op = argv[0], argv[1], argv[2]
        self.calls.append((backend, op))
        code, payload = secrets_helper.dispatch(
            [backend, op], stdin_text, factory=self.store_for)
        return types.SimpleNamespace(returncode=code,
                                     stdout=json.dumps(payload), stderr="")
