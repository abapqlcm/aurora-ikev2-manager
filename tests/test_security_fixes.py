"""Regression tests for the Priority 1-3 fixes (permissions, redirects,
credentials, rate limiting, forced password change, whitelist, monitoring,
configuration validation, backend routing, CSP, dead code, backups, hashing,
installer reliability)."""
import json
import os
import re
import subprocess
import sqlite3
import time
import types

import pytest

from aurora import app as aurora_app
from aurora import monitor, privileged, secrets_client, secrets_helper, strongswan
from aurora import swanctl_users, environment
from aurora.app import (hash_password, verify_password, needs_rehash,
                        safe_next, login_blocked, record_login_failure,
                        PBKDF2_ITERS, LOGIN_MAX_FAILS)
from aurora.secrets_helper import SecretsError, SecretsFile, ValidationError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as fh:
        return fh.read()


# ================================================================ item 1
class TestPrivilegeBoundary:
    def test_panel_code_never_touches_secrets_files_directly(self):
        """Only the root helper may name the secrets paths."""
        for name in os.listdir(os.path.join(ROOT, "aurora")):
            if not name.endswith(".py") or name == "secrets_helper.py":
                continue
            text = _read(os.path.join("aurora", name))
            assert "/etc/ipsec.secrets" not in text, name
            assert "/etc/swanctl/secrets" not in text, name

    def test_helper_is_stdlib_only(self):
        text = _read("aurora/secrets_helper.py")
        imports = re.findall(r"^(?:import|from) (\w+)", text, re.M)
        allowed = {"__future__", "json", "os", "re", "subprocess", "sys",
                   "tempfile", "time"}
        assert set(imports) <= allowed, set(imports) - allowed
        assert text.startswith("#!/usr/bin/python3")

    def test_systemd_hardening_not_weakened(self):
        install = _read("install.sh")
        assert "ProtectSystem=strict" in install
        assert "ReadWritePaths=$BASE_DIR" in install

    def test_helper_unreadable_path_returns_error_not_traceback(self, tmp_path):
        d = tmp_path / "a-directory.secrets"
        d.mkdir()  # opening a directory raises IsADirectoryError
        store = SecretsFile(str(d), "classic", backup_dir=str(tmp_path / "b"))
        code, payload = secrets_helper.dispatch(
            ["classic", "list"], "", factory=lambda backend: store)
        assert code == 3 and payload["ok"] is False
        assert "Traceback" not in json.dumps(payload)

    def test_helper_refuses_unknown_backend_and_op(self):
        assert secrets_helper.dispatch(["evil", "list"], "")[0] == 2
        assert secrets_helper.dispatch(["classic", "rm"], "")[0] == 2

    def test_helper_rejects_non_object_and_oversized_input(self, tmp_path):
        store = SecretsFile(str(tmp_path / "s"), "classic", backup_dir=str(tmp_path / "b"))
        def f(backend):
            return store

        assert secrets_helper.dispatch(["classic", "add"], "[1,2]", factory=f)[0] == 2
        big = json.dumps({"username": "a" * 5000, "password": "x"})
        assert secrets_helper.dispatch(["classic", "add"], big, factory=f)[0] == 2
        assert secrets_helper.dispatch(["classic", "add"], "{bad", factory=f)[0] == 2

    def test_client_maps_exit_codes(self, monkeypatch):
        monkeypatch.setattr(secrets_client, "effective_cmd", lambda a: a)

        def runner(code, out):
            return lambda argv, s: types.SimpleNamespace(
                returncode=code, stdout=out, stderr="boom")
        monkeypatch.setattr(secrets_client, "RUNNER",
                            runner(2, json.dumps({"ok": False, "error": "bad name"})))
        with pytest.raises(ValueError, match="bad name"):
            secrets_client.call("classic", "add", "x", "y")
        monkeypatch.setattr(secrets_client, "RUNNER",
                            runner(3, json.dumps({"ok": False, "error": "disk"})))
        from aurora.environment import CommandError
        with pytest.raises(CommandError, match="disk"):
            secrets_client.call("classic", "list")
        monkeypatch.setattr(secrets_client, "RUNNER", runner(0, "not json"))
        with pytest.raises(CommandError, match="malformed"):
            secrets_client.call("classic", "list")

    def test_missing_helper_is_reported_cleanly(self, monkeypatch):
        monkeypatch.setattr(secrets_client, "effective_cmd", lambda a: a)

        def missing(argv, s):
            raise FileNotFoundError(2, "No such file", argv[0])
        monkeypatch.setattr(secrets_client, "RUNNER", missing)
        from aurora.environment import CommandError
        with pytest.raises(CommandError, match="unavailable"):
            secrets_client.call("classic", "list")

    def test_inspect_existing_tolerates_unreadable_paths(self, monkeypatch):
        warnings = []
        assert environment._read_text("/", warnings) is None  # directory
        assert warnings and "cannot read /" in warnings[0]


# ================================================================ item 2
class TestSafeRedirect:
    @pytest.mark.parametrize("bad", [
        "https://evil.example", "http://evil.example/x", "//evil.example",
        "///evil.example", "/\\evil.example", "\\\\evil.example", "/\\\\evil",
        "%2F%2Fevil.example", "/%2F%2Fevil.example", "/%5Cevil.example",
        "%2f%2fevil", "javascript:alert(1)", "evil.example", "",
        "/ok\r\nLocation: https://evil", "/tab\tbed", "https:%2F%2Fevil.example",
        "/%252F%252Fevil.example", "x" * 600,
    ])
    def test_unsafe_targets_fall_back(self, bad):
        assert safe_next(bad, "/dash") == "/dash"

    @pytest.mark.parametrize("good", ["/", "/users", "/users?q=alice", "/server",
                                      "/change-password"])
    def test_internal_paths_accepted(self, good):
        assert safe_next(good, "/dash") == good

    def test_login_ignores_external_next(self, tmp_path, monkeypatch):
        client = _web_client(tmp_path, monkeypatch)
        csrf = _csrf(client)
        r = client.post("/login?next=https://evil.example",
                        data={"username": "admin", "password": "TestPass123", "csrf": csrf})
        assert r.status_code == 302
        assert r.headers["Location"].endswith("/") and "evil" not in r.headers["Location"]


# ================================================================ item 3
class TestPasswordPolicy:
    @pytest.mark.parametrize("bad", [
        'pa"ssword1', "pass\\word1", '"quoted1', "back\\slash", " leading1",
        "trailing1 ", "short", "پسورد فارسی", "x" * 129, "tab\there1",
    ])
    def test_rejected_and_file_unchanged(self, tmp_path, bad):
        f = tmp_path / "ipsec.secrets"
        s = SecretsFile(str(f), "classic", backup_dir=str(tmp_path / "b"))
        s.add("alice", "GoodPass123")
        before = f.read_text()
        with pytest.raises(ValidationError):
            s.add("bob", bad)
        assert f.read_text() == before
        with pytest.raises(ValidationError):
            s.set_password("alice", bad)
        assert f.read_text() == before

    def test_valid_password_with_inner_spaces_roundtrips_exactly(self, tmp_path):
        f = tmp_path / "ipsec.secrets"
        s = SecretsFile(str(f), "classic", backup_dir=str(tmp_path / "b"))
        s.add("alice", "correct horse 9!")
        assert 'alice : EAP "correct horse 9!"' in f.read_text()

    def test_same_policy_for_both_backends(self, tmp_path):
        for style in ("classic", "swanctl"):
            f = tmp_path / f"{style}.secrets"
            s = SecretsFile(str(f), style, backup_dir=str(tmp_path / "b"))
            with pytest.raises(ValidationError):
                s.add("alice", 'bad"pass1')


# ================================================================ item 4
class TestDisabledDeletion:
    def test_delete_disabled_classic_user_leaves_no_secret(self, tmp_path):
        f = tmp_path / "ipsec.secrets"
        s = SecretsFile(str(f), "classic", backup_dir=str(tmp_path / "b"))
        s.add("alice", "SecretAlpha1")
        s.add("bob", "KeepBravo22")
        assert s.disable("alice") is True
        assert s.delete("alice") is True
        text = f.read_text()
        assert "SecretAlpha1" not in text and "alice" not in text
        assert 'bob : EAP "KeepBravo22"' in text  # unrelated user intact

    def test_delete_returns_false_when_nothing_matches(self, tmp_path):
        s = SecretsFile(str(tmp_path / "x"), "classic", backup_dir=str(tmp_path / "b"))
        assert s.delete("ghost") is False

    def test_set_password_keeps_disabled_state(self, tmp_path):
        f = tmp_path / "ipsec.secrets"
        s = SecretsFile(str(f), "classic", backup_dir=str(tmp_path / "b"))
        s.add("alice", "OldPass123")
        s.disable("alice")
        s.set_password("alice", "NewPass456")
        assert s.state("alice") == "disabled"
        assert "NewPass456" in f.read_text() and "OldPass123" not in f.read_text()


# ================================================================ item 13
class TestBackups:
    def test_backup_dir_and_files_are_root_style_private(self, tmp_path):
        f = tmp_path / "ipsec.secrets"
        bdir = tmp_path / "bk"
        s = SecretsFile(str(f), "classic", backup_dir=str(bdir))
        s.add("alice", "SecretAlpha1")
        assert (bdir.stat().st_mode & 0o777) == 0o700
        baks = list(bdir.glob("ipsec.secrets.*.bak"))
        assert baks and all((b.stat().st_mode & 0o777) == 0o600 for b in baks)

    def test_retention_keeps_newest_only(self, tmp_path):
        f = tmp_path / "ipsec.secrets"
        bdir = tmp_path / "bk"
        s = SecretsFile(str(f), "classic", backup_dir=str(bdir), keep=3)
        for i in range(8):
            s.add(f"user{i:02d}", f"Password{i:02d}x")
        baks = list(bdir.glob("ipsec.secrets.*.bak"))
        assert len(baks) == 3

    def test_retention_never_deletes_unrelated_files(self, tmp_path):
        bdir = tmp_path / "bk"
        bdir.mkdir()
        keep_me = bdir / "notes.txt"
        keep_me.write_text("operator notes")
        other = bdir / "ipsec.secrets.12.bak.manual"
        other.write_text("x")
        s = SecretsFile(str(tmp_path / "ipsec.secrets"), "classic",
                        backup_dir=str(bdir), keep=1)
        for i in range(4):
            s.add(f"user{i:02d}", f"Password{i:02d}x")
        assert keep_me.exists() and other.exists()

    def test_backup_failure_refuses_change(self, tmp_path):
        f = tmp_path / "ipsec.secrets"
        f.write_text('alice : EAP "Original123"\n')
        not_a_dir = tmp_path / "file-not-dir"
        not_a_dir.write_text("")
        s = SecretsFile(str(f), "classic", backup_dir=str(not_a_dir))
        with pytest.raises(SecretsError, match="backup"):
            s.add("bob", "NewPass123")
        assert f.read_text() == 'alice : EAP "Original123"\n'

    def test_reload_failure_restores_previous_content(self, tmp_path):
        f = tmp_path / "ipsec.secrets"
        f.write_text('alice : EAP "Original123"\n')
        calls = {"n": 0}

        def reload():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("charon unavailable")
        s = SecretsFile(str(f), "classic", reload=reload, backup_dir=str(tmp_path / "b"))
        with pytest.raises(SecretsError, match="rolled back"):
            s.add("bob", "NewPass123")
        assert f.read_text() == 'alice : EAP "Original123"\n'
        assert calls["n"] == 2  # recovery reload attempted

    def test_secrets_file_mode_is_0600(self, tmp_path):
        f = tmp_path / "ipsec.secrets"
        SecretsFile(str(f), "classic", backup_dir=str(tmp_path / "b")).add("alice", "SecretAlpha1")
        assert (f.stat().st_mode & 0o777) == 0o600


# ================================================================ item 5
class TestSharedRateLimit:
    def _db(self, tmp_path, monkeypatch):
        path = tmp_path / "shared.db"
        monkeypatch.setenv("AURORA_DB", str(path))
        aurora_app.init_db(None)
        return sqlite3.connect(path)

    def test_failures_visible_across_processes(self, tmp_path, monkeypatch):
        db_a = self._db(tmp_path, monkeypatch)
        db_b = sqlite3.connect(tmp_path / "shared.db")
        db_b.row_factory = sqlite3.Row
        for _ in range(LOGIN_MAX_FAILS):
            record_login_failure(db_a, "203.0.113.9")
        assert login_blocked(db_b, "203.0.113.9") is True
        assert login_blocked(db_b, "198.51.100.1") is False

    def test_window_expiry_unblocks(self, tmp_path, monkeypatch):
        db = self._db(tmp_path, monkeypatch)
        old = time.time() - aurora_app.LOGIN_WINDOW - 60
        for _ in range(LOGIN_MAX_FAILS):
            db.execute("INSERT INTO login_attempts (ip, ts) VALUES (?,?)", ("203.0.113.9", old))
        db.commit()
        assert login_blocked(db, "203.0.113.9") is False

    def test_second_app_instance_enforces_block(self, tmp_path, monkeypatch):
        monkeypatch.setenv("AURORA_DB", str(tmp_path / "shared.db"))
        monkeypatch.setenv("AURORA_SECRET_KEY", "k")
        monkeypatch.setenv("AURORA_INSECURE_COOKIES", "1")
        app1 = aurora_app.create_app()
        app2 = aurora_app.create_app()  # second "worker"
        _seed_admin(tmp_path / "shared.db")
        c1, c2 = app1.test_client(), app2.test_client()
        for _ in range(LOGIN_MAX_FAILS):
            c1.post("/login", data={"username": "admin", "password": "WrongPass1",
                                    "csrf": _csrf(c1)})
        r = c2.post("/login", data={"username": "admin", "password": "TestPass123",
                                    "csrf": _csrf(c2)})
        assert r.status_code == 429


# ================================================================ item 6
class TestForcedPasswordChange:
    def test_must_change_redirects_then_clears(self, tmp_path, monkeypatch):
        client = _web_client(tmp_path, monkeypatch, must_change=1)
        csrf = _csrf(client)
        r = client.post("/login", data={"username": "admin", "password": "TestPass123",
                                        "csrf": csrf})
        assert "/change-password" in r.headers["Location"]
        assert client.get("/").status_code == 302
        assert "/change-password" in client.get("/").headers["Location"]
        assert client.get("/users").status_code == 302
        assert client.get("/change-password").status_code == 200  # no loop

        wrong = client.post("/change-password", data={
            "csrf": _csrf(client), "current": "nope", "new": "NewPass999",
            "confirm": "NewPass999"})
        assert wrong.status_code == 200
        assert _must_change(tmp_path) == 1

        ok = client.post("/change-password", data={
            "csrf": _csrf(client), "current": "TestPass123", "new": "NewPass999",
            "confirm": "NewPass999"})
        assert ok.status_code == 302 and ok.headers["Location"].endswith("/")
        assert _must_change(tmp_path) == 0
        assert client.get("/").status_code == 200

    def test_change_requires_csrf(self, tmp_path, monkeypatch):
        client = _web_client(tmp_path, monkeypatch, must_change=1)
        client.post("/login", data={"username": "admin", "password": "TestPass123",
                                    "csrf": _csrf(client)})
        r = client.post("/change-password", data={
            "current": "TestPass123", "new": "NewPass999", "confirm": "NewPass999"})
        assert r.status_code == 400
        assert _must_change(tmp_path) == 1

    def test_new_password_must_differ_and_match(self, tmp_path, monkeypatch):
        client = _web_client(tmp_path, monkeypatch, must_change=1)
        client.post("/login", data={"username": "admin", "password": "TestPass123",
                                    "csrf": _csrf(client)})
        same = client.post("/change-password", data={
            "csrf": _csrf(client), "current": "TestPass123", "new": "TestPass123",
            "confirm": "TestPass123"})
        assert same.status_code == 200 and _must_change(tmp_path) == 1
        mism = client.post("/change-password", data={
            "csrf": _csrf(client), "current": "TestPass123", "new": "NewPass999",
            "confirm": "Other9999"})
        assert mism.status_code == 200 and _must_change(tmp_path) == 1

    def test_reset_admin_sets_must_change(self, tmp_path):
        src = _read("install.sh")
        assert "must_change=1 WHERE username=?" in src

    def test_bootstrap_inserts_must_change(self):
        assert "must_change) VALUES (?,?,1)" in _read("install.sh")


# ================================================================ item 7
class TestWhitelistExact:
    def _sudoers_commands(self):
        text = privileged.sudoers_text("aurora")
        line = [ln for ln in text.splitlines() if "NOPASSWD:" in ln][0]
        return [c.strip() for c in line.split("NOPASSWD:", 1)[1].split(",")]

    def test_sudoers_matches_python_whitelist_exactly(self):
        expected = sorted(" ".join(c) for c in privileged.SUDO_WHITELIST)
        assert sorted(self._sudoers_commands()) == expected

    def test_install_sh_generates_sudoers_from_python(self):
        text = _read("install.sh")
        assert "sudoers_text" in text
        assert "visudo -c -f" in text
        assert "NOPASSWD: /usr/sbin/ipsec rereadsecrets" not in text  # no hand-written copy

    @pytest.mark.parametrize("argv", [
        [privileged.HELPER_PATH, "classic", "add", "extra"],
        [privileged.HELPER_PATH, "classic"],
        [privileged.HELPER_PATH, "classic", "rm"],
        ["/usr/local/bin/aurora-secrets-helper", "classic", "list"],
        ["/usr/sbin/ipsec", "start"],
        ["/usr/sbin/ipsec", "restart"],
        ["/usr/sbin/ipsec", "update", "--force"],
        ["/usr/sbin/swanctl", "--load-secrets"],
        ["/usr/bin/systemctl", "restart", "strongswan-starter", "--now"],
        ["/usr/bin/systemctl", "restart", "sshd"],
        ["/bin/rm", "-rf", "/"],
    ])
    def test_extra_args_alt_paths_and_subcommands_rejected(self, argv):
        assert privileged.is_whitelisted(argv) is False

    def test_effective_cmd_refuses_non_whitelisted_under_sudo_mode(self, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        monkeypatch.setenv("AURORA_USE_SUDO", "1")
        from aurora.environment import CommandError
        with pytest.raises(CommandError):
            privileged.effective_cmd(["/usr/sbin/ipsec", "start"])

    def test_restart_and_helper_entries_are_whitelisted(self):
        assert privileged.is_whitelisted(["/usr/bin/systemctl", "restart", "strongswan-starter"])
        assert privileged.is_whitelisted([privileged.HELPER_PATH, "swanctl", "passwd"])

    def test_sudoers_user_name_validated(self):
        with pytest.raises(ValueError):
            privileged.sudoers_text("aurora ALL=(ALL) ALL")


# ================================================================ item 8
class TestMonitorStatus:
    def _patch(self, monkeypatch, *, active, run_rc=0, stdout="", stderr=""):
        monkeypatch.setattr(monitor, "service_active", lambda: active)
        monkeypatch.setattr(monitor, "effective_cmd", lambda argv: argv)
        monkeypatch.setattr(monitor, "run", lambda argv, timeout=15: types.SimpleNamespace(
            returncode=run_rc, stdout=stdout, stderr=stderr))

    def test_running(self, monkeypatch):
        self._patch(monkeypatch, active=True,
                    stdout="Status of IKE charon daemon (strongSwan 5.9.13)\n")
        assert monitor.get_status().daemon_up is True

    def test_stopped_service_reports_down(self, monkeypatch):
        self._patch(monkeypatch, active=False)
        rep = monitor.get_status()
        assert rep.daemon_up is False and rep.errors

    def test_failed_status_is_unknown_not_healthy(self, monkeypatch):
        self._patch(monkeypatch, active=True, run_rc=1, stderr="socket error")
        rep = monitor.get_status()
        assert rep.daemon_up is None and "socket error" in rep.errors[0]

    def test_unexpected_output_is_unknown(self, monkeypatch):
        self._patch(monkeypatch, active=True, stdout="garbage")
        assert monitor.get_status().daemon_up is None

    def test_no_unconditional_true_remains(self):
        assert "or True" not in _read("aurora/monitor.py")


# ================================================================ item 9
class TestStaticConfigValidation:
    def test_validator_never_starts_or_contacts_daemons(self, monkeypatch):
        def boom(*a, **k):
            raise AssertionError("validator must not run any command")
        monkeypatch.setattr(subprocess, "run", boom)
        monkeypatch.setattr(subprocess, "Popen", boom)
        ok, _ = strongswan.validate_conf_static(strongswan.render_conn("203.0.113.5"))
        assert ok is True

    def test_detects_problems(self):
        good = strongswan.render_conn("203.0.113.5")
        assert strongswan.validate_conf_static(good.replace("# aurora-end aurora-ikev2", ""))[0] is False
        assert strongswan.validate_conf_static(good + good)[0] is False
        assert strongswan.validate_conf_static(good.replace("conn aurora-ikev2", "conn other"))[0] is False

    def test_unsafe_validator_removed(self):
        assert not hasattr(strongswan, "validate_ipsec_conf")
        assert "--nofork" not in _read("aurora/strongswan.py")


# ================================================================ item 10
class TestBackendRouting:
    def test_dashboard_uses_selected_backend(self, tmp_path, monkeypatch):
        client = _web_client(tmp_path, monkeypatch)
        _login(client)
        monkeypatch.setattr(aurora_app.strongswan, "stack_layout", lambda: "swanctl")

        def classic_must_not_run():
            raise AssertionError("classic backend used while swanctl is selected")
        monkeypatch.setattr(strongswan, "list_entries", classic_must_not_run)
        monkeypatch.setattr(swanctl_users, "list_entries",
                            lambda: [("swan-user", "enabled")])
        r = client.get("/")
        assert r.status_code == 200
        assert b"<strong>1</strong>" in r.data  # one user, from the swanctl backend

    def test_users_listing_error_is_flashed_not_500(self, tmp_path, monkeypatch):
        client = _web_client(tmp_path, monkeypatch)
        _login(client)
        def fail():
            raise environment.CommandError("helper unavailable")
        monkeypatch.setattr(strongswan, "list_entries", fail)
        r = client.get("/users")
        assert r.status_code == 200 and b"helper unavailable" in r.data
        r = client.get("/")
        assert r.status_code == 200


# ================================================================ item 11
class TestCspConfirmations:
    def test_no_inline_event_handlers_in_templates(self):
        tdir = os.path.join(ROOT, "aurora", "templates")
        for name in os.listdir(tdir):
            if name.endswith(".html"):
                text = _read(os.path.join("aurora", "templates", name))
                assert not re.search(r"\son[a-z]+\s*=", text), name

    def test_confirmations_use_external_script(self):
        base = _read("aurora/templates/base.html")
        assert "confirm.js" in base
        js = _read("aurora/templates/static/confirm.js")
        assert "data-confirm" in js and "preventDefault" in js

    def test_delete_form_requires_typed_username(self):
        users = _read("aurora/templates/users.html")
        assert 'name="confirm"' in users and "type {{ u }}" in users

    def test_server_rejects_mismatched_confirm(self, tmp_path, monkeypatch):
        client = _web_client(tmp_path, monkeypatch)
        _login(client)
        monkeypatch.setattr(swanctl_users, "list_entries", list)
        r = client.post("/users", data={"action": "delete", "username": "alice",
                                        "confirm": "wrong", "csrf": _csrf(client)})
        assert r.status_code == 302


# ================================================================ item 12
class TestDeadCode:
    def test_no_meaningless_admin_count_query(self):
        assert "WHERE 0" not in _read("aurora/app.py")


# ================================================================ item 14
class TestPasswordHashing:
    def test_iteration_count_matches_docs(self):
        assert PBKDF2_ITERS == 600_000
        assert "600,000" in _read("docs/security.md")
        assert "260k" not in _read("docs/security.md")

    def test_legacy_hash_verifies_and_needs_rehash(self):
        legacy = hash_password("LegacyPass1", iterations=260_000)
        assert verify_password("LegacyPass1", legacy)
        assert needs_rehash(legacy)
        assert not needs_rehash(hash_password("CurrentPass1"))

    def test_login_upgrades_legacy_hash(self, tmp_path, monkeypatch):
        db = tmp_path / "upgrade.db"
        monkeypatch.setenv("AURORA_DB", str(db))
        aurora_app.init_db(None)
        conn = sqlite3.connect(db)
        conn.execute("INSERT INTO admin (username, password_hash, must_change) VALUES (?,?,0)",
                     ("admin", hash_password("TestPass123", iterations=260_000)))
        conn.commit()
        conn.close()
        monkeypatch.setenv("AURORA_SECRET_KEY", "k")
        monkeypatch.setenv("AURORA_INSECURE_COOKIES", "1")
        client = aurora_app.create_app().test_client()
        client.post("/login", data={"username": "admin", "password": "TestPass123",
                                    "csrf": _csrf(client)})
        stored = sqlite3.connect(db).execute("SELECT password_hash FROM admin").fetchone()[0]
        assert stored.startswith(f"pbkdf2${PBKDF2_ITERS}$")


# ================================================================ item 15
class TestInstallerReliability:
    def test_no_urandom_pipeline(self):
        text = _read("install.sh")
        assert "/dev/urandom" not in text
        assert "secrets.token_urlsafe" in text

    def test_umask_precedes_secret_file_write(self):
        text = _read("install.sh")
        write_at = text.index('> "$BOOTSTRAP_FILE"')
        umask_at = text.rindex("umask 077", 0, write_at)
        assert umask_at < write_at

    def test_password_never_logged(self):
        text = _read("install.sh")
        assert "initial admin: " not in text
        assert not re.search(r'log[^\n]*\$ADMIN_PASS', text)

    def test_bash_syntax_still_valid(self):
        p = subprocess.run(["bash", "-n", os.path.join(ROOT, "install.sh")],
                           capture_output=True, text=True)
        assert p.returncode == 0, p.stderr


# ----------------------------------------------------------------- helpers

def _seed_admin(db_path, must_change=0, password="TestPass123"):
    conn = sqlite3.connect(db_path)
    aurora_app.init_db(None) if False else None
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK (id = 1),
        username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
        must_change INTEGER NOT NULL DEFAULT 0);
    """)
    conn.execute("DELETE FROM admin")
    conn.execute("INSERT INTO admin (id, username, password_hash, must_change) VALUES (1,?,?,?)",
                 ("admin", hash_password(password), must_change))
    conn.commit()
    conn.close()


def _must_change(tmp_path):
    return sqlite3.connect(tmp_path / "test.db").execute(
        "SELECT must_change FROM admin").fetchone()[0]


def _web_client(tmp_path, monkeypatch, must_change=0):
    monkeypatch.setenv("AURORA_DB", str(tmp_path / "test.db"))
    monkeypatch.setenv("AURORA_SECRET_KEY", "unit-test-key")
    monkeypatch.setenv("AURORA_INSECURE_COOKIES", "1")
    monkeypatch.setattr(monitor, "get_status", lambda: monitor.StatusReport(service_active=True))
    monkeypatch.setattr(strongswan, "list_entries", lambda: [("alice", "enabled")])
    monkeypatch.setattr(strongswan, "stack_layout", lambda: "classic")
    aurora_app.init_db(None)
    _seed_admin(tmp_path / "test.db", must_change=must_change)
    return aurora_app.create_app().test_client()


def _csrf(client):
    r = client.get("/login")
    return re.search(r'name="csrf" value="([0-9a-f]+)"', r.get_data(as_text=True)).group(1)


def _login(client):
    client.post("/login", data={"username": "admin", "password": "TestPass123",
                                "csrf": _csrf(client)})


class TestDeployedPermissions:
    """Static checks that the installer deploys the boundary with the right modes."""

    def test_helper_installed_root_owned_not_writable_by_service_user(self):
        text = _read("install.sh")
        assert ("install -o root -g root -m 0755 \"$INSTALL_DIR/aurora/secrets_helper.py\" \\\n"
                "  /usr/local/libexec/aurora-secrets-helper") in text

    def test_backup_area_is_root_only_outside_service_data_dir(self):
        text = _read("install.sh")
        assert "install -d -o root -g root -m 0700 /var/lib/aurora-secrets-backups" in text
        assert "/var/lib/aurora-secrets-backups" == secrets_helper.BACKUP_DIR

    def test_sudoers_file_is_0440_root(self):
        assert "install -o root -g root -m 0440" in _read("install.sh")

    def test_installer_backup_retention(self):
        text = _read("install.sh")
        assert "tail -n +11" in text

    def test_service_user_cannot_write_helper_or_sudoers(self):
        # The service user owns only $INSTALL_DIR/$BASE_DIR; the helper and
        # sudoers are installed root:root (asserted above) and nothing chowns them.
        text = _read("install.sh")
        assert "chown -R \"$AURORA_USER" in text
        assert "/usr/local/libexec" not in text.split("chown -R \"$AURORA_USER")[1].split("\n")[0]


class TestConnDnsKeyword:
    def test_rendered_conn_uses_rightdns_not_dns(self):
        # Verified against strongSwan 5.9: `dns=` is an unknown ipsec.conf keyword,
        # `rightdns=` parses cleanly.
        block = strongswan.render_conn("203.0.113.5")
        assert "    rightdns=1.1.1.1,1.0.0.1" in block
        assert "\n    dns=" not in block


class TestInstallerConnKeyword:
    def test_installer_conn_block_uses_rightdns(self):
        text = _read("install.sh")
        assert "rightdns=1.1.1.1,1.0.0.1" in text
        assert "\n    dns=" not in text


class TestFirewallPersistence:
    def test_nat_rules_applied_by_boot_unit(self):
        text = _read("install.sh")
        assert "/etc/systemd/system/aurora-nat.service" in text
        assert "WantedBy=multi-user.target" in text
        assert "systemctl enable aurora-nat.service" in text

    def test_nat_script_is_idempotent_and_dynamic_interface(self):
        text = _read("install.sh")
        assert "iptables -t nat -C POSTROUTING" in text
        assert "ip -4 route show default" in text  # interface chosen at boot

    def test_ports_opened_only_when_ufw_active(self):
        text = _read("install.sh")
        block = text.split("ufw is active: opened UDP 500/4500")[0]
        assert 'Status: active" && ' not in block
        assert "ufw allow 500/udp" in text and "ufw route allow from 10.99.0.0/24" in text
        assert "ufw is not active: no OS port changes needed." in text

    def test_raw_forward_rules_only_without_ufw(self):
        text = _read("install.sh")
        assert "if ! ufw status 2>/dev/null | grep -q \"Status: active\"; then" in text
        assert "iptables -I FORWARD 1 -s \"$SUBNET\" -j ACCEPT" in text

    def test_iptables_package_installed(self):
        assert "strongswan-pki libcharon-extra-plugins iptables" in _read("install.sh")

    def test_daemon_reload_failure_is_not_fatal_in_nat_block(self):
        assert 'systemctl daemon-reload || warn' in _read("install.sh")
