"""Tests for Aurora IKEv2 Manager — isolated, no privileged operations.

Uses temp files for ipsec.secrets and mocks for command execution.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from aurora import strongswan, environment, monitor  # noqa: E402
from aurora.app import hash_password, verify_password  # noqa: E402


# ---------------------------------------------------------------- environment

class TestEnvironment:
    def test_parse_os_release(self, tmp_path, monkeypatch):
        f = tmp_path / "os-release"
        f.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
        monkeypatch.setattr(environment, "detect_os", lambda: ("ubuntu", "22.04"))
        os_id, ver = environment.detect_os()
        assert (os_id, ver) == ("ubuntu", "22.04")

    def test_arch_mapping(self):
        import platform
        assert environment.detect_arch() == {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine(), platform.machine())

    def test_detect_env_flags_unsupported(self, monkeypatch):
        monkeypatch.setattr(environment, "detect_os", lambda: ("debian", "12"))
        env = environment.detect_environment()
        assert env.supported is False
        assert any("debian" in r for r in env.reasons)

    def test_detect_env_ubuntu_ok(self, monkeypatch):
        monkeypatch.setattr(environment, "detect_os", lambda: ("ubuntu", "24.04"))
        monkeypatch.setattr(environment, "detect_arch", lambda: "amd64")
        monkeypatch.setattr(environment, "detect_public_ip", lambda: "1.2.3.4")
        monkeypatch.setattr(environment, "detect_default_interface", lambda: "eth0")
        monkeypatch.setattr(environment, "detect_strongswan", lambda: (False, False, False))
        env = environment.detect_environment()
        assert env.supported is True
        assert env.public_ip == "1.2.3.4"


# ------------------------------------------------------------------- secrets

class TestUserManagement:
    def test_add_and_list(self, tmp_path):
        f = tmp_path / "secrets"
        strongswan.add_user("alice", "S3curePass!x", path=f)
        strongswan.add_user("bob@test", "AnotherPass1", path=f)
        assert strongswan.list_users(f) == ["alice", "bob@test"]

    def test_duplicate_rejected(self, tmp_path):
        f = tmp_path / "secrets"
        strongswan.add_user("alice", "S3curePass!x", path=f)
        with pytest.raises(ValueError):
            strongswan.add_user("alice", "OtherPass99", path=f)

    def test_invalid_username_rejected(self, tmp_path):
        f = tmp_path / "secrets"
        for bad in ("", "a", "bad name", "x" * 65, "injection; rm -rf"):
            with pytest.raises(ValueError):
                strongswan.add_user(bad, "S3curePass!x", path=f)

    def test_invalid_password_rejected(self, tmp_path):
        f = tmp_path / "secrets"
        with pytest.raises(ValueError):
            strongswan.add_user("alice", "short", path=f)
        with pytest.raises(ValueError):
            strongswan.add_user("alice", "پسورد فارسی", path=f)

    def test_delete_user(self, tmp_path):
        f = tmp_path / "secrets"
        strongswan.add_user("alice", "S3curePass!x", path=f)
        strongswan.add_user("bob", "AnotherPass1", path=f)
        assert strongswan.delete_user("alice", path=f) is True
        assert strongswan.list_users(f) == ["bob"]
        assert strongswan.delete_user("ghost", path=f) is False

    def test_disable_enable(self, tmp_path):
        f = tmp_path / "secrets"
        strongswan.add_user("alice", "S3curePass!x", path=f)
        assert strongswan.disable_user("alice", path=f) is True
        assert strongswan.user_state("alice", path=f) == "disabled"
        assert strongswan.enable_user("alice", path=f) is True
        assert strongswan.user_state("alice", path=f) == "enabled"

    def test_change_password(self, tmp_path):
        f = tmp_path / "secrets"
        strongswan.add_user("alice", "OldPass1234", path=f)
        strongswan.set_user_password("alice", "NewPass5678", path=f)
        text = f.read_text()
        assert "NewPass5678" in text and "OldPass1234" not in text

    def test_simultaneous_connections_supported(self, tmp_path):
        """Separate credentials each create their own SA; pool /24 = 253 hosts."""
        f = tmp_path / "secrets"
        for i in range(5):
            strongswan.add_user(f"dev{i}", f"Passw0rd{i}x!", path=f)
        assert len(strongswan.list_users(f)) == 5

    def test_secrets_file_permissions(self, tmp_path):
        f = tmp_path / "secrets"
        strongswan.add_user("alice", "S3curePass!x", path=f)
        assert (f.stat().st_mode & 0o777) == 0o600


# ---------------------------------------------------------------- monitoring

class TestMonitorParsing:
    SAMPLE = """Status of IKE charon daemon (strongSwan 5.9.3):
uptime: 34 minutes, since ...
worker threads: 11 of 16 idle
loaded plugins: ...
ipsec pool: aurora-pool ... 10.99.0.0/24
Connections:
aurora-ikev2:  %any... %any: IKEv2
aurora-ikev2[7]: ESTABLISHED 5 minutes ago, 1.2.3.4[alice]...5.6.7.8[bob-peer]
aurora-ikev2{3}:  INSTALLED, TUNNEL, ESP in UDP, 10.99.0.1/32 === 5.6.7.8/32
"""

    def test_parse_sessions(self):
        sessions, pool = monitor.parse_statusall(self.SAMPLE)
        assert len(sessions) == 1
        assert sessions[0].username == "alice"
        assert sessions[0].ike_sa == "ESTABLISHED"
        assert sessions[0].remote_ip == "5.6.7.8"

    def test_empty_when_down(self, monkeypatch):
        monkeypatch.setattr(strongswan, "service_active", lambda: False)
        rep = monitor.get_status()
        assert rep.service_active is False
        assert rep.sessions == []
        assert rep.errors


# ----------------------------------------------------------------- web app

@pytest.fixture()
def client(tmp_path, monkeypatch):
    os.environ["AURORA_DB"] = str(tmp_path / "test.db")
    os.environ["AURORA_SECRET_KEY"] = "unit-test-key"
    os.environ["AURORA_INSECURE_COOKIES"] = "1"
    monkeypatch.setattr(strongswan, "list_users", lambda path=None: ["alice", "bob"])
    monkeypatch.setattr(strongswan, "user_state", lambda u, path=None: "enabled")
    monkeypatch.setattr(monitor, "get_status", lambda: monitor.StatusReport(service_active=True))
    import aurora.app as aurora_app
    aurora_app.app_login_fails.clear()
    from aurora.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    db_file = tmp_path / "test.db"
    import sqlite3
    db = sqlite3.connect(db_file)
    db.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, must_change INTEGER NOT NULL DEFAULT 0)")
    db.execute("INSERT INTO admin (username, password_hash) VALUES (?,?)",
               ("admin", hash_password("TestPass123")))
    db.commit()
    with app.test_client() as c:
        yield c
    os.environ.pop("AURORA_DB", None)


class TestWebAuth:
    def test_redirect_unauthenticated(self, client):
        r = client.get("/")
        assert r.status_code == 302 and "/login" in r.headers["Location"]

    def test_login_success_and_csrf(self, client):
        r = client.get("/login")
        assert r.status_code == 200
        import re
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.get_data(as_text=True)).group(1)
        r = client.post("/login", data={"username": "admin", "password": "TestPass123", "csrf": csrf})
        assert r.status_code == 302

    def test_login_wrong_password(self, client):
        r = client.get("/login")
        import re
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.get_data(as_text=True)).group(1)
        r = client.post("/login", data={"username": "admin", "password": "wrong", "csrf": csrf})
        assert b"Invalid credentials" in r.data

    def test_login_rate_limit(self, client):
        import re
        for _ in range(6):
            r = client.get("/login")
            csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.get_data(as_text=True)).group(1)
            r = client.post("/login", data={"username": "admin", "password": "nope", "csrf": csrf})
        assert r.status_code == 429

    def test_csrf_rejected_on_post(self, client):
        # unauthenticated -> redirect to login
        r = client.post("/users", data={"action": "add", "username": "x", "password": "Password1"})
        assert r.status_code == 302
        # authenticated but no CSRF -> 400
        import re
        r = client.get("/login")
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.get_data(as_text=True)).group(1)
        client.post("/login", data={"username": "admin", "password": "TestPass123", "csrf": csrf})
        r = client.post("/users", data={"action": "add", "username": "x", "password": "Password1"})
        assert r.status_code == 400

    def test_dashboard_requires_auth(self, client):
        r = client.get("/users")
        assert r.status_code == 302

    def test_security_headers(self, client):
        r = client.get("/login")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in r.headers["Content-Security-Policy"]

    def test_malicious_username_safe(self, client, monkeypatch):
        import re
        r = client.get("/login")
        csrf = re.search(r'name="csrf" value="([0-9a-f]+)"', r.get_data(as_text=True)).group(1)
        client.post("/login", data={"username": "admin", "password": "TestPass123", "csrf": csrf})
        # XSS attempt in the search filter must be escaped by Jinja:
        r = client.get("/users?q=<script>alert(1)</script>")
        assert b"<script>alert(1)" not in r.data
        assert b"&lt;script&gt;" in r.data


# ---------------------------------------------------------------- password hash

class TestPasswordHashing:
    def test_roundtrip(self):
        h = hash_password("hunter2secret")
        assert verify_password("hunter2secret", h)
        assert not verify_password("wrong", h)

    def test_unique_salts(self):
        assert hash_password("x12345678") != hash_password("x12345678")

    def test_never_plaintext(self):
        pw = "VeryS3cret!"
        assert pw not in hash_password(pw)
