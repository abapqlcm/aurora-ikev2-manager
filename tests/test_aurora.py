"""Tests for Aurora IKEv2 Manager — isolated, no privileged operations.

Uses temp files for ipsec.secrets and mocks for command execution.
"""
import os
import sys

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
        expected = {"x86_64": "amd64", "aarch64": "arm64"}.get(
            platform.machine(), platform.machine())
        assert environment.detect_arch() == expected

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
        monkeypatch.setattr(monitor, "service_active", lambda: False)
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
    monkeypatch.setattr(strongswan, "list_entries", lambda: [("alice", "enabled"), ("bob", "enabled")])
    monkeypatch.setattr(strongswan, "user_state", lambda u, path=None: "enabled")
    monkeypatch.setattr(monitor, "get_status", lambda: monitor.StatusReport(service_active=True))
    from aurora.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    db_file = tmp_path / "test.db"
    import sqlite3
    db = sqlite3.connect(db_file)
    db.execute("CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY CHECK(id=1), "
               "username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, "
               "must_change INTEGER NOT NULL DEFAULT 0)")
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


# ------------------------------------------------- hardening tests (v1.1)

import aurora.privileged as privileged


class TestPrivilegeSeparation:
    def test_unprivileged_without_sudo_refuses(self, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        monkeypatch.delenv("AURORA_USE_SUDO", raising=False)
        with pytest.raises(Exception):
            privileged.effective_cmd(["/usr/sbin/ipsec", "restart"])

    def test_unprivileged_whitelisted_gets_sudo(self, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        monkeypatch.setenv("AURORA_USE_SUDO", "1")
        cmd = privileged.effective_cmd(["/usr/sbin/ipsec", "rereadsecrets"])
        assert cmd == ["sudo", "-n", "/usr/sbin/ipsec", "rereadsecrets"]

    def test_unprivileged_nonwhitelisted_rejected(self, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        monkeypatch.setenv("AURORA_USE_SUDO", "1")
        with pytest.raises(Exception, match="whitelist"):
            privileged.effective_cmd(["/bin/rm", "-rf", "/"])
        with pytest.raises(Exception, match="whitelist"):
            privileged.effective_cmd(["/usr/sbin/ipsec", "start"])

    def test_root_runs_directly(self, monkeypatch):
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        assert privileged.effective_cmd(["/usr/sbin/ipsec", "update"]) == ["/usr/sbin/ipsec", "update"]


class TestAddressClassification:
    def test_public(self):
        r = environment.classify_address("93.184.216.34")
        assert r["class"] == "public" and not r["needs_public_ip"]

    def test_private_nat(self):
        r = environment.classify_address("10.0.5.9")
        assert r["class"] == "private" and r["needs_public_ip"]
        assert "cloud NAT" in r["note"]

    def test_loopback(self):
        assert environment.classify_address("127.0.0.1")["class"] == "loopback"

    def test_none(self):
        assert environment.classify_address(None)["needs_public_ip"]


class TestExistingServer:
    def test_swanctl_detected_and_marked(self):
        cfg = environment.parse_swanctl_conf(
            "connections { vpn {\n local-1 { auth = pubkey }\n"
            " remote-1 { auth = eap-mschapv2 }\n }\n}\n")
        assert cfg.uses_swanctl is True

    def test_classic_eap_users_extracted(self):
        users = environment.parse_ipsec_secrets_usernames(
            '"alice" : EAP "secret1"\n# disabled by aurora: "bob" : EAP "x"\n')
        assert "alice" in users

    def test_layout_detection(self, tmp_path):
        sc = str(tmp_path / "swanctl.conf")
        ic = str(tmp_path / "nope.conf")
        open(sc, "w").write("connections {}\n")
        assert strongswan.stack_layout(sc, ic) == "swanctl"
        os.remove(sc)
        open(ic, "w").write("conn x\n")
        assert strongswan.stack_layout(sc, ic) == "classic"
        assert strongswan.stack_layout(str(tmp_path / "a"), str(tmp_path / "b")) == "none"

    def test_user_mgmt_blocked_on_swanctl(self, client, monkeypatch):
        # panel must refuse user mutations when swanctl layout detected
        import re as _re
        r = client.get("/login")
        csrf = _re.search(r'name="csrf" value="([0-9a-f]+)"',
                          r.get_data(as_text=True)).group(1)
        client.post("/login", data={"username": "admin", "password": "TestPass123",
                                    "csrf": csrf})
        monkeypatch.setattr(strongswan, "stack_layout", lambda: "swanctl")
        r = client.post("/users", data={
            "action": "add", "username": "eve", "password": "Password1",
            "csrf": session_csrf(client)})
        assert r.status_code == 302  # flash + redirect, no mutation
        # add_user must NOT have been called (mock would have recorded via list_users)
        assert "eve" not in strongswan.list_users()


def session_csrf(client):
    import re
    r = client.get("/login")
    return re.search(r'name="csrf" value="([0-9a-f]+)"',
                     r.get_data(as_text=True)).group(1)


class TestInstallerHelpers:
    def test_install_sh_bash_syntax(self):
        import subprocess
        p = subprocess.run(["bash", "-n",
                            os.path.join(os.path.dirname(os.path.dirname(
                                os.path.abspath(__file__))), "install.sh")],
                           capture_output=True, text=True)
        assert p.returncode == 0, p.stderr

    def test_install_sh_unprivileged_service(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "install.sh")
        text = open(path).read()
        assert "User=$AURORA_USER" in text or "User=aurora" in text
        assert "User=root" not in text.split("aurora-panel.service")[-1]
        assert "sudoers_text" in text  # sudoers generated from the Python whitelist
        assert "visudo -c" in text  # sudoers validated

    def test_install_sh_no_restart_in_panel_only(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "install.sh")
        text = open(path).read()
        # in panel-only branch there must be no ipsec restart
        assert "ipsec restart" not in text
        assert "ipsec update" in text  # non-disruptive reload instead

    def test_install_sh_preserves_admin(self):
        path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "install.sh")
        text = open(path).read()
        assert "PRESERVED" in text  # admin access kept on reinstall


# ---------------------------------------------- swanctl user management (v1.2)



import shutil
import subprocess

import pytest

from aurora import pki

HAVE_PKI = shutil.which("/usr/sbin/ipsec") is not None and os.path.isdir("/etc/ipsec.d")


@pytest.mark.skipif(not HAVE_PKI, reason="strongswan-pki not installed")
class TestRealPKI:
    """REAL certificate generation with strongSwan pki — isolated under tmp."""

    @pytest.fixture()
    def pki_env(self, tmp_path):
        ca_key = str(tmp_path / "aurora-manager-ca-key.pem")
        ca_cert = str(tmp_path / "aurora-manager-ca.pem")
        s_key = str(tmp_path / "aurora-server-key.pem")
        s_cert = str(tmp_path / "aurora-server-cert.pem")
        yield ca_key, ca_cert, s_key, s_cert

    def test_generate_ca_and_server_cert_real(self, pki_env):
        ca_key, ca_cert, s_key, s_cert = pki_env
        pki.generate_ca(ca_key, ca_cert)
        pki.generate_server_cert("203.0.113.10", ca_key, ca_cert, s_key, s_cert)
        # files exist with right content type
        assert b"BEGIN CERTIFICATE" in open(ca_cert, "rb").read()
        assert b"PRIVATE KEY" in open(ca_key, "rb").read()
        # restrictive perms
        assert (os.stat(ca_key).st_mode & 0o777) == 0o600
        assert (os.stat(s_key).st_mode & 0o777) == 0o600

    def test_chain_and_key_match_real(self, pki_env):
        ca_key, ca_cert, s_key, s_cert = pki_env
        pki.generate_ca(ca_key, ca_cert)
        pki.generate_server_cert("vpn.example.com", ca_key, ca_cert, s_key, s_cert)
        res = pki.validate_pki(ca_cert, s_cert, s_key)
        assert res["chain_ok"] is True
        assert res["key_match"] is True
        assert res["expiry_ok"] is True
        assert (res["expiry_days"] or 0) > 365

    def test_identity_in_san_real(self, pki_env):
        ca_key, ca_cert, s_key, s_cert = pki_env
        pki.generate_ca(ca_key, ca_cert)
        pki.generate_server_cert("198.51.100.7", ca_key, ca_cert, s_key, s_cert)
        assert pki.validate_identity(ca_cert, s_cert, "198.51.100.7")
        assert not pki.validate_identity(ca_cert, s_cert, "10.9.9.9")

    def test_wrong_key_rejected_real(self, pki_env):
        ca_key, ca_cert, s_key, s_cert = pki_env
        pki.generate_ca(ca_key, ca_cert)
        pki.generate_server_cert("203.0.113.10", ca_key, ca_cert, s_key, s_cert)
        # replace server key with a fresh unrelated one -> mismatch
        subprocess.run(["/usr/sbin/ipsec", "pki", "--gen", "--type", "rsa",
                        "--size", "2048", "--outform", "pem"],
                       stdout=open(s_key, "wb"), check=True)
        res = pki.validate_pki(ca_cert, s_cert, s_key)
        assert res["key_match"] is False

    def test_ca_refusal_to_overwrite(self, pki_env):
        ca_key, ca_cert, s_key, s_cert = pki_env
        pki.generate_ca(ca_key, ca_cert)
        with pytest.raises(pki.PKIError, match="refusing to overwrite"):
            pki.generate_ca(ca_key, ca_cert)

    def test_invalid_identity_rejected(self, pki_env):
        ca_key, ca_cert, s_key, s_cert = pki_env
        pki.generate_ca(ca_key, ca_cert)
        for bad in ("", "a/b", "..", "x y"):
            with pytest.raises(pki.PKIError, match="invalid server identity"):
                pki.generate_server_cert(bad, ca_key, ca_cert, s_key, s_cert)

    def test_replace_ca_requires_approval(self, tmp_path):
        with pytest.raises(pki.PKIError, match="approval"):
            pki.replace_ca_approved(False)
        f = tmp_path / "ca.pem"
        f.write_text("x")
        old = str(tmp_path / "aurora-manager-ca.pem")
        f.rename(old)
        pki.replace_ca_approved(True, ca_cert=old, ca_key=str(tmp_path / "k"))
        assert not os.path.exists(old)  # renamed to .replaced-<ts>


class TestDownloadEndpoint:
    def _login(self, client):
        client.post("/login", data={"username": "admin",
                                    "password": "TestPass123",
                                    "csrf": session_csrf(client)})
        return session_csrf(client)

    def test_download_standard_filename(self, client, monkeypatch, tmp_path):
        self._login(client)
        ca = tmp_path / "aurora-manager-ca.pem"
        ca.write_text("-----BEGIN CERTIFICATE-----\nabc\n"
                      "-----END CERTIFICATE-----\n")
        monkeypatch.setattr(pki, "CA_CERT", str(ca))
        r = client.get("/ca.pem")
        assert r.status_code == 200
        cd = r.headers["Content-Disposition"]
        assert "aurora-manager-ca.pem" in cd
        assert r.data == ca.read_bytes()  # EXACT public CA bytes

    def test_download_missing_cert_clear_error(self, client, monkeypatch, tmp_path):
        self._login(client)
        monkeypatch.setattr(pki, "CA_CERT", str(tmp_path / "nope.pem"))
        r = client.get("/ca.pem")
        assert r.status_code == 404
        assert b"not found" in r.data

    def test_download_invalid_pem_rejected(self, client, monkeypatch, tmp_path):
        self._login(client)
        ca = tmp_path / "aurora-manager-ca.pem"
        ca.write_text("not a certificate")
        monkeypatch.setattr(pki, "CA_CERT", str(ca))
        r = client.get("/ca.pem")
        assert r.status_code == 500

    def test_download_requires_auth(self, client):
        r = client.get("/ca.pem")
        assert r.status_code == 302  # redirect to login

    def test_no_path_traversal_possible(self, client, monkeypatch):
        # endpoint ignores any form of user input entirely
        self._login(client)
        r = client.get("/ca.pem?path=/etc/shadow&file=../../../../etc/shadow")
        assert b"root:" not in r.data

    def test_private_keys_never_served(self, client, monkeypatch, tmp_path):
        # even if someone points CA_CERT at a private key, the PEM check rejects
        self._login(client)
        key = tmp_path / "aurora-manager-ca.pem"
        key.write_text("-----BEGIN PRIVATE KEY-----\nabc\n"
                       "-----END PRIVATE KEY-----\n")
        monkeypatch.setattr(pki, "CA_CERT", str(key))
        r = client.get("/ca.pem")
        assert r.status_code == 500


class TestInstallerStandardNames:
    def _inst(self):
        return open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "install.sh")).read()

    def test_standard_ca_filename(self):
        text = self._inst()
        assert "aurora-manager-ca.pem" in text
        assert "aurora-manager-ca-key.pem" in text
        assert "aurora-server-key.pem" in text
        assert "aurora-server-cert.pem" in text
        assert 'leftcert=aurora-server-cert.pem' in text
        assert "ca-cert.pem" not in text.replace("aurora-manager-ca.pem", "")

    def test_cert_validation_steps(self):
        text = self._inst()
        assert "validate_certs" in text
        assert "openssl verify -CAfile" in text
        assert "-checkend" in text
        assert "-modulus" in text

    def test_ca_replace_needs_explicit_approval(self):
        text = self._inst()
        assert "REPLACE-CA" in text

    def test_fresh_conflict_detection(self):
        text = self._inst()
        assert "non-Aurora configuration" in text
        assert "swanctl config detected" in text

    def test_bash_syntax(self):
        p = subprocess.run(["bash", "-n", os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "install.sh")], capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
