"""User management through the real panel->helper client path (classic and swanctl).

Calls go through aurora.strongswan / aurora.swanctl_users exactly as the web app
does; only the root boundary is replaced by tests/helpers_fake.FakeHelper, which
dispatches to the real helper logic on temporary files.
"""
import pytest

from aurora import secrets_helper, strongswan, swanctl_users
from aurora.environment import CommandError
from tests.helpers_fake import FakeHelper


@pytest.fixture()
def fake(tmp_path, monkeypatch):
    return FakeHelper(tmp_path, monkeypatch)


class TestClassicUserManagement:
    def test_add_and_list(self, fake):
        strongswan.add_user("alice", "S3curePass!x")
        strongswan.add_user("bob@test", "AnotherPass1")
        assert strongswan.list_users() == ["alice", "bob@test"]

    def test_duplicate_rejected(self, fake):
        strongswan.add_user("alice", "S3curePass!x")
        with pytest.raises(ValueError):
            strongswan.add_user("alice", "OtherPass99")

    def test_invalid_username_rejected(self, fake):
        for bad in ("", "a", "bad name", "x" * 65, "injection; rm -rf"):
            with pytest.raises(ValueError):
                strongswan.add_user(bad, "S3curePass!x")
        assert not fake.classic_path.exists() or fake.classic_path.read_text() == ""

    def test_invalid_password_rejected(self, fake):
        for bad in ("short", "پسورد فارسی"):
            with pytest.raises(ValueError):
                strongswan.add_user("alice", bad)

    def test_delete_user(self, fake):
        strongswan.add_user("alice", "S3curePass!x")
        strongswan.add_user("bob", "AnotherPass1")
        assert strongswan.delete_user("alice") is True
        assert strongswan.list_users() == ["bob"]
        assert strongswan.delete_user("ghost") is False

    def test_disable_enable(self, fake):
        strongswan.add_user("alice", "S3curePass!x")
        assert strongswan.disable_user("alice") is True
        assert strongswan.user_state("alice") == "disabled"
        assert strongswan.enable_user("alice") is True
        assert strongswan.user_state("alice") == "enabled"

    def test_change_password(self, fake):
        strongswan.add_user("alice", "OldPass1234")
        strongswan.set_user_password("alice", "NewPass5678")
        text = fake.classic_path.read_text()
        assert "NewPass5678" in text and "OldPass1234" not in text

    def test_five_users(self, fake):
        for i in range(5):
            strongswan.add_user(f"dev{i}", f"Passw0rd{i}x!")
        assert len(strongswan.list_users()) == 5

    def test_secrets_file_permissions(self, fake):
        strongswan.add_user("alice", "S3curePass!x")
        assert (fake.classic_path.stat().st_mode & 0o777) == 0o600

    def test_helper_failure_surfaces_as_command_error(self, fake):
        fake.fail_reload = True
        with pytest.raises(CommandError, match="rolled back"):
            strongswan.add_user("alice", "S3curePass!x")
        assert not fake.classic_path.exists() or "alice" not in fake.classic_path.read_text()


class TestSwanctlUserManagement:
    @pytest.fixture(autouse=True)
    def seed(self, fake):
        fake.swanctl_path.write_text('"existing-user" : EAP "ExistingPw99"\n')
        self.fake = fake

    def test_add_user(self):
        swanctl_users.add_user("alice", "S3curePass!x")
        assert swanctl_users.list_users() == ["existing-user", "alice"]

    def test_delete_only_target_user(self):
        swanctl_users.add_user("alice", "S3curePass!x")
        swanctl_users.add_user("bob", "BobsPass1234")
        assert swanctl_users.delete_user("alice") is True
        assert swanctl_users.list_users() == ["existing-user", "bob"]
        text = self.fake.swanctl_path.read_text()
        assert '"existing-user" : EAP "ExistingPw99"' in text
        assert "alice" not in text

    def test_delete_missing_returns_false(self):
        assert swanctl_users.delete_user("ghost") is False

    def test_password_change(self):
        swanctl_users.add_user("alice", "S3curePass!x")
        swanctl_users.set_user_password("alice", "NewPass99xyz")
        text = self.fake.swanctl_path.read_text()
        assert "NewPass99xyz" in text and "S3curePass" not in text

    def test_disable_enable(self):
        swanctl_users.add_user("alice", "S3curePass!x")
        assert swanctl_users.disable_user("alice") is True
        assert swanctl_users.user_state("alice") == "disabled"
        assert swanctl_users.enable_user("alice") is True
        assert swanctl_users.user_state("alice") == "enabled"

    def test_reload_failure_restores_existing_state(self):
        self.fake.fail_reload = True
        with pytest.raises(CommandError):
            swanctl_users.add_user("alice", "S3curePass!x")
        text = self.fake.swanctl_path.read_text()
        assert "alice" not in text and "ExistingPw99" in text

    def test_eap_configured_check(self, tmp_path):
        conf = tmp_path / "swanctl.conf"
        conf.write_text('connections { vpn { remote-1 { auth = eap-mschapv2; } } }\n')
        assert swanctl_users.check_eap_configured(str(conf))[0] is True
        conf.write_text('connections { vpn { remote-1 { auth = pubkey; } } }\n')
        ok, detail = swanctl_users.check_eap_configured(str(conf))
        assert ok is False and "does not edit swanctl.conf" in detail
        assert swanctl_users.check_eap_configured(str(tmp_path / "missing"))[0] is False

    def test_resolve_prefers_aurora_then_existing(self, tmp_path):
        d = tmp_path / "secrets"
        d.mkdir()
        (d / "other.secrets").write_text('"x" : EAP "pw12345678"\n')
        assert secrets_helper.resolve_swanctl_path(str(d)) == str(d / "other.secrets")
        (d / "aurora.secrets").write_text("")
        assert secrets_helper.resolve_swanctl_path(str(d)) == str(d / "aurora.secrets")
