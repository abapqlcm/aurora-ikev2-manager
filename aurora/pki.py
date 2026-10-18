"""Aurora IKEv2 Manager — PKI lifecycle.

Standard filenames (single source of truth):
- CA private key:   /etc/ipsec.d/private/aurora-manager-ca-key.pem   (0600)
- CA certificate:   /etc/ipsec.d/cacerts/aurora-manager-ca.pem        (0644)
- Server key:       /etc/ipsec.d/private/aurora-server-key.pem        (0600)
- Server cert:      /etc/ipsec.d/certs/aurora-server-cert.pem         (0644)

Storage location follows the strongSwan standard directory so charon loads
the cert natively; the DOWNLOAD name is `aurora-manager-ca.pem` and matches
the on-disk public CA byte-for-byte (same file, not a copy that can drift).

Validation: `ipsec pki --verify` for the chain, openssl for expiry/key match.
"""
from __future__ import annotations

import os
import subprocess

CA_KEY = "/etc/ipsec.d/private/aurora-manager-ca-key.pem"
CA_CERT = "/etc/ipsec.d/cacerts/aurora-manager-ca.pem"
SERVER_KEY = "/etc/ipsec.d/private/aurora-server-key.pem"
SERVER_CERT = "/etc/ipsec.d/certs/aurora-server-cert.pem"
DOWNLOAD_NAME = "aurora-manager-ca.pem"


class PKIError(RuntimeError):
    pass


def _pki(args: list[str], stdin: bytes | None = None) -> bytes:
    p = subprocess.run(["/usr/sbin/ipsec", "pki", *args],
                       input=stdin, capture_output=True, timeout=60)
    if p.returncode != 0:
        raise PKIError(f"ipsec pki {' '.join(args)} failed: "
                       f"{p.stderr.decode(errors='replace')[:300]}")
    return p.stdout


def ca_exists(ca_cert: str = CA_CERT) -> bool:
    return os.path.isfile(ca_cert)


def generate_ca(ca_key: str = CA_KEY, ca_cert: str = CA_CERT,
                dn: str = "CN=Aurora VPN Manager CA") -> None:
    """Generate a 4096-bit RSA CA. Fails if one already exists (use replace_ca)."""
    for p in (ca_key, ca_cert):
        if os.path.exists(p):
            raise PKIError(f"refusing to overwrite existing CA file: {p}")
    os.makedirs(os.path.dirname(ca_key), mode=0o700, exist_ok=True)
    os.makedirs(os.path.dirname(ca_cert), mode=0o755, exist_ok=True)
    key = _pki(["--gen", "--type", "rsa", "--size", "4096", "--outform", "pem"])
    with open(ca_key, "wb") as fh:
        fh.write(key)
    os.chmod(ca_key, 0o600)
    cert = _pki(["--self", "--ca", "--lifetime", "3650",
                 "--in", ca_key, "--type", "rsa", "--dn", dn,
                 "--outform", "pem"])
    with open(ca_cert, "wb") as fh:
        fh.write(cert)
    os.chmod(ca_cert, 0o644)


def generate_server_cert(identity: str, ca_key: str = CA_KEY,
                         ca_cert: str = CA_CERT, server_key: str = SERVER_KEY,
                         server_cert: str = SERVER_CERT,
                         lifetime_days: int = 1200) -> None:
    """Server cert with SAN = identity (IP or hostname) and serverAuth flag.

    `identity` MUST be what clients enter as the server address so the
    strongSwan Android app can validate it against the SAN.
    """
    import re as _re
    if not identity or not _re.fullmatch(
            r"[A-Za-z0-9.:-]{1,253}", identity) or identity.startswith("."):
        raise PKIError(f"invalid server identity: {identity!r}")
    if not (os.path.isfile(ca_key) and os.path.isfile(ca_cert)):
        raise PKIError("CA missing — generate it first")
    os.makedirs(os.path.dirname(server_key), mode=0o700, exist_ok=True)
    os.makedirs(os.path.dirname(server_cert), mode=0o755, exist_ok=True)
    key = _pki(["--gen", "--type", "rsa", "--size", "2048", "--outform", "pem"])
    with open(server_key, "wb") as fh:
        fh.write(key)
    os.chmod(server_key, 0o600)
    pub = _pki(["--pub", "--in", server_key, "--type", "rsa"])
    san = f"--san={identity}"
    cert = _pki(["--issue", san, f"--san=@{identity}",
                 "--flag", "serverAuth", "--lifetime", str(lifetime_days),
                 "--cacert", ca_cert, "--cakey", ca_key,
                 "--dn", f"CN={identity}", "--outform", "pem"], stdin=pub)
    with open(server_cert, "wb") as fh:
        fh.write(cert)
    os.chmod(server_cert, 0o644)


def validate_pki(ca_cert: str = CA_CERT, server_cert: str = SERVER_CERT,
                 server_key: str = SERVER_KEY) -> dict:
    """Chain verification, expiry check, cert/key correspondence.

    Returns {"chain_ok": bool, "expiry_days": int|None, "key_match": bool,
             "san_matches": {identity: bool}} — raises PKIError on tool failure.
    """
    out: dict = {"chain_ok": False, "expiry_days": None,
                 "key_match": False, "san_matches": {}}
    # chain: verify server cert against the CA (openssl — portable)
    p = subprocess.run(["openssl", "verify", "-CAfile", ca_cert, server_cert],
                       capture_output=True, timeout=30)
    out["chain_ok"] = p.returncode == 0 and b": OK" in p.stdout
    # expiry via openssl
    p = subprocess.run(["openssl", "x509", "-in", server_cert, "-noout",
                        "-checkend", str(30 * 86400)],
                       capture_output=True, timeout=15)
    out["expiry_ok"] = p.returncode == 0
    p = subprocess.run(["openssl", "x509", "-in", server_cert, "-noout",
                        "-enddate"], capture_output=True, text=True, timeout=15)
    if p.returncode == 0:
        try:
            import datetime
            date_str = p.stdout.split("=", 1)[1].strip()
            end = datetime.datetime.strptime(
                date_str, "%b %d %H:%M:%S %Y %Z").replace(
                tzinfo=datetime.timezone.utc)
            out["expiry_days"] = max(
                0, (end - datetime.datetime.now(datetime.timezone.utc)).days)
        except (ValueError, IndexError):
            pass
    # cert/key correspondence: modulus comparison
    def _mod(path: str, is_cert: bool) -> str:
        args = (["openssl", "x509", "-in", path, "-noout", "-modulus"] if is_cert
                else ["openssl", "rsa", "-in", path, "-noout", "-modulus"])
        q = subprocess.run(args, capture_output=True, text=True, timeout=15)
        if q.returncode != 0:
            raise PKIError(f"cannot read modulus from {path}")
        return q.stdout.strip().split("=", 1)[1]
    out["key_match"] = _mod(server_cert, True) == _mod(server_key, False)
    return out


def validate_identity(ca_cert: str = CA_CERT, server_cert: str = SERVER_CERT,
                      identity: str | None = None) -> bool:
    """True if identity is present in the server cert SAN (via pki --verify)."""
    if not identity:
        return False
    p = subprocess.run(
        ["openssl", "x509", "-in", server_cert, "-noout",
         "-ext", "subjectAltName"],
        capture_output=True, text=True, timeout=30)
    if p.returncode != 0:
        return False
    import re as _re
    sans = _re.findall(r"(?:DNS|IP Address):([^,\s]+)", p.stdout)
    return identity in sans or f"@{identity}" in p.stdout


def replace_ca_approved(approved: bool, ca_key: str = CA_KEY,
                        ca_cert: str = CA_CERT, server_key: str = SERVER_KEY,
                        server_cert: str = SERVER_CERT) -> None:
    """Controlled CA replacement: explicit approval required, old files
    backed up with a .replaced-<ts> suffix first. Server cert/key are
    invalidated together (they chain to the replaced CA)."""
    if not approved:
        raise PKIError("CA replacement requires explicit approval")
    import time
    ts = int(time.time())
    for p in (ca_key, ca_cert, server_key, server_cert):
        if os.path.exists(p):
            try:
                os.replace(p, f"{p}.replaced-{ts}")
            except OSError as e:
                raise PKIError(f"cannot replace {p}: {e}")


def ca_bytes(ca_cert: str = CA_CERT) -> bytes:
    """Exact public CA bytes served by the dashboard download."""
    with open(ca_cert, "rb") as fh:
        return fh.read()
