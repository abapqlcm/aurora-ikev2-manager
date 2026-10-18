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
    """Exact typed SAN match for the client-facing identity."""
    if not identity:
        return False
    return identity_in_san(identity, server_cert)


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


def parse_certificate(path: str) -> dict:
    """Robust certificate parse via openssl. Returns {} on invalid input.

    Checks: parseable X.509, subject, SAN entries (typed), validity window,
    basicConstraints CA flag optionally. Never accepts "looks like PEM" text.
    """
    p = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-subject"],
                       capture_output=True, text=True, timeout=15)
    san = subprocess.run(["openssl", "x509", "-in", path, "-noout",
                          "-ext", "subjectAltName"],
                         capture_output=True, text=True, timeout=15)
    bc = subprocess.run(["openssl", "x509", "-in", path, "-noout",
                         "-ext", "basicConstraints"],
                        capture_output=True, text=True, timeout=15)
    p.stdout += san.stdout + bc.stdout
    if p.returncode != 0:
        return {}
    import re as _re
    import datetime
    info: dict = {"subject": "", "sans": [], "is_ca": None, "expired": False}
    for line in p.stdout.splitlines():
        if line.startswith("subject="):
            info["subject"] = line.split("=", 1)[1].strip()
        if "CA:" in line:
            info["is_ca"] = "CA:TRUE" in line
        if "Not After" in line or line.startswith("notAfter"):
            info["not_after"] = line.split("=", 1)[-1].strip()
    # SANs are typed: DNS:<name> / IP Address:<addr> / email:<...>
    m = _re.search(r"Subject Alternative Name:\s*(.+)", p.stdout)
    if m:
        for entry in m.group(1).split(","):
            entry = entry.strip()
            if entry.startswith("DNS:"):
                info["sans"].append(("dns", entry[4:].strip()))
            elif entry.startswith("IP Address:"):
                import ipaddress as _ip
                raw = entry[len("IP Address:"):].strip()
                try:
                    info["sans"].append(("ip", str(_ip.ip_address(raw))))
                except ValueError:
                    info["sans"].append(("ip", raw))
            elif entry.startswith("email:"):
                info["sans"].append(("email", entry[6:].strip()))
    # expiry
    q = subprocess.run(["openssl", "x509", "-in", path, "-noout", "-enddate"],
                       capture_output=True, text=True, timeout=15)
    if q.returncode == 0:
        try:
            end = datetime.datetime.strptime(
                q.stdout.split("=", 1)[1].strip(),
                "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
            info["expired"] = end < datetime.datetime.now(datetime.timezone.utc)
        except (ValueError, IndexError):
            info["expired"] = True
    return info


def identity_in_san(identity: str, path: str) -> bool:
    """Exact typed SAN match for IPv4, IPv6 and DNS identities.

    Canonicalizes: IP addresses compared as parsed values (IPv6 compressed
    form), DNS compared case-insensitively. Unsupported forms rejected.
    """
    import re as _re
    import ipaddress as _ip
    identity = identity.strip()
    try:
        ip = _ip.ip_address(identity)
    except ValueError:
        # DNS identity per RFC 5280/1035: letters, digits, hyphen, dots
        if not _re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?"
                             r"(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*",
                             identity):
            return False
        kind = "dns"
        canon = identity.lower().rstrip(".")
    else:
        kind = "ip"
        canon = str(ip)
    info = parse_certificate(path)
    return (kind, canon) in info.get("sans", [])


def ca_bytes(ca_cert: str | None = None) -> bytes:
    """Exact public CA bytes served by the dashboard download.
    Refuses anything that does not parse as a real CA certificate."""
    ca_cert = ca_cert or CA_CERT  # read global at call time (test monkeypatch)
    with open(ca_cert, "rb") as fh:
        data = fh.read()
    info = parse_certificate(ca_cert)
    if not info or info.get("is_ca") is not True or info.get("expired"):
        raise PKIError(f"{ca_cert} is not a valid, unexpired CA certificate")
    return data
