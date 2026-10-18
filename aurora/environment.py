"""Aurora IKEv2 Manager — environment detection.

All functions are pure/read-only against the host so they can be unit-tested
with mocks for command output.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import subprocess
from dataclasses import dataclass, field


class CommandError(RuntimeError):
    pass


def run(cmd: list[str], timeout: int = 30) -> subprocess.CompletedProcess:
    """Run a command WITHOUT a shell (no shell injection)."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def run_ok(cmd: list[str], timeout: int = 30) -> str:
    p = run(cmd, timeout=timeout)
    if p.returncode != 0:
        raise CommandError(f"{' '.join(cmd)} failed ({p.returncode}): {p.stderr.strip()[:300]}")
    return p.stdout


def is_root() -> bool:
    return os.geteuid() == 0


@dataclass
class Environment:
    os_id: str = ""
    os_version: str = ""
    arch: str = ""
    supported: bool = False
    reasons: list[str] = field(default_factory=list)
    public_ip: str | None = None
    ip_class: str = "unknown"
    ip_note: str = ""
    default_interface: str | None = None
    has_strongswan: bool = False
    swanctl_available: bool = False
    ipsec_available: bool = False


def detect_os() -> tuple[str, str]:
    """Parse /etc/os-release. Returns (ID, VERSION_ID)."""
    try:
        data = {}
        with open("/etc/os-release", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    k, _, v = line.partition("=")
                    data[k.strip()] = v.strip().strip('"')
        return data.get("ID", ""), data.get("VERSION_ID", "")
    except OSError:
        return "", ""


def detect_arch() -> str:
    m = platform.machine()
    return {"x86_64": "amd64", "aarch64": "arm64"}.get(m, m)


def _classify_ip(ip: str) -> str:
    """'public' | 'private' | 'loopback' | 'link-local' | 'unknown'."""
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_private:
        return "private"
    return "public" if addr.version == 4 else "public"


def detect_public_ip() -> str | None:
    """Return the source IPv4 for outbound traffic (local detection only,
    no external services). May be a private/NATed address — callers must
    classify the result with classify_address()."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.connect(("1.1.1.1", 443))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return None


def classify_address(ip: str | None) -> dict:
    """Classify a detected address: is it routable, private/NATed, etc.

    Returns {"ip": ..., "class": ..., "needs_public_ip": bool, "note": str}.
    A private address behind 1:1 cloud NAT still works for clients reaching
    the server by the cloud IP, but the certificate SAN and leftid must use
    the public cloud IP, not the private one.
    """
    if not ip:
        return {"ip": None, "class": "unknown", "needs_public_ip": True,
                "note": "no outbound address detected"}
    cls = _classify_ip(ip)
    if cls == "public":
        return {"ip": ip, "class": "public", "needs_public_ip": False,
                "note": "public address detected"}
    return {"ip": ip, "class": cls, "needs_public_ip": True,
            "note": f"{cls} address — likely behind cloud NAT; pass the "
                    "public cloud IP explicitly via --public-ip so certificate "
                    "SAN and leftid match what clients connect to"}


def detect_default_interface() -> str | None:
    """Read default route interface from /proc/net/route (no ip command needed)."""
    try:
        with open("/proc/net/route", encoding="ascii") as fh:
            for line in fh.readlines()[1:]:
                parts = line.split()
                if len(parts) > 7 and parts[1] == "00000000" and parts[7] == "00000003":
                    return parts[0]
    except OSError:
        pass
    return None


def detect_strongswan() -> tuple[bool, bool, bool]:
    """(installed, swanctl available, ipsec available)."""
    swanctl = shutil.which("swanctl") is not None
    ipsec = shutil.which("ipsec") is not None
    installed = swanctl or ipsec or os.path.isdir("/etc/ipsec.d") or os.path.isdir("/etc/swanctl")
    return installed, swanctl, ipsec


def detect_environment() -> Environment:
    env = Environment()
    env.os_id, env.os_version = detect_os()
    env.arch = detect_arch()
    env.public_ip = detect_public_ip()
    _cls = classify_address(env.public_ip)
    env.ip_class = _cls["class"]
    env.ip_note = _cls["note"]
    env.default_interface = detect_default_interface()
    env.has_strongswan, env.swanctl_available, env.ipsec_available = detect_strongswan()

    if env.os_id != "ubuntu":
        env.reasons.append(f"unsupported distribution: {env.os_id or 'unknown'} (Ubuntu required)")
    else:
        major = env.os_version.split(".")[0]
        if major.isdigit() and int(major) < 20:
            env.reasons.append(f"Ubuntu {env.os_version} is too old (20.04+ required)")
    if env.arch not in ("amd64", "arm64"):
        env.reasons.append(f"unsupported architecture: {env.arch}")
    if env.supported is False and not env.reasons:
        env.supported = True
    env.supported = len(env.reasons) == 0
    return env


# ---------------- existing strongSwan inspection ----------------

@dataclass
class ExistingConfig:
    auth_methods: list[str] = field(default_factory=list)
    eap_users: list[str] = field(default_factory=list)   # names only, never secrets
    connections: list[str] = field(default_factory=list)
    pools: list[str] = field(default_factory=list)
    ca_certs: list[str] = field(default_factory=list)
    uses_swanctl: bool = False
    service_active: bool = False
    warnings: list[str] = field(default_factory=list)


def _strip_comments(text: str) -> str:
    return re.sub(r"[#].*$", "", text, flags=re.M)


def parse_ipsec_conf(text: str) -> ExistingConfig:
    """Parse classic /etc/ipsec.conf (safe, read-only)."""
    cfg = ExistingConfig()
    text = _strip_comments(text)
    cur_conn = None
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^(\S+)\s+(.+)$", line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if key in ("conn", "ca"):
            cur_conn = val
            if key == "conn":
                cfg.connections.append(val)
            continue
        if cur_conn and key == "authby":
            if "eap" not in cfg.auth_methods:
                cfg.auth_methods.append("authby:" + val)
        if cur_conn and key == "leftauth":
            cfg.auth_methods.append("leftauth:" + val)
        if cur_conn and key == "eap_identity":
            if "eap-mschapv2" not in cfg.auth_methods:
                cfg.auth_methods.append("eap (leftauth/eap)")
    return cfg


def parse_ipsec_secrets_usernames(text: str) -> list[str]:
    """Extract EAP usernames from ipsec.secrets (names only — never values)."""
    users = []
    for line in _strip_comments(text).splitlines():
        m = re.match(r'\s*"?([A-Za-z0-9._@+-]+)"?\s*:\s*EAP\s', line, re.I)
        if m:
            users.append(m.group(1))
    return users


def parse_swanctl_conf(text: str) -> ExistingConfig:
    cfg = ExistingConfig()
    cfg.uses_swanctl = True
    text = _strip_comments(text)
    section = None
    for line in text.splitlines():
        line = line.strip()
        m = re.match(r"^([A-Za-z-]+)\s+(\S+)\s*\{", line)
        if m:
            section, name = m.group(1), m.group(2)
            if section == "connections":
                cfg.connections.append(name)
            if section == "pools":
                cfg.pools.append(name)
            continue
        if line.startswith("}"):
            section = None
            continue
        if section == "connections" and re.match(r"^local[\d-]*\s*\.\s*auth\s*=", line):
            cfg.auth_methods.append(line.split("=", 1)[1].strip())
    return cfg


def inspect_existing() -> ExistingConfig:
    """Best-effort read-only inspection of a live strongSwan installation."""
    cfg = ExistingConfig()
    ipsec_conf = "/etc/ipsec.conf"
    ipsec_secrets = "/etc/ipsec.secrets"
    swanctl_conf = "/etc/swanctl/swanctl.conf"

    if os.path.exists(swanctl_conf):
        cfg = parse_swanctl_conf(open(swanctl_conf, encoding="utf-8", errors="replace").read())
    elif os.path.exists(ipsec_conf):
        cfg = parse_ipsec_conf(open(ipsec_conf, encoding="utf-8", errors="replace").read())
        if os.path.exists(ipsec_secrets):
            cfg.eap_users = parse_ipsec_secrets_usernames(
                open(ipsec_secrets, encoding="utf-8", errors="replace").read())

    for d in ("/etc/ipsec.d/cacerts", "/etc/swanctl/x509ca"):
        if os.path.isdir(d):
            cfg.ca_certs = [f for f in os.listdir(d) if f.endswith((".pem", ".crt", ".cer"))]

    p = run(["systemctl", "is-active", "strongswan-starter"])
    if p.returncode != 0:
        p = run(["systemctl", "is-active", "strongswan"])
    cfg.service_active = p.stdout.strip() == "active"
    return cfg
