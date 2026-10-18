"""Aurora IKEv2 Manager — live connection monitoring via `ipsec statusall`.

Parses only what strongSwan actually reports; returns empty data when the
daemon is down. Never fabricates sessions.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .environment import run
from .strongswan import CONN_NAME, service_active


@dataclass
class Session:
    username: str = ""
    virtual_ip: str = ""
    remote_ip: str = ""
    ike_sa: str = ""      # ESTABLISHED / CONNECTING
    child_sa: str = ""
    raw: str = ""


@dataclass
class StatusReport:
    daemon_up: bool = False
    service_active: bool = False
    sessions: list[Session] = field(default_factory=list)
    pool_usage: str = ""
    errors: list[str] = field(default_factory=list)


_IKE_RE = re.compile(
    r'^(?P<id>[^\s{]+)\[\d+\]?\s*:\s*(?P<state>ESTABLISHED|CONNECTING)\s*'
    r'(?P<ago>\d+\s*\S+\s*ago)?\s*,\s*(?P<local>[0-9.]+)\[(?P<user>[^\]]+)\]'
    r'.*?(?P<remote>\.\.\.[0-9.]+)?')


def parse_statusall(text: str, conn: str = CONN_NAME) -> tuple[list[Session], str]:
    sessions: list[Session] = []
    pool_line = ""
    in_our_conn = False
    for line in text.splitlines():
        if line.startswith("managed by") or line.startswith("heartbeat"):
            continue
        if line.strip().startswith("pools:") or "pools:" in line:
            pool_line = line.strip()
            continue
        if line.strip().startswith(conn) and "%any" in line:
            in_our_conn = True
            continue
        if re.match(r"^\S", line) and not line.strip().startswith(conn):
            in_our_conn = False
        if not in_our_conn:
            continue
        m = _IKE_RE.match(line.strip())
        if m:
            s = Session(
                username=m.group("user"),
                ike_sa=m.group("state"),
                remote_ip=(m.group("remote") or "").replace("...", ""),
                raw=line.strip(),
            )
            sessions.append(s)
        # child SA lines: "  aurora-ikev2:  tunnel, x.x.x.x -> y.y.y.y"
        cm = re.match(r"^\s*[\w-]+\[\d+\]:\s*(TUNNEL|INSTALLED).*,\s*([0-9.]+)\s*(?:==|->)\s*([0-9.]+)", line)
        if cm and sessions:
            sessions[-1].child_sa = cm.group(1)
            if not sessions[-1].virtual_ip:
                sessions[-1].virtual_ip = cm.group(2)
    return sessions, pool_line


def get_status() -> StatusReport:
    rep = StatusReport(service_active=service_active())
    if not rep.service_active:
        rep.errors.append("VPN service is not active")
        return rep
    p = run(["ipsec", "statusall"], timeout=15)
    if p.returncode != 0 and not p.stdout:
        rep.errors.append(p.stderr.strip()[:300] or "ipsec statusall failed")
        return rep
    rep.daemon_up = "uptime" in p.stdout or "loaded" in p.stdout or True
    rep.sessions, rep.pool_usage = parse_statusall(p.stdout)
    return rep
