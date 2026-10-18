"""Root-side CLI for the Aurora PKI module.

The installer (Bash) calls THIS instead of maintaining its own certificate
commands — one authoritative PKI implementation. Run as root only:
    python3 -m aurora.pki_cli gen-ca
    python3 -m aurora.pki_cli gen-server <identity>
    python3 -m aurora.pki_cli validate <identity>
"""
from __future__ import annotations

import os
import sys

from . import pki


def _require_root() -> None:
    if os.geteuid() != 0:
        print("pki_cli must run as root", file=sys.stderr)
        raise SystemExit(2)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "gen-ca":
        _require_root()
        if pki.ca_exists():
            print("ca-exists")
            return 3  # caller decides (never silent overwrite)
        pki.generate_ca()
        print("ca-generated")
        return 0
    if cmd == "gen-server":
        _require_root()
        if len(argv) != 3:
            print("usage: pki_cli gen-server <identity>", file=sys.stderr)
            return 2
        pki.generate_server_cert(argv[2])
        print("server-cert-generated")
        return 0
    if cmd == "replace-ca":
        _require_root()
        if argv[2:] != ["--approved"]:
            print("refusing: CA replacement requires explicit --approved",
                  file=sys.stderr)
            return 2
        pki.replace_ca_approved(True)
        pki.generate_ca()
        print("ca-replaced")
        return 0
    if cmd == "validate":
        if len(argv) != 3:
            print("usage: pki_cli validate <identity>", file=sys.stderr)
            return 2
        res = pki.validate_pki()
        res["san_match"] = pki.validate_identity(
            identity=argv[2], server_cert=pki.SERVER_CERT)
        for k, v in res.items():
            print(f"{k}={v}")
        return 0 if (res["chain_ok"] and res["key_match"]
                     and res["san_match"] and not res.get("expired", False)) else 1
    print(f"unknown command: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
