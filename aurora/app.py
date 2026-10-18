"""Aurora IKEv2 Manager — web application factory.

Security model:
- Single administrator (username in DB, password hashed with pbkdf2).
- Session cookie: HttpOnly, SameSite=Lax, 8h expiry, signed via itsdangerous.
- CSRF token per session, required on every POST.
- Login rate limited per remote address (5 failures / 10 min).
- All privileged actions go through aurora.privileged helper functions which
  use argument lists (never shell=True).
"""
from __future__ import annotations

import hmac
import hashlib
import os
import secrets
import sqlite3
import time
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for, send_file, Response)

from . import strongswan, monitor
from .environment import detect_environment, inspect_existing

def _db_path() -> str:
    return os.environ.get("AURORA_DB", "/var/lib/aurora-ikev2/aurora.db")
SESSION_TTL = 8 * 3600
PBKDF2_ITERS = 260_000

# ----------------------------------------------------------------------- crypto

def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS)
    return f"pbkdf2${PBKDF2_ITERS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(iters))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except (ValueError, TypeError):
        return False


# ----------------------------------------------------------------------- storage

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(_db_path())
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db(app: Flask) -> None:
    p = _db_path()
    os.makedirs(os.path.dirname(p) or ".", mode=0o700, exist_ok=True)
    db = sqlite3.connect(p)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS admin (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        must_change INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        action TEXT NOT NULL,
        detail TEXT NOT NULL
    );
    """)
    db.commit()
    db.close()


def audit(action: str, detail: str = "") -> None:
    try:
        db = get_db()
        db.execute("INSERT INTO audit (ts, action, detail) VALUES (?,?,?)",
                   (int(time.time()), action, detail[:500]))
        db.commit()
    except sqlite3.Error:
        pass  # auditing must never break the request


# ------------------------------------------------------------------- auth layer

def _rate_limited(key: str, max_fails: int = 5, window: int = 600) -> bool:
    now = time.time()
    fails = app_login_fails.get(key, [])
    fails = [t for t in fails if now - t < window]
    app_login_fails[key] = fails
    return len(fails) >= max_fails


app_login_fails: dict[str, list[float]] = {}


def record_fail(key: str) -> None:
    app_login_fails.setdefault(key, []).append(time.time())


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get("uid") or time.time() - session.get("ts", 0) > SESSION_TTL:
            session.clear()
            return redirect(url_for("login", next=request.path))
        session["ts"] = time.time()
        return fn(*args, **kwargs)
    return wrapper


def csrf_token() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


def check_csrf() -> None:
    tok = request.form.get("csrf", "")
    if not tok or not hmac.compare_digest(tok, session.get("_csrf", "")):
        abort(400, "CSRF validation failed")


# ------------------------------------------------------------------- app factory

def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("AURORA_SECRET_KEY") or secrets.token_hex(32)
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("AURORA_INSECURE_COOKIES") != "1",
        PERMANENT_SESSION_LIFETIME=SESSION_TTL,
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    init_db(app)
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.after_request
    def security_headers(resp: Response) -> Response:
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; style-src 'self'; script-src 'self'")
        return resp

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    # ---------------- auth routes ----------------

    @app.route("/login", methods=["GET", "POST"])
    def login():
        ip = request.remote_addr or "?"
        if request.method == "POST":
            if _rate_limited(ip):
                flash("Too many failed attempts. Try again later.", "error")
                return render_template("login.html"), 429
            check_csrf()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            db = get_db()
            row = db.execute("SELECT * FROM admin WHERE username=?", (username,)).fetchone()
            if row and verify_password(password, row["password_hash"]):
                session.clear()
                session["uid"] = row["id"]
                session["ts"] = time.time()
                audit("login_ok")
                return redirect(request.args.get("next") or url_for("dashboard"))
            record_fail(ip)
            audit("login_fail", f"ip={ip} user={username[:64]}")
            flash("Invalid credentials.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        check_csrf()
        session.clear()
        return redirect(url_for("login"))

    # ---------------- dashboard ----------------

    @app.route("/")
    @login_required
    def dashboard():
        env = detect_environment()
        status = monitor.get_status()
        db = get_db()
        user_count = db.execute("SELECT COUNT(*) c FROM admin WHERE 0").fetchone()["c"]
        # users live in ipsec.secrets, not the app DB:
        users = strongswan.list_users()
        return render_template("dashboard.html", env=env, status=status,
                               users=users, sysinfo=_sysinfo())

    @app.route("/users", methods=["GET", "POST"])
    @login_required
    def users():
        if request.method == "POST":
            check_csrf()
            action = request.form.get("action", "")
            username = request.form.get("username", "").strip()
            try:
                if action == "add":
                    strongswan.add_user(username, request.form.get("password", ""))
                    strongswan.reload_secrets()
                    audit("user_add", username)
                    flash(f"User {username} created.", "ok")
                elif action == "delete":
                    confirm = request.form.get("confirm", "") == username
                    if not confirm:
                        raise ValueError("type the username to confirm deletion")
                    strongswan.delete_user(username)
                    strongswan.reload_secrets()
                    audit("user_delete", username)
                    flash(f"User {username} deleted.", "ok")
                elif action == "disable":
                    strongswan.disable_user(username)
                    strongswan.reload_secrets()
                    audit("user_disable", username)
                    flash(f"User {username} disabled.", "ok")
                elif action == "enable":
                    strongswan.enable_user(username)
                    strongswan.reload_secrets()
                    audit("user_enable", username)
                    flash(f"User {username} enabled.", "ok")
                elif action == "passwd":
                    strongswan.set_user_password(username, request.form.get("password", ""))
                    strongswan.reload_secrets()
                    audit("user_passwd", username)
                    flash(f"Password changed for {username}.", "ok")
                else:
                    raise ValueError("unknown action")
            except (ValueError, strongswan.CommandError) as e:
                flash(str(e), "error")
            return redirect(url_for("users"))
        q = request.args.get("q", "").lower()
        all_users = [(u, strongswan.user_state(u)) for u in strongswan.list_users()]
        if q:
            all_users = [(u, s) for u, s in all_users if q in u.lower()]
        return render_template("users.html", users=all_users, q=q)

    @app.route("/connections")
    @login_required
    def connections():
        return render_template("connections.html", status=monitor.get_status())

    @app.route("/server", methods=["GET", "POST"])
    @login_required
    def server():
        if request.method == "POST":
            check_csrf()
            action = request.form.get("action", "")
            try:
                if action == "reload":
                    strongswan.reload_full()
                    audit("server_reload")
                    flash("strongSwan reloaded.", "ok")
                elif action == "restart":
                    strongswan.restart_service()
                    audit("server_restart")
                    flash("strongSwan restarted.", "ok")
                else:
                    raise ValueError("unknown action")
            except strongswan.CommandError as e:
                flash(f"Operation failed: {e}", "error")
            return redirect(url_for("server"))
        env = detect_environment()
        existing = inspect_existing()
        return render_template("server.html", env=env, existing=existing,
                               sysinfo=_sysinfo(), diag=_diagnostics())

    @app.route("/setup")
    @login_required
    def client_setup():
        env = detect_environment()
        return render_template("setup.html", env=env)

    @app.route("/ca.crt")
    @login_required
    def download_ca():
        path = os.environ.get("AURORA_CA_PATH", "/etc/ipsec.d/cacerts/ca-cert.pem")
        if not os.path.isfile(path):
            abort(404, "CA certificate not found")
        return send_file(path, mimetype="application/x-x509-ca-cert",
                         as_attachment=True, download_name="aurora-vpn-ca.crt")

    # JSON status endpoint (authenticated)
    @app.route("/api/status")
    @login_required
    def api_status():
        rep = monitor.get_status()
        return {"service": rep.service_active, "sessions": len(rep.sessions),
                "pool": rep.pool_usage, "errors": rep.errors}

    return app


# ------------------------------------------------------------------ helpers

def _sysinfo() -> dict:
    info: dict = {}
    try:
        load = os.getloadavg()
        info["load"] = f"{load[0]:.2f} / {load[1]:.2f} / {load[2]:.2f}"
        mem = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                mem[k] = int(v.strip().split()[0]) if v.strip() else 0
        total, avail = mem.get("MemTotal", 0), mem.get("MemAvailable", 0)
        if total:
            info["ram"] = f"{(total - avail) // 1024} / {total // 1024} MB"
        with open("/proc/uptime") as fh:
            secs = int(float(fh.read().split()[0]))
        info["uptime"] = f"{secs // 86400}d {(secs % 86400) // 3600}h"
    except (OSError, ValueError):
        pass
    st = os.statvfs("/") if hasattr(os, "statvfs") else None
    if st:
        gb = st.f_frsize * st.f_blocks / 1e9
        free = st.f_frsize * st.f_bavail / 1e9
        info["disk"] = f"{gb - free:.0f} / {gb:.0f} GB"
    return info


def _diagnostics() -> dict:
    checks: dict[str, str] = {}
    checks["service"] = "active" if strongswan.service_active() else "inactive"
    p = strongswan.run(["ipsec", "listcerts"], timeout=10)
    checks["certs_loaded"] = str(p.stdout.count("subject")) if p.returncode == 0 else "unknown"
    fwd = None
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as fh:
            fwd = fh.read().strip()
    except OSError:
        pass
    checks["ip_forward"] = "enabled" if fwd == "1" else "DISABLED"
    return checks
