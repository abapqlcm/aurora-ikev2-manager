"""Aurora IKEv2 Manager — web application factory.

Security model:
- Single administrator (username in DB, password hashed with PBKDF2-SHA256).
- Session cookie: HttpOnly, SameSite=Lax, 8h expiry, signed via itsdangerous.
- CSRF token per session, required on every POST.
- Login rate limit per remote address, shared across all worker processes
  through the SQLite database (5 failures / 10 minutes).
- A bootstrap or reset password forces a change before any other page.
- Redirect targets after login are validated as internal paths only.
- Credential writes go through the root secrets helper (see secrets_client).
"""
from __future__ import annotations

import hashlib
import hmac
import io
import os
import secrets
import sqlite3
import time
import urllib.parse
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for, send_file, Response)

from . import strongswan, monitor, swanctl_users
from .environment import detect_environment, inspect_existing, CommandError
from .secrets_helper import password_error

TEMPLATE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
SESSION_TTL = 8 * 3600
# OWASP (2023) minimum for PBKDF2-HMAC-SHA256. Older hashes still verify and are
# transparently upgraded on the next successful login (see needs_rehash).
PBKDF2_ITERS = 600_000
LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 600

# Endpoints reachable while a forced password change is pending.
FORCED_CHANGE_ALLOWED = {"login", "logout", "change_password", "static"}


def _db_path() -> str:
    return os.environ.get("AURORA_DB", "/var/lib/aurora-ikev2/aurora.db")


# ----------------------------------------------------------------- crypto

def hash_password(password: str, salt: bytes | None = None,
                  iterations: int = PBKDF2_ITERS) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2${iterations}${salt.hex()}${dk.hex()}"


def _parse_hash(stored: str):
    _, iters, salt_hex, dk_hex = stored.split("$")
    return int(iters), bytes.fromhex(salt_hex), dk_hex


def verify_password(password: str, stored: str) -> bool:
    try:
        iters, salt, dk_hex = _parse_hash(stored)
    except (ValueError, TypeError):
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iters)
    return hmac.compare_digest(dk.hex(), dk_hex)


def needs_rehash(stored: str) -> bool:
    try:
        iters, _, _ = _parse_hash(stored)
    except (ValueError, TypeError):
        return True
    return iters < PBKDF2_ITERS


# ----------------------------------------------------------------- redirects

def safe_next(target: str | None, default: str) -> str:
    """Return `target` only if it is a same-site path; otherwise `default`.

    Rejects absolute URLs, protocol-relative '//host', backslash tricks,
    control characters and anything that still resolves to another origin
    after percent-decoding (applied repeatedly to defeat double encoding).
    """
    if not target or len(target) > 512:
        return default
    candidate = target
    for _ in range(3):
        decoded = urllib.parse.unquote(candidate)
        if decoded == candidate:
            break
        candidate = decoded
    if any(ord(c) < 32 or ord(c) == 127 for c in candidate):
        return default
    if "\\" in candidate:
        return default
    if not candidate.startswith("/") or candidate.startswith("//"):
        return default
    parts = urllib.parse.urlsplit(candidate)
    if parts.scheme or parts.netloc:
        return default
    return target


# ----------------------------------------------------------------- storage

def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(_db_path(), timeout=10)
        g.db.row_factory = sqlite3.Row
    return g.db


def init_db(app=None) -> None:
    p = _db_path()
    os.makedirs(os.path.dirname(p) or ".", mode=0o700, exist_ok=True)
    db = sqlite3.connect(p, timeout=10)
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
    CREATE TABLE IF NOT EXISTS login_attempts (
        ip TEXT NOT NULL,
        ts REAL NOT NULL
    );
    CREATE INDEX IF NOT EXISTS login_attempts_ip ON login_attempts (ip, ts);
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


# ----------------------------------------------------- shared login limiter

def login_blocked(db: sqlite3.Connection, ip: str) -> bool:
    """True if `ip` has too many recent failures. State is shared in SQLite,
    so every worker process sees the same counters."""
    cutoff = time.time() - LOGIN_WINDOW
    db.execute("DELETE FROM login_attempts WHERE ts < ?", (cutoff,))
    row = db.execute("SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND ts >= ?",
                     (ip, cutoff)).fetchone()
    db.commit()
    return row[0] >= LOGIN_MAX_FAILS


def record_login_failure(db: sqlite3.Connection, ip: str) -> None:
    db.execute("INSERT INTO login_attempts (ip, ts) VALUES (?, ?)", (ip, time.time()))
    db.commit()


def clear_login_failures(db: sqlite3.Connection, ip: str) -> None:
    db.execute("DELETE FROM login_attempts WHERE ip = ?", (ip,))
    db.commit()


# ------------------------------------------------------------- auth layer

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


def _admin_row():
    uid = session.get("uid")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM admin WHERE id = ?", (uid,)).fetchone()


def _user_action(action: str, username: str, form) -> str:
    """Apply one user mutation to the active backend. Raises ValueError/CommandError."""
    if strongswan.stack_layout() == "swanctl":
        ok, detail = swanctl_users.check_eap_configured()
        if not ok:
            raise ValueError(f"swanctl server: {detail}")
        mod = swanctl_users
    else:
        mod = strongswan
    if action == "add":
        mod.add_user(username, form.get("password", ""))
        audit("user_add", username)
        return f"User {username} created."
    if action == "delete":
        if form.get("confirm", "") != username:
            raise ValueError("type the username to confirm deletion")
        if not mod.delete_user(username):
            raise ValueError(f"User {username} not found.")
        audit("user_delete", username)
        return f"User {username} deleted."
    if action in ("disable", "enable"):
        changed = mod.disable_user(username) if action == "disable" else mod.enable_user(username)
        if not changed:
            raise ValueError(f"User {username} not found.")
        audit(f"user_{action}", username)
        return f"User {username} {action}d."
    if action == "passwd":
        mod.set_user_password(username, form.get("password", ""))
        audit("user_passwd", username)
        return f"Password changed for {username}."
    raise ValueError("unknown action")


def _list_entries():
    if strongswan.stack_layout() == "swanctl":
        return swanctl_users.list_entries()
    return strongswan.list_entries()


# ------------------------------------------------------------- app factory

def create_app() -> Flask:
    app = Flask(__name__, static_folder=os.path.join(TEMPLATE_DIR, "static"))
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

    @app.before_request
    def enforce_forced_password_change():
        if not session.get("uid") or request.endpoint in FORCED_CHANGE_ALLOWED:
            return None
        row = _admin_row()
        if row is not None and row["must_change"]:
            return redirect(url_for("change_password"))
        return None

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
            db = get_db()
            if login_blocked(db, ip):
                flash("Too many failed attempts. Try again later.", "error")
                return render_template("login.html"), 429
            check_csrf()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            row = db.execute("SELECT * FROM admin WHERE username=?", (username,)).fetchone()
            if row and verify_password(password, row["password_hash"]):
                if needs_rehash(row["password_hash"]):
                    db.execute("UPDATE admin SET password_hash=? WHERE id=?",
                               (hash_password(password), row["id"]))
                    db.commit()
                clear_login_failures(db, ip)
                session.clear()
                session["uid"] = row["id"]
                session["ts"] = time.time()
                audit("login_ok")
                default = url_for("change_password") if row["must_change"] else url_for("dashboard")
                return redirect(safe_next(request.args.get("next"), default))
            record_login_failure(db, ip)
            audit("login_fail", f"ip={ip} user={username[:64]}")
            flash("Invalid credentials.", "error")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    def logout():
        check_csrf()
        session.clear()
        return redirect(url_for("login"))

    @app.route("/change-password", methods=["GET", "POST"])
    @login_required
    def change_password():
        row = _admin_row()
        if row is None:
            session.clear()
            return redirect(url_for("login"))
        forced = bool(row["must_change"])
        if request.method == "POST":
            check_csrf()
            current = request.form.get("current", "")
            new = request.form.get("new", "")
            confirm = request.form.get("confirm", "")
            if not verify_password(current, row["password_hash"]):
                flash("Current password is incorrect.", "error")
            elif new != confirm:
                flash("New passwords do not match.", "error")
            elif hmac.compare_digest(new, current):
                flash("Choose a password different from the current one.", "error")
            elif (err := password_error(new)):
                flash(err, "error")
            else:
                db = get_db()
                db.execute("UPDATE admin SET password_hash=?, must_change=0 WHERE id=?",
                           (hash_password(new), row["id"]))
                db.commit()
                audit("password_changed")
                session.pop("_csrf", None)  # rotate CSRF token after credential change
                session["ts"] = time.time()
                flash("Password changed.", "ok")
                return redirect(url_for("dashboard"))
        return render_template("change_password.html", forced=forced)

    # ---------------- dashboard ----------------

    @app.route("/")
    @login_required
    def dashboard():
        env = detect_environment()
        status = monitor.get_status()
        try:
            users = [name for name, _ in _list_entries()]
        except (CommandError, ValueError) as exc:
            users = []
            flash(f"Cannot read users: {exc}", "error")
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
                flash(_user_action(action, username, request.form), "ok")
            except (ValueError, CommandError) as exc:
                flash(str(exc), "error")
            return redirect(url_for("users"))
        q = request.args.get("q", "").lower()
        try:
            all_users = _list_entries()
        except (CommandError, ValueError) as exc:
            flash(f"Cannot read users: {exc}", "error")
            all_users = []
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
            except (CommandError, ValueError) as e:
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
        from . import pki
        return render_template("setup.html", env=env, pki=pki)

    @app.route("/ca.pem")
    @app.route("/ca.crt")  # legacy alias, same certificate
    @login_required
    def download_ca():
        """Serve the exact public CA cert. The path is fixed (aurora/pki.CA_CERT);
        no user input touches it. Private keys are never served."""
        from . import pki
        try:
            data = pki.ca_bytes(pki.CA_CERT)
        except OSError:
            abort(404, "CA certificate not found on this server — "
                       "expected at " + pki.CA_CERT)
        if b"BEGIN CERTIFICATE" not in data:
            abort(500, "CA file at " + pki.CA_CERT + " is not a valid PEM certificate")
        return send_file(io.BytesIO(data),
                         mimetype="application/x-pem-file",
                         as_attachment=True,
                         download_name=pki.DOWNLOAD_NAME)

    @app.route("/api/status")
    @login_required
    def api_status():
        rep = monitor.get_status()
        return {"service": rep.service_active, "daemon_up": rep.daemon_up,
                "sessions": len(rep.sessions), "pool": rep.pool_usage,
                "errors": rep.errors}

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
    try:
        p = strongswan.run(["ipsec", "listcerts"], timeout=10)
        checks["certs_loaded"] = str(p.stdout.count("subject")) if p.returncode == 0 else "unknown"
    except OSError:
        checks["certs_loaded"] = "unknown"
    fwd = None
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as fh:
            fwd = fh.read().strip()
    except OSError:
        pass
    checks["ip_forward"] = "enabled" if fwd == "1" else "DISABLED"
    return checks
