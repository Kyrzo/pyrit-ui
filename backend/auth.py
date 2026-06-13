"""
auth.py — User management with SQLite + RBAC
=============================================
Roles: admin, analyst, viewer

Create first admin:
    python3 create_user.py --username admin --password secret --role admin

"""
import hashlib
import os
import secrets
import sqlite3
from datetime import datetime
from typing import Optional

DB_PATH = os.environ.get("DB_PATH", "/root/pyrit-ui-backend/users.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                username  TEXT    UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                salt      TEXT    NOT NULL,
                role      TEXT    NOT NULL DEFAULT 'viewer',
                active    INTEGER NOT NULL DEFAULT 1,
                created_at TEXT   NOT NULL,
                last_login TEXT
            )
        """)
        conn.commit()


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 310_000
    ).hex()


def create_user(username: str, password: str, role: str = "viewer") -> dict:
    if role not in ("admin", "analyst", "viewer"):
        raise ValueError(f"Invalid role: {role}")
    salt = secrets.token_hex(32)
    pw_hash = hash_password(password, salt)
    now = datetime.utcnow().isoformat()
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash, salt, role, active, created_at) VALUES (?,?,?,?,1,?)",
                (username, pw_hash, salt, role, now),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            raise ValueError(f"Username '{username}' already exists")
    return get_user(username)


def verify_password(username: str, password: str) -> Optional[dict]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username=? AND active=1", (username,)
        ).fetchone()
    if not row:
        return None
    expected = hash_password(password, row["salt"])
    if not secrets.compare_digest(expected, row["password_hash"]):
        return None
    # Update last_login
    with get_db() as conn:
        conn.execute(
            "UPDATE users SET last_login=? WHERE username=?",
            (datetime.utcnow().isoformat(), username),
        )
        conn.commit()
    return dict(row)


def get_user(username: str) -> Optional[dict]:
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, username, role, active, created_at, last_login FROM users WHERE username=?",
            (username,),
        ).fetchone()
    return dict(row) if row else None


def list_users() -> list:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, username, role, active, created_at, last_login FROM users ORDER BY id"
        ).fetchall()
    return [dict(r) for r in rows]


def update_user(username: str, role: Optional[str] = None, active: Optional[bool] = None) -> dict:
    if role and role not in ("admin", "analyst", "viewer"):
        raise ValueError(f"Invalid role: {role}")
    with get_db() as conn:
        if role is not None:
            conn.execute("UPDATE users SET role=? WHERE username=?", (role, username))
        if active is not None:
            conn.execute("UPDATE users SET active=? WHERE username=?", (1 if active else 0, username))
        conn.commit()
    return get_user(username)


def delete_user(username: str) -> bool:
    with get_db() as conn:
        cur = conn.execute("DELETE FROM users WHERE username=?", (username,))
        conn.commit()
    return cur.rowcount > 0


def change_password(username: str, new_password: str) -> bool:
    salt = secrets.token_hex(32)
    pw_hash = hash_password(new_password, salt)
    with get_db() as conn:
        cur = conn.execute(
            "UPDATE users SET password_hash=?, salt=? WHERE username=?",
            (pw_hash, salt, username),
        )
        conn.commit()
    return cur.rowcount > 0


# Role permission checks
PERMISSIONS = {
    "admin":   {"launch_scan", "view_scans", "manage_users", "view_settings", "delete_scan", "export"},
    "analyst": {"launch_scan", "view_scans", "export"},
    "viewer":  {"view_scans"},
}

def has_permission(role: str, permission: str) -> bool:
    return permission in PERMISSIONS.get(role, set())
