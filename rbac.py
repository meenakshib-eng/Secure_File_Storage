# rbac.py
import sqlite3
import os
import hashlib
import secrets
from typing import Optional, Tuple   # <-- added Tuple import

DB_FILE = "database.db"
PBKDF2_ITER = 150_000

ROLE_PERMISSIONS = {
    "admin": {"upload", "download", "delete", "assign_role"},
    "editor": {"upload", "download"},
    "viewer": {"download"},
}

def get_conn():
    return sqlite3.connect(DB_FILE, check_same_thread=False)

def init_db():
    conn = get_conn()
    c = conn.cursor()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY,
        name TEXT UNIQUE NOT NULL
    );
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role_id INTEGER,
        FOREIGN KEY(role_id) REFERENCES roles(id)
    );
    CREATE TABLE IF NOT EXISTS files (
        id INTEGER PRIMARY KEY,
        filename TEXT NOT NULL,
        filepath TEXT NOT NULL,
        owner_id INTEGER,
        wrapped_key BLOB,
        nonce BLOB,
        sha3 TEXT,
        hmac TEXT,
        created_at TEXT,
        FOREIGN KEY(owner_id) REFERENCES users(id)
    );
    """)
    # seed roles
    for role in ROLE_PERMISSIONS.keys():
        try:
            c.execute("INSERT OR IGNORE INTO roles (name) VALUES (?)", (role,))
        except Exception:
            pass
    conn.commit()
    conn.close()

def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    if salt is None:
        salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITER)
    return pwd_hash.hex(), salt.hex()

def add_user(username: str, password: str, role: str = "viewer"):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM roles WHERE name = ?", (role,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise ValueError("Role does not exist")
    role_id = row[0]
    pwd_hash, salt = hash_password(password)
    c.execute("INSERT INTO users (username, password_hash, salt, role_id) VALUES (?, ?, ?, ?)",
              (username, pwd_hash, salt, role_id))
    conn.commit()
    conn.close()

def authenticate(username: str, password: str) -> Optional[dict]:
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id, password_hash, salt, role_id FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    uid, pwd_hash_hex, salt_hex, role_id = row
    salt = bytes.fromhex(salt_hex)
    computed_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITER).hex()
    if computed_hash != pwd_hash_hex:
        return None
    # get role name
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT name FROM roles WHERE id = ?", (role_id,))
    role_row = c.fetchone()
    conn.close()
    role_name = role_row[0] if role_row else None
    return {"id": uid, "username": username, "role": role_name}

def assign_role(username: str, role: str):
    conn = get_conn()
    c = conn.cursor()
    c.execute("SELECT id FROM roles WHERE name = ?", (role,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise ValueError("Role does not exist")
    role_id = row[0]
    c.execute("UPDATE users SET role_id = ? WHERE username = ?", (role_id, username))
    conn.commit()
    conn.close()

def check_permission(user: dict, permission: str) -> bool:
    if not user:
        return False
    role = user.get("role")
    perms = ROLE_PERMISSIONS.get(role, set())
    return permission in perms
