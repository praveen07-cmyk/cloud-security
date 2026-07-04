"""
db.py
-------------------------------------------------
SQLite storage for the cloud security platform.

The app uses this module for incident persistence,
demo user seeding, and authentication lookup so the
platform behaves like a small real product instead of
an in-memory mock.
-------------------------------------------------
"""

import os
import sqlite3

from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "database", "security_platform.db")


def get_connection():
    """Return a new SQLite connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_user_columns(cursor):
    """Lightweight migration for older demo databases."""
    cursor.execute("PRAGMA table_info(users)")
    columns = {row[1] for row in cursor.fetchall()}

    if "display_name" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
    if "password_hash" not in columns:
        cursor.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")


def init_db():
    """Create the database tables required by the platform."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            source_ip TEXT,
            destination_ip TEXT,
            attack_type TEXT,
            severity TEXT,
            confidence INTEGER,
            assigned_to TEXT,
            status TEXT
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            display_name TEXT,
            role TEXT,
            password_hash TEXT NOT NULL
        )
        """
    )

    _ensure_user_columns(cursor)

    conn.commit()
    conn.close()
    print(f"[INFO] Database ready at: {DB_PATH}")


def seed_demo_data(incidents, admin_username=None, admin_password=None):
    """Seed demo incidents and a demo admin account once."""
    admin_username = admin_username or os.getenv("SECURITY_ADMIN_USERNAME", "admin")
    admin_password = admin_password or os.getenv("SECURITY_ADMIN_PASSWORD", "admin")

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM incidents")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            """
            INSERT INTO incidents (
                time, source_ip, destination_ip, attack_type,
                severity, confidence, assigned_to, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    inc["time"],
                    inc["source_ip"],
                    inc["destination_ip"],
                    inc["attack_type"],
                    inc["severity"],
                    inc["confidence"],
                    inc["assigned_to"],
                    inc["status"],
                )
                for inc in incidents
            ],
        )

    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            """
            INSERT INTO users (username, display_name, role, password_hash)
            VALUES (?, ?, ?, ?)
            """,
            (
                admin_username,
                "Security Administrator",
                "Administrator",
                generate_password_hash(admin_password),
            ),
        )

    conn.commit()
    conn.close()


def load_incidents():
    """Load incidents ordered by their stored sequence."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, time, source_ip, destination_ip, attack_type,
               severity, confidence, assigned_to, status
        FROM incidents
        ORDER BY id ASC
        """
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def authenticate_user(username, password):
    """Authenticate a user against the SQLite user store."""
    row = get_user_by_username(username)

    if row is None:
        return None

    if not check_password_hash(row["password_hash"], password):
        return None

    return {
        "username": row["username"],
        "display_name": row["display_name"] or row["username"],
        "role": row["role"] or "User",
    }


def get_user_by_username(username):
    """Fetch a user row by username."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, username, display_name, role, password_hash
        FROM users
        WHERE username = ?
        """,
        (username,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


def get_user_by_id(user_id):
    """Fetch a user row by id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT id, username, display_name, role, password_hash
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    )
    row = cursor.fetchone()
    conn.close()
    return row


if __name__ == "__main__":
    init_db()
