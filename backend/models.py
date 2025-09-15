import os
import sqlite3
import secrets
import logging
from datetime import datetime
from dataclasses import dataclass
from typing import Optional
from werkzeug.security import generate_password_hash

# Database configuration
DB_PATH = os.environ.get('DATABASE_URL', 'msg_converter.db')


def get_connection():
    """Return a new SQLite connection."""
    return sqlite3.connect(DB_PATH)


def init_db():
    """Create tables if they do not exist."""
    with get_connection() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                subscription_status TEXT,
                is_unlimited INTEGER DEFAULT 0,
                free_conversions_used INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.commit()


@dataclass
class User:
    id: Optional[int]
    email: str
    password_hash: str
    subscription_status: Optional[str] = None
    is_unlimited: bool = False
    free_conversions_used: int = 0
    created_at: Optional[str] = None


def seed_unlimited_user():
    """Create a default unlimited user if none exists."""
    email = "unlimited@example.com"
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        if cur.fetchone():
            return
        password = secrets.token_urlsafe(12)
        password_hash = generate_password_hash(password)
        cur.execute(
            """
            INSERT INTO users (email, password_hash, subscription_status, is_unlimited, free_conversions_used, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                password_hash,
                "active",
                1,
                0,
                datetime.utcnow().isoformat(),
            ),
        )
        conn.commit()
        logging.getLogger(__name__).info(
            "Seeded unlimited user '%s' with password: %s", email, password
        )


def create_user(email: str, password_hash: str) -> User:
    """Insert a new user and return it."""
    created_at = datetime.utcnow().isoformat()
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO users (email, password_hash, created_at)
            VALUES (?, ?, ?)
            """,
            (email, password_hash, created_at),
        )
        user_id = cur.lastrowid
        conn.commit()
    return User(user_id, email, password_hash, None, False, 0, created_at)


def get_user_by_email(email: str) -> Optional[User]:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, password_hash, subscription_status, is_unlimited, free_conversions_used, created_at FROM users WHERE email=?",
            (email,),
        )
        row = cur.fetchone()
    return User(*row) if row else None


def get_user_by_id(user_id: int) -> Optional[User]:
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, email, password_hash, subscription_status, is_unlimited, free_conversions_used, created_at FROM users WHERE id=?",
            (user_id,),
        )
        row = cur.fetchone()
    return User(*row) if row else None
