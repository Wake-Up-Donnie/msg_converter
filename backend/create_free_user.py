#!/usr/bin/env python3
"""
Script to create a user with free unlimited access.
Usage: python create_free_user.py
"""

import os
import sys
import sqlite3
import secrets
from datetime import datetime
from werkzeug.security import generate_password_hash

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import get_connection, init_db

def create_free_unlimited_user(email: str, set_password: str = None):
    """
    Create a user with unlimited access and active subscription status.

    Args:
        email: User's email address
        set_password: Optional password to set. If None, generates a random one.

    Returns:
        tuple: (user_id, email, password)
    """
    # Initialize database if needed
    init_db()

    # Generate password if not provided
    if set_password is None:
        password = secrets.token_urlsafe(16)
    else:
        password = set_password

    password_hash = generate_password_hash(password)
    created_at = datetime.utcnow().isoformat()

    with get_connection() as conn:
        cur = conn.cursor()

        # Check if user already exists
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        existing_user = cur.fetchone()

        if existing_user:
            print(f"❌ User with email '{email}' already exists (ID: {existing_user[0]})")
            print("   To update, delete the user first or use a different email.")
            return None

        # Insert new user with unlimited access
        cur.execute(
            """
            INSERT INTO users (
                email,
                password_hash,
                subscription_status,
                is_unlimited,
                free_conversions_used,
                created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                password_hash,
                "active",  # Active subscription status
                1,         # Unlimited access (TRUE)
                0,         # No conversions used yet
                created_at,
            ),
        )
        user_id = cur.lastrowid
        conn.commit()

    print("✅ User created successfully!")
    print(f"   User ID: {user_id}")
    print(f"   Email: {email}")
    print(f"   Password: {password}")
    print(f"   Subscription Status: active")
    print(f"   Unlimited Access: Yes (Free Yearly)")
    print(f"   Created At: {created_at}")
    print("\n⚠️  IMPORTANT: Save the password - it cannot be retrieved later!")

    return (user_id, email, password)


if __name__ == "__main__":
    # User to create
    EMAIL = "tbobik91@gmail.com"

    # You can set a specific password here, or leave as None for random generation
    PASSWORD = None  # Set to a string like "MySecurePassword123!" to use a specific password

    print(f"Creating user with free yearly unlimited access...")
    print(f"Email: {EMAIL}\n")

    result = create_free_unlimited_user(EMAIL, PASSWORD)

    if result:
        print("\n" + "="*60)
        print("User can now log in with the credentials above.")
        print("="*60)
