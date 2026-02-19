"""Database utilities and connection management.

IMPORTANT: This file provides utilities for SQLite (ephemeral data only).
For persistent data (users, admins, api_keys, apps), use Teable via models/*.py
"""

import sqlite3
from config import DATABASE


def get_db_connection():
    """
    Get a SQLite database connection for ephemeral data only.

    SQLite is used for temporary/ephemeral data:
    - email_codes
    - verification_tokens
    - opt_out_tokens
    - oauth_tokens
    - api_key_logs

    For persistent data, use Teable via models/*.py
    """
    conn = sqlite3.connect(DATABASE)
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.row_factory = sqlite3.Row
    return conn


def dict_factory(cursor, row):
    """Convert database row to dictionary."""
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d
