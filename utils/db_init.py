"""Database initialization and schema management for SQLite (ephemeral data only).

IMPORTANT: SQLite is used for ephemeral/temporary data only.
Persistent data (users, admins, api_keys, apps) is stored in Teable.

Ephemeral tables created here:
- email_codes: Email verification codes (temporary)
- verification_tokens: Discord verification tokens (temporary)
- opt_out_tokens: Privacy deletion tokens (permanent links but not user data)
- oauth_tokens: OAuth session tokens (temporary)
- api_key_logs: API usage logs (ephemeral, can be purged)
- group_membership_cache: Short-lived ACL group membership cache
"""

import sqlite3
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DATABASE


def init_db():
    """Initialize SQLite database with ephemeral tables only."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        print(f"📂 Initializing SQLite (ephemeral data): {DATABASE}")
    except Exception as e:
        print(f"❌ Error connecting to SQLite database {DATABASE}: {e}")
        raise

    # Email verification codes table (EPHEMERAL)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS email_codes (
            email TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            expires_at TIMESTAMP NOT NULL
        )
    """
    )
    print("  ✓ email_codes table")

    # Discord verification tokens table (EPHEMERAL)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS verification_tokens (
            token TEXT PRIMARY KEY,
            discord_id TEXT NOT NULL,
            discord_username TEXT,
            message_id TEXT,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT FALSE
        )
    """
    )
    print("  ✓ verification_tokens table")

    # Opt-out tokens table for permanent secure deletion links (EPHEMERAL)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS opt_out_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            used_at TIMESTAMP NULL,
            is_used BOOLEAN DEFAULT FALSE
        )
    """
    )

    # Create indexes for fast token lookups
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_opt_out_tokens_token ON opt_out_tokens(token)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_opt_out_tokens_email ON opt_out_tokens(user_email)"
    )
    print("  ✓ opt_out_tokens table")

    # API key usage logs table (EPHEMERAL - can be purged periodically)
    # Note: key_id references Teable record ID (string), not SQLite integer
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS api_key_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            metadata TEXT DEFAULT '{}'
        )
    """
    )
    print("  ✓ api_key_logs table")

    # OAuth 2.0 authorization codes table (EPHEMERAL)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS authorization_codes (
            code TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_email TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            scope TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            used BOOLEAN DEFAULT FALSE
        )
    """
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_auth_codes_client ON authorization_codes(client_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_auth_codes_expires ON authorization_codes(expires_at)"
    )
    print("  ✓ authorization_codes table")

    # OAuth 2.0 access tokens table (EPHEMERAL)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS access_tokens (
            token TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_email TEXT NOT NULL,
            scope TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            revoked BOOLEAN DEFAULT FALSE
        )
    """
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_tokens_client ON access_tokens(client_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_tokens_user ON access_tokens(user_email)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_access_tokens_expires ON access_tokens(expires_at)"
    )
    print("  ✓ access_tokens table")

    # Legacy OAuth temporary tokens table (EPHEMERAL - for backward compatibility)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS oauth_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            user_email TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL
        )
    """
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_oauth_tokens_token ON oauth_tokens(token)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_oauth_tokens_expires ON oauth_tokens(expires_at)"
    )
    print("  ✓ oauth_tokens table (legacy)")

    # Group membership cache table for ACL evaluation (EPHEMERAL)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS group_membership_cache (
            group_key TEXT PRIMARY KEY,
            members_json TEXT NOT NULL,
            computed_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_group_cache_expires ON group_membership_cache(expires_at)"
    )
    print("  ✓ group_membership_cache table")

    try:
        conn.commit()
        conn.close()
        print("✅ SQLite (ephemeral data) initialized successfully!")
        print("ℹ️  Persistent data (users, admins, api_keys, apps) is in Teable")
    except Exception as e:
        print(f"❌ Error committing SQLite database changes: {e}")
        conn.close()
        raise


def check_table_exists(table_name):
    """Check if a specific table exists in the database."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        )
        result = cursor.fetchone()
        conn.close()
        exists = result is not None
        print(f"Table '{table_name}' exists: {exists}")
        return exists
    except Exception as e:
        print(f"Error checking if table '{table_name}' exists: {e}")
        return False


def list_all_tables():
    """List all tables in the database."""
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        conn.close()
        print(f"All tables in database: {tables}")
        return tables
    except Exception as e:
        print(f"Error listing tables: {e}")
        return []


if __name__ == "__main__":
    init_db()
