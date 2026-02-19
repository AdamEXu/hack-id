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
- saml_sp_sessions: App-scoped SLO session index mappings
- saml_request_replay: Replay-protection window for SAML request IDs
- saml_audit_events: SAML protocol and admin audit trail
- flask_sessions: Server-side Flask session storage
"""

import sqlite3
import sys
import os
import time

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

    # SAML SP sessions for app-scoped logout handling (EPHEMERAL)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS saml_sp_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            app_id TEXT NOT NULL,
            user_email TEXT NOT NULL,
            name_id TEXT NOT NULL,
            session_index TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_saml_sp_sessions_app ON saml_sp_sessions(app_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_saml_sp_sessions_user ON saml_sp_sessions(user_email)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_saml_sp_sessions_index ON saml_sp_sessions(session_index)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_saml_sp_sessions_expires ON saml_sp_sessions(expires_at)"
    )
    print("  ✓ saml_sp_sessions table")

    # SAML replay protection table (EPHEMERAL)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS saml_request_replay (
            request_id TEXT PRIMARY KEY,
            app_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
        )
    """
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_saml_request_replay_expires ON saml_request_replay(expires_at)"
    )
    print("  ✓ saml_request_replay table")

    # SAML audit events (retained with cleanup policy)
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS saml_audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            app_id TEXT,
            user_email TEXT,
            sp_entity_id TEXT,
            request_id TEXT,
            session_index TEXT,
            outcome TEXT NOT NULL,
            reason TEXT,
            details_json TEXT DEFAULT '{}',
            created_at INTEGER NOT NULL
        )
    """
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_saml_audit_events_app ON saml_audit_events(app_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_saml_audit_events_user ON saml_audit_events(user_email)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_saml_audit_events_created ON saml_audit_events(created_at)"
    )
    print("  ✓ saml_audit_events table")

    # Flask-Session SQLAlchemy compatibility table.
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS flask_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT UNIQUE,
            data BLOB,
            expiry INTEGER
        )
    """
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_flask_sessions_session_id ON flask_sessions(session_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_flask_sessions_expiry ON flask_sessions(expiry)"
    )
    print("  ✓ flask_sessions table")

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


def cleanup_expired_records() -> dict:
    """Cleanup expired ephemeral rows for OAuth/SAML/session tables."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    now_epoch = int(time.time())
    now_iso = time.strftime("%Y-%m-%d %H:%M:%S")
    cleanup_counts = {}

    cleanup_sql = {
        "authorization_codes": ("DELETE FROM authorization_codes WHERE expires_at < ?", (now_iso,)),
        "access_tokens": ("DELETE FROM access_tokens WHERE expires_at < ? OR revoked = TRUE", (now_iso,)),
        "oauth_tokens": ("DELETE FROM oauth_tokens WHERE expires_at < ?", (now_iso,)),
        "verification_tokens": ("DELETE FROM verification_tokens WHERE expires_at < ? OR used = TRUE", (now_iso,)),
        "saml_sp_sessions": ("DELETE FROM saml_sp_sessions WHERE expires_at < ?", (now_epoch,)),
        "saml_request_replay": ("DELETE FROM saml_request_replay WHERE expires_at < ?", (now_epoch,)),
        # One-year retention for SAML audit.
        "saml_audit_events": ("DELETE FROM saml_audit_events WHERE created_at < ?", (now_epoch - 365 * 24 * 60 * 60,)),
        "flask_sessions": ("DELETE FROM flask_sessions WHERE expiry IS NOT NULL AND expiry < ?", (now_epoch,)),
    }

    try:
        for table_name, (query, params) in cleanup_sql.items():
            try:
                cursor.execute(query, params)
                cleanup_counts[table_name] = cursor.rowcount
            except Exception:
                cleanup_counts[table_name] = -1
        conn.commit()
    finally:
        conn.close()

    return cleanup_counts


if __name__ == "__main__":
    init_db()
