"""OAuth 2.0 authorization code flow implementation."""

import secrets
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from utils.database import get_db_connection
from models.app import get_app_by_client_id, validate_redirect_uri
import json


def create_authorization_code(
    client_id: str,
    user_email: str,
    redirect_uri: str,
    scope: str
) -> str:
    """
    Create a short-lived authorization code (10 minutes).
    This is step 1 of OAuth 2.0 authorization code flow.
    """
    code = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(minutes=10)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        """
        INSERT INTO authorization_codes 
        (code, client_id, user_email, redirect_uri, scope, expires_at, used)
        VALUES (?, ?, ?, ?, ?, ?, FALSE)
        """,
        (code, client_id, user_email, redirect_uri, scope, expires_at)
    )
    
    conn.commit()
    conn.close()
    
    return code


def verify_authorization_code(
    code: str,
    client_id: str,
    redirect_uri: str
) -> Optional[Dict[str, Any]]:
    """
    Verify authorization code and return associated data.
    Returns None if code is invalid, expired, or already used.
    """
    from config import DEBUG_MODE

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT client_id, user_email, redirect_uri, scope, expires_at, used
        FROM authorization_codes
        WHERE code = ?
        """,
        (code,)
    )

    result = cursor.fetchone()

    if DEBUG_MODE:
        print(f"DEBUG verify_authorization_code: code={code[:20]}...")
        print(f"DEBUG verify_authorization_code: result from DB={result}")

    conn.close()

    if not result:
        if DEBUG_MODE:
            print(f"DEBUG verify_authorization_code: Code not found in database")
        return None

    stored_client_id, user_email, stored_redirect_uri, scope, expires_at, used = result

    # Verify code hasn't been used
    if used:
        if DEBUG_MODE:
            print(f"DEBUG verify_authorization_code: Code already used")
        return None

    # Verify code hasn't expired
    if datetime.fromisoformat(expires_at) < datetime.now():
        if DEBUG_MODE:
            print(f"DEBUG verify_authorization_code: Code expired (expires_at={expires_at}, now={datetime.now()})")
        return None

    # Verify client_id matches
    if stored_client_id != client_id:
        if DEBUG_MODE:
            print(f"DEBUG verify_authorization_code: client_id mismatch (stored={stored_client_id}, provided={client_id})")
        return None

    # Verify redirect_uri matches (OAuth 2.0 security requirement)
    if stored_redirect_uri != redirect_uri:
        if DEBUG_MODE:
            print(f"DEBUG verify_authorization_code: redirect_uri mismatch (stored={stored_redirect_uri}, provided={redirect_uri})")
        return None

    if DEBUG_MODE:
        print(f"DEBUG verify_authorization_code: Code valid! user_email={user_email}, scope={scope}")

    return {
        "user_email": user_email,
        "scope": scope,
        "client_id": client_id
    }


def mark_code_as_used(code: str) -> None:
    """Mark authorization code as used (one-time use only)."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        "UPDATE authorization_codes SET used = TRUE WHERE code = ?",
        (code,)
    )
    
    conn.commit()
    conn.close()


def create_access_token(
    client_id: str,
    user_email: str,
    scope: str,
    expires_in_seconds: int = 3600
) -> str:
    """
    Create an access token (default 1 hour expiry).
    This is the token that apps use to access user data.
    """
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(seconds=expires_in_seconds)
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute(
        """
        INSERT INTO access_tokens 
        (token, client_id, user_email, scope, expires_at, revoked)
        VALUES (?, ?, ?, ?, ?, FALSE)
        """,
        (token, client_id, user_email, scope, expires_at)
    )
    
    conn.commit()
    conn.close()
    
    return token


def exchange_code_for_token(
    code: str,
    client_id: str,
    client_secret: str,
    redirect_uri: str
) -> Dict[str, Any]:
    """
    Exchange authorization code for access token.
    This is step 2 of OAuth 2.0 authorization code flow.
    """
    from config import DEBUG_MODE

    # Verify client credentials
    app = get_app_by_client_id(client_id)
    if DEBUG_MODE:
        print(f"Looking for app with client_id={client_id}")
        print(f"Found app: {app}")

    if not app:
        return {"success": False, "error": "invalid_client"}
    if app.get("app_type", "oauth") != "oauth":
        return {"success": False, "error": "invalid_client"}

    if DEBUG_MODE:
        print(f"Comparing secrets: provided={client_secret[:10]}... vs stored={app.get('client_secret', '')[:10]}...")

    if app.get("client_secret") != client_secret:
        return {"success": False, "error": "invalid_client"}

    # Verify authorization code
    code_data = verify_authorization_code(code, client_id, redirect_uri)
    if not code_data:
        return {"success": False, "error": "invalid_grant"}

    # Mark code as used (one-time use only)
    mark_code_as_used(code)

    # Create access token
    access_token = create_access_token(
        client_id=code_data["client_id"],
        user_email=code_data["user_email"],
        scope=code_data["scope"],
        expires_in_seconds=3600  # 1 hour
    )

    return {
        "success": True,
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "scope": code_data["scope"]
    }


def verify_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify access token and return user info + scopes.
    Returns None if token is invalid, expired, or revoked.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT client_id, user_email, scope, expires_at, revoked
        FROM access_tokens
        WHERE token = ?
        """,
        (token,)
    )

    result = cursor.fetchone()
    conn.close()

    if not result:
        return None

    client_id, user_email, scope, expires_at, revoked = result

    # Check if revoked
    if revoked:
        return None

    # Check if expired
    if datetime.fromisoformat(expires_at) < datetime.now():
        return None

    return {
        "client_id": client_id,
        "user_email": user_email,
        "scope": scope.split() if scope else []
    }


def revoke_access_token(token: str) -> bool:
    """Revoke an access token."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE access_tokens SET revoked = TRUE WHERE token = ?",
        (token,)
    )

    rows_affected = cursor.rowcount
    conn.commit()
    conn.close()

    return rows_affected > 0


def cleanup_expired_codes() -> int:
    """Clean up expired authorization codes. Returns number of deleted codes."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM authorization_codes WHERE expires_at < ?",
        (datetime.now(),)
    )

    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    return deleted


def cleanup_expired_tokens() -> int:
    """Clean up expired access tokens. Returns number of deleted tokens."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM access_tokens WHERE expires_at < ?",
        (datetime.now(),)
    )

    deleted = cursor.rowcount
    conn.commit()
    conn.close()

    return deleted
