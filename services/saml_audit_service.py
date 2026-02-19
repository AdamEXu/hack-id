"""SQLite-backed audit helpers for SAML runtime and admin events."""

from __future__ import annotations

import hashlib
import json
import time
from typing import Any, Dict, List, Optional

from utils.database import get_db_connection
from utils.validation import normalize_email


def _now_epoch() -> int:
    return int(time.time())


def log_saml_event(
    *,
    event_type: str,
    outcome: str,
    app_id: Optional[str] = None,
    user_email: Optional[str] = None,
    sp_entity_id: Optional[str] = None,
    request_id: Optional[str] = None,
    session_index: Optional[str] = None,
    reason: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Persist a SAML audit event. Best-effort (never raises)."""
    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT INTO saml_audit_events (
                event_type,
                app_id,
                user_email,
                sp_entity_id,
                request_id,
                session_index,
                outcome,
                reason,
                details_json,
                created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_type,
                app_id,
                normalize_email(user_email) if user_email else None,
                sp_entity_id,
                request_id,
                session_index,
                outcome,
                reason,
                json.dumps(details or {}),
                _now_epoch(),
            ),
        )
        conn.commit()
    except Exception:
        # Audit paths should not break auth/runtime behavior.
        pass
    finally:
        conn.close()


def get_saml_audit_events(app_id: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
    """Fetch recent SAML audit events for admin surfaces."""
    conn = get_db_connection()
    try:
        if app_id:
            rows = conn.execute(
                """
                SELECT *
                FROM saml_audit_events
                WHERE app_id = ?
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (app_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT *
                FROM saml_audit_events
                ORDER BY created_at DESC, id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        events: List[Dict[str, Any]] = []
        for row in rows:
            details_raw = row["details_json"]
            try:
                details_obj = json.loads(details_raw or "{}")
                if not isinstance(details_obj, dict):
                    details_obj = {}
            except (TypeError, ValueError):
                details_obj = {}

            events.append(
                {
                    "id": row["id"],
                    "event_type": row["event_type"],
                    "app_id": row["app_id"],
                    "user_email": row["user_email"],
                    "sp_entity_id": row["sp_entity_id"],
                    "request_id": row["request_id"],
                    "session_index": row["session_index"],
                    "outcome": row["outcome"],
                    "reason": row["reason"],
                    "details": details_obj,
                    "created_at": row["created_at"],
                }
            )
        return events
    finally:
        conn.close()


def anonymize_saml_audit_email(user_email: str) -> int:
    """Anonymize user_email in SAML audit logs for deletion requests."""
    normalized = normalize_email(user_email)
    digest = hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]
    replacement = f"deleted+{digest}@redacted.local"

    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "UPDATE saml_audit_events SET user_email = ? WHERE user_email = ?",
            (replacement, normalized),
        )
        conn.commit()
        return int(cursor.rowcount or 0)
    finally:
        conn.close()


def delete_saml_sp_sessions_for_email(user_email: str) -> int:
    """Delete SAML SP session index mappings for a user."""
    normalized = normalize_email(user_email)
    conn = get_db_connection()
    try:
        cursor = conn.execute(
            "DELETE FROM saml_sp_sessions WHERE user_email = ?",
            (normalized,),
        )
        conn.commit()
        return int(cursor.rowcount or 0)
    finally:
        conn.close()


def count_saml_artifacts_for_email(user_email: str) -> Dict[str, int]:
    """Count remaining SAML-linked rows used by deletion verification."""
    normalized = normalize_email(user_email)
    conn = get_db_connection()
    try:
        audit_count = conn.execute(
            "SELECT COUNT(*) AS count FROM saml_audit_events WHERE user_email = ?",
            (normalized,),
        ).fetchone()["count"]
        session_count = conn.execute(
            "SELECT COUNT(*) AS count FROM saml_sp_sessions WHERE user_email = ?",
            (normalized,),
        ).fetchone()["count"]
        return {
            "saml_audit_events": int(audit_count or 0),
            "saml_sp_sessions": int(session_count or 0),
        }
    finally:
        conn.close()
