"""App ACL management and evaluation service."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from config import APP_ACL_MAX_ENTRIES
from models.admin import get_all_admins
from models.user import get_users_by_event
from services.universal_admin_snapshot import has_valid_universal_admin_snapshot
from utils.database import get_db_connection
from utils.events import get_all_events
from utils.teable import (
    create_record,
    create_records_batch,
    delete_record,
    delete_records_batch,
    get_records,
    get_records_strict,
)
from utils.validation import normalize_email, validate_email

logger = logging.getLogger(__name__)

PRINCIPAL_TYPE_EMAIL = "email"
PRINCIPAL_TYPE_GROUP_ADMINS = "group_admins"
PRINCIPAL_TYPE_GROUP_EVENT_ATTENDEES = "group_event_attendees"
GROUP_ADMINS_ALL = "all_admins"
ACL_ROLE_MEMBER = "member"
GROUP_CACHE_TTL_SECONDS = 120


class AppAclEvaluationError(RuntimeError):
    """Raised when ACL evaluation cannot complete."""


def _log_acl_event(event_name: str, **fields: Any) -> None:
    payload = {
        "event": event_name,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **fields,
    }
    logger.info(json.dumps(payload, sort_keys=True))


def _now_epoch() -> int:
    return int(time.time())


def _serialize_entry_from_record(record: Dict[str, Any]) -> Dict[str, Any]:
    fields = record.get("fields", {})
    return {
        "id": record.get("id"),
        "app_id": fields.get("app_id"),
        "principal_type": fields.get("principal_type"),
        "principal_ref": fields.get("principal_ref"),
        "role": fields.get("role") or ACL_ROLE_MEMBER,
    }


def get_app_acl_entries(app_id: str, strict: bool = False) -> List[Dict[str, Any]]:
    """Get ACL entries for an app."""
    records = (
        get_records_strict("app_access_entries", limit=1000)
        if strict
        else get_records("app_access_entries", limit=1000)
    )

    entries: List[Dict[str, Any]] = []
    for record in records:
        fields = record.get("fields", {})
        if fields.get("app_id") == app_id:
            entries.append(_serialize_entry_from_record(record))
    return entries


def _event_exists(event_id: str) -> bool:
    events = get_all_events()
    return event_id in events


def validate_acl_entries(
    entries: Sequence[Dict[str, Any]],
    max_entries: int = APP_ACL_MAX_ENTRIES,
) -> Tuple[Optional[List[Dict[str, str]]], Optional[str], Optional[str]]:
    """Validate and normalize incoming ACL entries payload."""
    if len(entries) > max_entries:
        return None, "too_many_entries", f"Maximum {max_entries} ACL entries are allowed"

    normalized_entries: List[Dict[str, str]] = []
    seen: Set[Tuple[str, str]] = set()
    for entry in entries:
        principal_type = (entry.get("principal_type") or "").strip()
        principal_ref_raw = (entry.get("principal_ref") or "").strip()
        principal_ref = principal_ref_raw

        if principal_type == PRINCIPAL_TYPE_EMAIL:
            principal_ref = normalize_email(principal_ref_raw)
            if not validate_email(principal_ref):
                return None, "invalid_email", f"Invalid email principal: {principal_ref_raw}"
        elif principal_type == PRINCIPAL_TYPE_GROUP_ADMINS:
            if principal_ref_raw != GROUP_ADMINS_ALL:
                return None, "invalid_principal", "Only all_admins is supported for group_admins"
            principal_ref = GROUP_ADMINS_ALL
        elif principal_type == PRINCIPAL_TYPE_GROUP_EVENT_ATTENDEES:
            if not _event_exists(principal_ref_raw):
                return None, "unknown_event", f"Unknown event id: {principal_ref_raw}"
        else:
            return None, "invalid_principal", f"Unsupported principal_type: {principal_type}"

        dedupe_key = (principal_type, principal_ref)
        if dedupe_key in seen:
            return None, "duplicate_principal", f"Duplicate principal: {principal_type}:{principal_ref}"
        seen.add(dedupe_key)

        normalized_entries.append(
            {
                "principal_type": principal_type,
                "principal_ref": principal_ref,
                "role": ACL_ROLE_MEMBER,
            }
        )

    return normalized_entries, None, None


def _ensure_group_cache_table() -> None:
    conn = get_db_connection()
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS group_membership_cache (
                group_key TEXT PRIMARY KEY,
                members_json TEXT NOT NULL,
                computed_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _read_group_membership_cache(group_key: str) -> Optional[Set[str]]:
    _ensure_group_cache_table()
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT members_json
            FROM group_membership_cache
            WHERE group_key = ? AND expires_at > ?
            """,
            (group_key, _now_epoch()),
        ).fetchone()
        if not row:
            return None

        return set(json.loads(row["members_json"]))
    finally:
        conn.close()


def _write_group_membership_cache(group_key: str, members: Set[str]) -> None:
    _ensure_group_cache_table()
    now_epoch = _now_epoch()
    expires_at = now_epoch + GROUP_CACHE_TTL_SECONDS
    conn = get_db_connection()
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO group_membership_cache (
                group_key, members_json, computed_at, expires_at
            ) VALUES (?, ?, ?, ?)
            """,
            (group_key, json.dumps(sorted(members)), now_epoch, expires_at),
        )
        conn.commit()
    finally:
        conn.close()


def _resolve_group_members(principal_type: str, principal_ref: str) -> Set[str]:
    group_key = f"{principal_type}:{principal_ref}"
    cached = _read_group_membership_cache(group_key)
    if cached is not None:
        return cached

    if principal_type == PRINCIPAL_TYPE_GROUP_ADMINS:
        admins = get_all_admins()
        members = {
            normalize_email(admin.get("email", ""))
            for admin in admins
            if admin.get("is_active")
        }
    elif principal_type == PRINCIPAL_TYPE_GROUP_EVENT_ATTENDEES:
        members = {
            normalize_email(user.get("email", ""))
            for user in get_users_by_event(principal_ref)
        }
    else:
        raise AppAclEvaluationError(f"Unsupported group principal_type: {principal_type}")

    _write_group_membership_cache(group_key, members)
    return members


def _entry_matches_user(entry: Dict[str, Any], normalized_user_email: str) -> bool:
    principal_type = entry.get("principal_type")
    principal_ref = entry.get("principal_ref")
    if principal_type == PRINCIPAL_TYPE_EMAIL:
        return normalize_email(principal_ref or "") == normalized_user_email

    if principal_type in (PRINCIPAL_TYPE_GROUP_ADMINS, PRINCIPAL_TYPE_GROUP_EVENT_ATTENDEES):
        members = _resolve_group_members(principal_type, principal_ref)
        return normalized_user_email in members

    return False


def evaluate_app_acl_strict(app: Dict[str, Any], user_email: str, path: str) -> Dict[str, Any]:
    """Evaluate ACL using strict Teable semantics. Raises on evaluation failures."""
    app_id = app.get("id")
    normalized_email = normalize_email(user_email)

    if app.get("allow_anyone"):
        _log_acl_event(
            "acl_granted",
            user_email=normalized_email,
            app_id=app_id,
            path=path,
            reason="allow_anyone",
        )
        return {"allowed": True, "reason": "allow_anyone", "fail_open_used": False}

    try:
        acl_entries = get_app_acl_entries(app_id, strict=True)
        for entry in acl_entries:
            if _entry_matches_user(entry, normalized_email):
                reason = f"matched_{entry.get('principal_type')}"
                _log_acl_event(
                    "acl_granted",
                    user_email=normalized_email,
                    app_id=app_id,
                    path=path,
                    reason=reason,
                )
                return {"allowed": True, "reason": reason, "fail_open_used": False}
    except Exception as exc:  # noqa: BLE001
        raise AppAclEvaluationError(str(exc)) from exc

    _log_acl_event(
        "acl_denied",
        user_email=normalized_email,
        app_id=app_id,
        path=path,
        reason="no_matching_principal",
    )
    return {"allowed": False, "reason": "no_matching_principal", "fail_open_used": False}


def evaluate_app_acl_with_fail_open(
    app: Dict[str, Any],
    user_email: str,
    path: str,
    sess: Dict[str, Any],
) -> Dict[str, Any]:
    """Evaluate ACL with universal-admin fail-open fallback."""
    normalized_email = normalize_email(user_email)
    app_id = app.get("id")
    try:
        return evaluate_app_acl_strict(app, normalized_email, path)
    except AppAclEvaluationError as exc:
        valid_snapshot, snapshot_age_sec = has_valid_universal_admin_snapshot(sess)
        _log_acl_event(
            "acl_eval_error",
            user_email=normalized_email,
            app_id=app_id,
            path=path,
            reason=str(exc),
            snapshot_age_sec=snapshot_age_sec,
        )
        if valid_snapshot:
            sess["acl_fail_open_used"] = True
            _log_acl_event(
                "acl_fail_open_used",
                user_email=normalized_email,
                app_id=app_id,
                path=path,
                reason=str(exc),
                snapshot_age_sec=snapshot_age_sec,
            )
            return {"allowed": True, "reason": "fail_open", "fail_open_used": True}

        _log_acl_event(
            "acl_denied",
            user_email=normalized_email,
            app_id=app_id,
            path=path,
            reason="acl_eval_error_no_snapshot",
            snapshot_age_sec=snapshot_age_sec,
        )
        return {"allowed": False, "reason": "acl_eval_error_no_snapshot", "fail_open_used": False}


def replace_app_acl_entries(
    app: Dict[str, Any],
    entries: Sequence[Dict[str, Any]],
    actor_email: str,
    max_entries: int = APP_ACL_MAX_ENTRIES,
) -> Dict[str, Any]:
    """Replace ACL entries via create-then-delete semantics."""
    validated_entries, error_reason, error_message = validate_acl_entries(entries, max_entries=max_entries)
    if validated_entries is None:
        return {
            "success": False,
            "error": error_message,
            "reason": error_reason,
        }

    app_id = app["id"]
    old_records_raw = get_records_strict("app_access_entries", limit=1000)
    old_records = [r for r in old_records_raw if r.get("fields", {}).get("app_id") == app_id]
    before_json = json.dumps([_serialize_entry_from_record(record) for record in old_records], sort_keys=True)

    now_iso = datetime.now(timezone.utc).isoformat()
    create_payload = [
        {
            "app_id": app_id,
            "principal_type": entry["principal_type"],
            "principal_ref": entry["principal_ref"],
            "role": ACL_ROLE_MEMBER,
            "created_by": normalize_email(actor_email),
            "created_at": now_iso,
        }
        for entry in validated_entries
    ]

    if create_payload:
        created = create_records_batch("app_access_entries", create_payload)
        if not created:
            return {
                "success": False,
                "error": "Failed to create ACL entries",
                "reason": "acl_write_failed",
            }

    old_ids = [record.get("id") for record in old_records if record.get("id")]
    if old_ids:
        deleted = delete_records_batch("app_access_entries", old_ids)
        if not deleted:
            # Re-read to handle eventual consistency/API quirks where delete may
            # report failure despite records already gone.
            try:
                refreshed_records = get_records_strict("app_access_entries", limit=1000)
                remaining_ids = {
                    record.get("id")
                    for record in refreshed_records
                    if record.get("fields", {}).get("app_id") == app_id and record.get("id")
                }
            except Exception:
                remaining_ids = set(old_ids)

            undeleted_ids = [record_id for record_id in old_ids if record_id in remaining_ids]

            # Final per-record retry for IDs still present.
            if undeleted_ids:
                still_remaining = []
                for record_id in undeleted_ids:
                    if not delete_record("app_access_entries", record_id):
                        still_remaining.append(record_id)
                undeleted_ids = still_remaining

            if undeleted_ids:
                return {
                    "success": False,
                    "error": f"Failed to delete previous ACL entries: {', '.join(undeleted_ids)}",
                    "reason": "acl_delete_failed",
                }

    after_json = json.dumps(validated_entries, sort_keys=True)
    create_record(
        "app_access_audit",
        {
            "app_id": app_id,
            "actor_email": normalize_email(actor_email),
            "action": "replace_acl",
            "before_json": before_json,
            "after_json": after_json,
            "created_at": now_iso,
        },
    )

    if not app.get("allow_anyone") and len(validated_entries) == 0:
        _log_acl_event(
            "acl_empty_restricted_saved",
            user_email=normalize_email(actor_email),
            app_id=app_id,
            path="/admin/apps/<app_id>/access",
            reason="restricted_app_empty_acl_saved",
        )

    return {
        "success": True,
        "entries": validated_entries,
        "warning": "restricted_empty_acl" if (not app.get("allow_anyone") and len(validated_entries) == 0) else None,
    }


def log_if_restricted_app_acl_empty(app: Dict[str, Any], actor_email: str, path: str) -> bool:
    """Emit warning log event when restricted app has empty ACL."""
    if app.get("allow_anyone"):
        return False
    entries = get_app_acl_entries(app.get("id"), strict=False)
    if entries:
        return False

    _log_acl_event(
        "acl_empty_restricted_saved",
        user_email=normalize_email(actor_email),
        app_id=app.get("id"),
        path=path,
        reason="restricted_app_empty_acl_saved",
    )
    return True


def get_acl_entries_for_admin(app_id: str) -> List[Dict[str, Any]]:
    """Get ACL entries enriched for admin UI."""
    entries = get_app_acl_entries(app_id, strict=True)
    events = get_all_events()
    enriched: List[Dict[str, Any]] = []
    for entry in entries:
        principal_type = entry.get("principal_type")
        principal_ref = entry.get("principal_ref")

        display_label = principal_ref
        display_kind = "email"
        if principal_type == PRINCIPAL_TYPE_GROUP_ADMINS and principal_ref == GROUP_ADMINS_ALL:
            display_label = "All admins"
            display_kind = "group"
        elif principal_type == PRINCIPAL_TYPE_GROUP_EVENT_ATTENDEES:
            event_name = events.get(principal_ref, {}).get("name", principal_ref)
            display_label = f"All attendees: {event_name}"
            display_kind = "group"

        enriched.append(
            {
                "principal_type": principal_type,
                "principal_ref": principal_ref,
                "role": entry.get("role") or ACL_ROLE_MEMBER,
                "display_label": display_label,
                "display_kind": display_kind,
            }
        )

    return enriched


def delete_acl_entries_for_email(user_email: str) -> int:
    """Delete ACL email principals for a user email."""
    normalized_email = normalize_email(user_email)
    records = get_records("app_access_entries", limit=1000)
    delete_ids = [
        record.get("id")
        for record in records
        if record.get("fields", {}).get("principal_type") == PRINCIPAL_TYPE_EMAIL
        and normalize_email(record.get("fields", {}).get("principal_ref", "")) == normalized_email
    ]
    delete_ids = [record_id for record_id in delete_ids if record_id]
    if not delete_ids:
        return 0

    if delete_records_batch("app_access_entries", delete_ids):
        return len(delete_ids)
    return 0


def count_acl_entries_for_email(user_email: str) -> int:
    """Count remaining ACL email principals for verification."""
    normalized_email = normalize_email(user_email)
    records = get_records("app_access_entries", limit=1000)
    return sum(
        1
        for record in records
        if record.get("fields", {}).get("principal_type") == PRINCIPAL_TYPE_EMAIL
        and normalize_email(record.get("fields", {}).get("principal_ref", "")) == normalized_email
    )
