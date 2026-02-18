"""Helpers for universal-admin fail-open snapshots in session."""

from __future__ import annotations

import time
from typing import Any, Mapping, MutableMapping, Optional, Tuple

from models.admin import has_universal_write_permission, is_admin
from utils.validation import normalize_email

SNAPSHOT_TTL_SECONDS = 60 * 60


def write_universal_admin_snapshot(email: str, sess: MutableMapping[str, Any]) -> bool:
    """Write or clear the session snapshot. Returns True if snapshot is active."""
    normalized_email = normalize_email(email)
    if is_admin(normalized_email) and has_universal_write_permission(normalized_email):
        sess["uw_admin"] = True
        sess["uw_admin_verified_at"] = int(time.time())
        return True

    sess.pop("uw_admin", None)
    sess.pop("uw_admin_verified_at", None)
    return False


def snapshot_age_seconds(sess: Mapping[str, Any], now_epoch: Optional[int] = None) -> Optional[int]:
    """Return snapshot age in seconds when present and parseable."""
    verified_at = sess.get("uw_admin_verified_at")
    if verified_at is None:
        return None

    try:
        verified_at_int = int(verified_at)
    except (TypeError, ValueError):
        return None

    now = int(now_epoch if now_epoch is not None else time.time())
    return max(0, now - verified_at_int)


def has_valid_universal_admin_snapshot(
    sess: Mapping[str, Any],
    now_epoch: Optional[int] = None,
) -> Tuple[bool, Optional[int]]:
    """Return tuple(valid, snapshot_age_seconds)."""
    if sess.get("uw_admin") is not True:
        return False, snapshot_age_seconds(sess, now_epoch)

    age_seconds = snapshot_age_seconds(sess, now_epoch)
    if age_seconds is None:
        return False, None

    return age_seconds <= SNAPSHOT_TTL_SECONDS, age_seconds
