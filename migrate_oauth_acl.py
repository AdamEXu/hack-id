"""OAuth ACL migration script.

Steps:
1. Attempt to create `app_type` field on apps table if missing.
2. Backfill `app_type='oauth'` on existing apps where empty.
3. Seed `group_admins:all_admins` ACL for restricted apps with no ACL entries.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import requests

from config import (
    TEABLE_API_URL,
    TEABLE_ACCESS_TOKEN,
    TEABLE_TABLE_APPS,
)
from utils.teable import (
    TEABLE_TABLE_IDS,
    create_record,
    get_records,
    update_record,
)


def _headers() -> dict:
    return {
        "Authorization": f"Bearer {TEABLE_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }


def ensure_app_optional_fields() -> list[dict]:
    """Best-effort optional field creation for existing environments."""
    if not TEABLE_TABLE_APPS:
        return [{"field": "*", "created": False, "skipped": True, "error": "TEABLE_TABLE_APPS not configured"}]

    field_payloads = [
        {
            "name": "skip_consent_screen",
            "type": "checkbox",
            "options": {},
        },
        {
            "name": "app_type",
            "type": "singleSelect",
            "options": {
                "choices": [
                    {"name": "oauth", "color": "blue"},
                    {"name": "saml", "color": "green"},
                ]
            },
        },
    ]

    results = []
    url = f"{TEABLE_API_URL}/table/{TEABLE_TABLE_APPS}/field"
    for payload in field_payloads:
        response = requests.post(url, headers=_headers(), json=payload, timeout=15)
        if response.status_code in (200, 201):
            results.append({"field": payload["name"], "created": True, "skipped": False, "error": None})
            continue

        # Already exists is expected on reruns.
        if response.status_code in (400, 409):
            results.append({"field": payload["name"], "created": False, "skipped": True, "error": None})
            continue

        results.append(
            {
                "field": payload["name"],
                "created": False,
                "skipped": False,
                "error": f"field create failed: {response.status_code} {response.text}",
            }
        )

    return results


def _app_acl_entries_by_app() -> dict[str, list[dict]]:
    rows = get_records("app_access_entries", limit=1000)
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        app_id = row.get("fields", {}).get("app_id")
        if not app_id:
            continue
        grouped.setdefault(app_id, []).append(row)
    return grouped


def run_migration() -> dict:
    report = {
        "field_create": [],
        "apps_scanned": 0,
        "app_type_backfilled": 0,
        "acl_seeded": 0,
        "acl_seed_skipped_existing": 0,
        "errors": [],
    }

    report["field_create"] = ensure_app_optional_fields()
    for field_result in report["field_create"]:
        if field_result["error"]:
            report["errors"].append(field_result["error"])

    apps = get_records("apps", limit=1000)
    acl_by_app = _app_acl_entries_by_app()
    report["apps_scanned"] = len(apps)

    now_iso = datetime.now(timezone.utc).isoformat()
    for app_record in apps:
        app_id = app_record.get("id")
        fields = app_record.get("fields", {})

        if not fields.get("app_type"):
            updated = update_record("apps", app_id, {"app_type": "oauth"})
            if updated:
                report["app_type_backfilled"] += 1
            else:
                report["errors"].append(f"Failed to backfill app_type for app_id={app_id}")

        allow_anyone = bool(fields.get("allow_anyone"))
        has_acl = bool(acl_by_app.get(app_id))
        if allow_anyone:
            continue
        if has_acl:
            report["acl_seed_skipped_existing"] += 1
            continue

        seeded = create_record(
            "app_access_entries",
            {
                "app_id": app_id,
                "principal_type": "group_admins",
                "principal_ref": "all_admins",
                "role": "member",
                "created_by": "migration",
                "created_at": now_iso,
            },
        )
        if seeded:
            report["acl_seeded"] += 1
        else:
            report["errors"].append(f"Failed to seed ACL for restricted app_id={app_id}")

    return report


def main() -> None:
    if not TEABLE_ACCESS_TOKEN:
        raise RuntimeError("TEABLE_ACCESS_TOKEN is required")
    required_tables = ["apps", "app_access_entries", "app_access_audit"]
    missing = [name for name in required_tables if not TEABLE_TABLE_IDS.get(name)]
    if missing:
        raise RuntimeError(
            f"Missing required table env vars for: {', '.join(missing)}"
        )

    report = run_migration()
    print(json.dumps(report, indent=2, sort_keys=True))

    if report["errors"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
