"""Daily SAML metadata sync job.

Behavior:
- Fetches metadata for each SAML app with a metadata URL.
- Stages diffs for admin approval.
- Auto-applies non-material changes.
- Never auto-applies material changes.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from typing import Any, Dict, List

from models.app import APP_TYPE_SAML, get_all_apps, get_app_by_id, update_app
from services.saml_audit_service import log_saml_event
from services.saml_metadata_service import (
    apply_staged_metadata_update,
    check_metadata_url_health,
    stage_app_metadata_update,
)


def _sync_one_app(app: Dict[str, Any]) -> Dict[str, Any]:
    app_id = app.get("id")
    metadata_url = (app.get("saml_metadata_url") or "").strip()
    if not metadata_url:
        return {
            "app_id": app_id,
            "status": "skipped",
            "reason": "missing_metadata_url",
        }

    health = check_metadata_url_health(metadata_url)
    if not health.get("success"):
        update_app(app_id, saml_metadata_sync_error=health.get("error", "metadata fetch failed"))
        log_saml_event(
            event_type="metadata_sync",
            app_id=app_id,
            sp_entity_id=app.get("saml_entity_id"),
            outcome="error",
            reason=health.get("error", "metadata fetch failed"),
            details={"source": "cron"},
        )
        return {
            "app_id": app_id,
            "status": "error",
            "reason": health.get("error", "metadata fetch failed"),
        }

    staged = stage_app_metadata_update(app_id, health["incoming"])
    if not staged.get("success"):
        return {
            "app_id": app_id,
            "status": "error",
            "reason": staged.get("error", "failed_to_stage"),
        }

    has_material = bool(staged["pending"]["diff"].get("has_material_change"))
    if has_material:
        log_saml_event(
            event_type="metadata_sync",
            app_id=app_id,
            sp_entity_id=app.get("saml_entity_id"),
            outcome="success",
            reason="staged_requires_approval",
            details={"source": "cron"},
        )
        return {
            "app_id": app_id,
            "status": "staged",
            "requires_approval": True,
        }

    applied = apply_staged_metadata_update(app_id)
    if not applied.get("success"):
        return {
            "app_id": app_id,
            "status": "error",
            "reason": applied.get("error", "failed_to_apply_non_material"),
        }

    log_saml_event(
        event_type="metadata_sync",
        app_id=app_id,
        sp_entity_id=app.get("saml_entity_id"),
        outcome="success",
        reason="auto_applied_non_material",
        details={"source": "cron"},
    )
    return {
        "app_id": app_id,
        "status": "applied",
        "requires_approval": False,
    }


def _select_apps(app_id: str | None) -> List[Dict[str, Any]]:
    if app_id:
        app = get_app_by_id(app_id)
        if not app:
            return []
        return [app]

    apps = get_all_apps()
    selected = []
    for app in apps:
        if app.get("app_type") != APP_TYPE_SAML:
            continue
        if not app.get("is_active"):
            continue
        selected.append(app)
    return selected


def run_sync(app_id: str | None = None) -> Dict[str, Any]:
    apps = _select_apps(app_id)
    results = [_sync_one_app(app) for app in apps]

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "apps_considered": len(apps),
        "results": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run SAML metadata sync")
    parser.add_argument("--app-id", help="Sync a single app ID", default=None)
    args = parser.parse_args()

    report = run_sync(app_id=args.app_id)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
