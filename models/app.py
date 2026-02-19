"""App models and database operations for OAuth/SAML applications."""

from __future__ import annotations

import json
import re
import secrets
from typing import Any, Dict, List, Optional, Set

from utils.teable import (
    create_record,
    create_table_field,
    find_record_by_field,
    get_records,
    get_table_field_names,
    update_record,
)

APP_TYPE_OAUTH = "oauth"
APP_TYPE_SAML = "saml"
SUPPORTED_APP_TYPES = {APP_TYPE_OAUTH, APP_TYPE_SAML}
SAML_DEFAULT_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
SAML_DEFAULT_ACS_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"

OAUTH_ONLY_FIELDS = {
    "redirect_uris",
    "allowed_scopes",
    "skip_consent_screen",
    "client_secret",
}

SAML_ONLY_FIELDS = {
    "saml_metadata_url",
    "saml_entity_id",
    "saml_acs_url",
    "saml_acs_binding",
    "saml_slo_url",
    "saml_nameid_format",
    "saml_attribute_mapping",
    "saml_require_signed_authn_request",
    "saml_enabled",
    "saml_sp_signing_certs_json",
    "saml_metadata_etag",
    "saml_metadata_last_fetched_at",
    "saml_metadata_last_applied_at",
    "saml_metadata_pending_diff_json",
    "saml_metadata_sync_error",
}

OPTIONAL_APP_FIELDS = {
    "skip_consent_screen": {
        "name": "skip_consent_screen",
        "type": "checkbox",
        "options": {},
    },
    "app_type": {
        "name": "app_type",
        "type": "singleSelect",
        "options": {
            "choices": [
                {"name": APP_TYPE_OAUTH, "color": "blue"},
                {"name": APP_TYPE_SAML, "color": "green"},
            ]
        },
    },
    "saml_metadata_url": {
        "name": "saml_metadata_url",
        "type": "singleLineText",
        "options": {},
    },
    "saml_entity_id": {
        "name": "saml_entity_id",
        "type": "singleLineText",
        "options": {},
    },
    "saml_acs_url": {
        "name": "saml_acs_url",
        "type": "singleLineText",
        "options": {},
    },
    "saml_acs_binding": {
        "name": "saml_acs_binding",
        "type": "singleLineText",
        "options": {},
    },
    "saml_slo_url": {
        "name": "saml_slo_url",
        "type": "singleLineText",
        "options": {},
    },
    "saml_nameid_format": {
        "name": "saml_nameid_format",
        "type": "singleLineText",
        "options": {},
    },
    "saml_attribute_mapping": {
        "name": "saml_attribute_mapping",
        "type": "longText",
        "options": {},
    },
    "saml_require_signed_authn_request": {
        "name": "saml_require_signed_authn_request",
        "type": "checkbox",
        "options": {},
    },
    "saml_enabled": {
        "name": "saml_enabled",
        "type": "checkbox",
        "options": {},
    },
    "saml_sp_signing_certs_json": {
        "name": "saml_sp_signing_certs_json",
        "type": "longText",
        "options": {},
    },
    "saml_metadata_etag": {
        "name": "saml_metadata_etag",
        "type": "singleLineText",
        "options": {},
    },
    "saml_metadata_last_fetched_at": {
        "name": "saml_metadata_last_fetched_at",
        "type": "singleLineText",
        "options": {},
    },
    "saml_metadata_last_applied_at": {
        "name": "saml_metadata_last_applied_at",
        "type": "singleLineText",
        "options": {},
    },
    "saml_metadata_pending_diff_json": {
        "name": "saml_metadata_pending_diff_json",
        "type": "longText",
        "options": {},
    },
    "saml_metadata_sync_error": {
        "name": "saml_metadata_sync_error",
        "type": "longText",
        "options": {},
    },
}


def generate_client_credentials() -> tuple[str, str]:
    """Generate OAuth 2.0 client credentials."""
    client_id = f"app_{secrets.token_urlsafe(16)}"
    client_secret = secrets.token_urlsafe(32)
    return client_id, client_secret


def validate_redirect_uri(redirect_uri: str, allowed_uris: List[str]) -> bool:
    """
    Validate that a redirect URI exactly matches one of the allowed URIs.
    OAuth 2.0 requires exact match for security.
    """
    return redirect_uri in allowed_uris


def _parse_json_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if not value:
        return []
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, list) else []
    except (TypeError, ValueError):
        return []


def _parse_json_obj(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not value:
        return {}
    try:
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    except (TypeError, ValueError):
        return {}


def _serialize_json(value: Any) -> str:
    return json.dumps(value or {})


def _ensure_optional_app_fields() -> Set[str]:
    """
    Ensure optional fields needed by modern apps UI exist.
    Returns current field names after best-effort provisioning.
    """
    field_names = get_table_field_names("apps")
    for field_name, field_config in OPTIONAL_APP_FIELDS.items():
        if field_name in field_names:
            continue
        create_table_field("apps", field_config)

    return get_table_field_names("apps")


def _validate_app_type(app_type: str) -> Optional[str]:
    if app_type not in SUPPORTED_APP_TYPES:
        return f"Invalid app_type '{app_type}'. Supported types: oauth, saml"
    return None


def _default_attribute_mapping_json() -> str:
    return json.dumps(
        [
            {
                "source_field": "email",
                "saml_name": "email",
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
                "required": True,
                "multi_valued": False,
                "transform": "identity",
            },
            {
                "source_field": "preferred_name",
                "saml_name": "displayName",
                "name_format": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
                "required": False,
                "multi_valued": False,
                "transform": "identity",
            },
        ]
    )


def _record_to_app_dict(record: Dict[str, Any]) -> Dict[str, Any]:
    fields = record.get("fields", {})
    app_dict = {"id": record.get("id"), **fields}
    app_dict.setdefault("skip_consent_screen", False)
    app_dict.setdefault("app_type", APP_TYPE_OAUTH)
    app_dict["redirect_uris_list"] = _parse_json_list(app_dict.get("redirect_uris"))
    app_dict["allowed_scopes_list"] = _parse_json_list(app_dict.get("allowed_scopes"))
    app_dict["saml_sp_signing_certs"] = _parse_json_list(app_dict.get("saml_sp_signing_certs_json"))
    app_dict["saml_attribute_mapping_obj"] = _parse_json_list(app_dict.get("saml_attribute_mapping"))
    app_dict["saml_metadata_pending_diff_obj"] = _parse_json_obj(
        app_dict.get("saml_metadata_pending_diff_json")
    )
    return app_dict


def get_app_by_client_id(client_id: str) -> Optional[Dict[str, Any]]:
    """Get app by client_id."""
    apps = get_records("apps", limit=1000)
    for app_record in apps:
        app = app_record.get("fields", {})
        if app.get("client_id") == client_id:
            return _record_to_app_dict(app_record)
    return None


def get_app_by_saml_entity_id(saml_entity_id: str) -> Optional[Dict[str, Any]]:
    """Get active SAML app by SP entity ID."""
    apps = get_records("apps", limit=1000)
    for app_record in apps:
        app = app_record.get("fields", {})
        if (
            app.get("app_type", APP_TYPE_OAUTH) == APP_TYPE_SAML
            and app.get("is_active")
            and app.get("saml_entity_id") == saml_entity_id
        ):
            return _record_to_app_dict(app_record)
    return None


def validate_app_redirect(redirect_url: str) -> Optional[Dict[str, Any]]:
    """
    LEGACY: Validate that a redirect URL matches a registered app's template.
    This is for backward compatibility with old token-based flow.
    Returns the app dict if valid, None otherwise.
    """
    apps = get_records("apps", limit=1000)

    for app_record in apps:
        app = app_record.get("fields", {})
        if not app.get("is_active"):
            continue

        template = app.get("redirect_url_template", "")
        if template and "{token}" in template:
            pattern = re.escape(template).replace(r"\{token\}", r"[A-Za-z0-9_-]+")
            pattern = f"^{pattern}$"
            if re.match(pattern, redirect_url):
                return _record_to_app_dict(app_record)

    return None


def get_all_apps() -> List[Dict[str, Any]]:
    """Get all apps."""
    records = get_records("apps", limit=1000)
    apps = [_record_to_app_dict(record) for record in records]
    apps.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return apps


def get_app_by_id(app_id: str) -> Optional[Dict[str, Any]]:
    """Get app by Teable record ID."""
    all_apps = get_all_apps()
    for app in all_apps:
        if app["id"] == app_id:
            return app
    return None


def create_app(
    *,
    name: str,
    created_by: str,
    app_type: str = APP_TYPE_OAUTH,
    icon: Optional[str] = None,
    allow_anyone: bool = False,
    redirect_uris: Optional[List[str]] = None,
    allowed_scopes: Optional[List[str]] = None,
    skip_consent_screen: bool = False,
    saml_metadata_url: Optional[str] = None,
    saml_entity_id: Optional[str] = None,
    saml_acs_url: Optional[str] = None,
    saml_acs_binding: Optional[str] = None,
    saml_slo_url: Optional[str] = None,
    saml_nameid_format: Optional[str] = None,
    saml_attribute_mapping: Optional[str] = None,
    saml_require_signed_authn_request: bool = False,
    saml_enabled: bool = False,
    saml_sp_signing_certs_json: Optional[str] = None,
    saml_metadata_etag: Optional[str] = None,
    saml_metadata_last_fetched_at: Optional[str] = None,
    saml_metadata_last_applied_at: Optional[str] = None,
    saml_metadata_pending_diff_json: Optional[str] = None,
    saml_metadata_sync_error: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a new OAuth or SAML app."""
    app_type_error = _validate_app_type(app_type)
    if app_type_error:
        return {"success": False, "error": app_type_error}

    if app_type == APP_TYPE_SAML and allow_anyone:
        return {"success": False, "error": "allow_anyone is not permitted for SAML apps"}

    if app_type == APP_TYPE_OAUTH:
        if not redirect_uris:
            return {"success": False, "error": "At least one redirect URI is required"}
        if allowed_scopes is None:
            allowed_scopes = ["profile", "email"]

    if app_type == APP_TYPE_SAML and saml_enabled:
        if not saml_entity_id or not saml_acs_url:
            return {
                "success": False,
                "error": "saml_entity_id and saml_acs_url are required when SAML is enabled",
            }

    client_id, client_secret = generate_client_credentials()
    if app_type == APP_TYPE_SAML:
        client_secret = ""

    try:
        apps_field_names = _ensure_optional_app_fields()
        record_data: Dict[str, Any] = {
            "name": name,
            "icon": icon or "",
            "client_id": client_id,
            "client_secret": client_secret,
            "created_by": created_by,
            "allow_anyone": allow_anyone,
            "is_active": True,
            "app_type": app_type,
        }

        if app_type == APP_TYPE_OAUTH:
            record_data["redirect_uris"] = json.dumps(redirect_uris or [])
            record_data["allowed_scopes"] = json.dumps(allowed_scopes or ["profile", "email"])
            record_data["skip_consent_screen"] = skip_consent_screen
        else:
            record_data["redirect_uris"] = "[]"
            record_data["allowed_scopes"] = "[]"
            record_data["skip_consent_screen"] = False
            record_data["saml_metadata_url"] = saml_metadata_url or ""
            record_data["saml_entity_id"] = saml_entity_id or ""
            record_data["saml_acs_url"] = saml_acs_url or ""
            record_data["saml_acs_binding"] = saml_acs_binding or SAML_DEFAULT_ACS_BINDING
            record_data["saml_slo_url"] = saml_slo_url or ""
            record_data["saml_nameid_format"] = saml_nameid_format or SAML_DEFAULT_NAMEID_FORMAT
            record_data["saml_attribute_mapping"] = saml_attribute_mapping or _default_attribute_mapping_json()
            record_data["saml_require_signed_authn_request"] = bool(saml_require_signed_authn_request)
            record_data["saml_enabled"] = bool(saml_enabled)
            record_data["saml_sp_signing_certs_json"] = (
                saml_sp_signing_certs_json or json.dumps([])
            )
            record_data["saml_metadata_etag"] = saml_metadata_etag or ""
            record_data["saml_metadata_last_fetched_at"] = saml_metadata_last_fetched_at or ""
            record_data["saml_metadata_last_applied_at"] = saml_metadata_last_applied_at or ""
            record_data["saml_metadata_pending_diff_json"] = saml_metadata_pending_diff_json or _serialize_json({})
            record_data["saml_metadata_sync_error"] = saml_metadata_sync_error or ""

        for key in list(record_data.keys()):
            if key in OPTIONAL_APP_FIELDS and key not in apps_field_names:
                record_data.pop(key, None)

        result = create_record("apps", record_data)
        if result and "records" in result and len(result["records"]) > 0:
            payload = {
                "success": True,
                "app_id": result["records"][0]["id"],
                "client_id": client_id,
            }
            if app_type == APP_TYPE_OAUTH:
                payload["client_secret"] = client_secret
            return payload
        return {"success": False, "error": "Failed to create app record"}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}


def update_app(
    app_id: str,
    *,
    name: Optional[str] = None,
    icon: Optional[str] = None,
    redirect_uris: Optional[List[str]] = None,
    allowed_scopes: Optional[List[str]] = None,
    allow_anyone: Optional[bool] = None,
    skip_consent_screen: Optional[bool] = None,
    app_type: Optional[str] = None,
    saml_metadata_url: Optional[str] = None,
    saml_entity_id: Optional[str] = None,
    saml_acs_url: Optional[str] = None,
    saml_acs_binding: Optional[str] = None,
    saml_slo_url: Optional[str] = None,
    saml_nameid_format: Optional[str] = None,
    saml_attribute_mapping: Optional[str] = None,
    saml_require_signed_authn_request: Optional[bool] = None,
    saml_enabled: Optional[bool] = None,
    saml_sp_signing_certs_json: Optional[str] = None,
    saml_metadata_etag: Optional[str] = None,
    saml_metadata_last_fetched_at: Optional[str] = None,
    saml_metadata_last_applied_at: Optional[str] = None,
    saml_metadata_pending_diff_json: Optional[str] = None,
    saml_metadata_sync_error: Optional[str] = None,
) -> Dict[str, Any]:
    """Update an existing OAuth/SAML app."""
    existing = get_app_by_id(app_id)
    if not existing:
        return {"success": False, "error": "App not found"}

    target_type = app_type or existing.get("app_type", APP_TYPE_OAUTH)
    app_type_error = _validate_app_type(target_type)
    if app_type_error:
        return {"success": False, "error": app_type_error}

    update_data: Dict[str, Any] = {}
    if name is not None:
        update_data["name"] = name
    if icon is not None:
        update_data["icon"] = icon
    if app_type is not None:
        update_data["app_type"] = app_type

    target_allow_anyone = existing.get("allow_anyone", False) if allow_anyone is None else bool(allow_anyone)
    if target_type == APP_TYPE_SAML and target_allow_anyone:
        return {"success": False, "error": "allow_anyone is not permitted for SAML apps"}
    if allow_anyone is not None:
        update_data["allow_anyone"] = bool(allow_anyone)

    if target_type == APP_TYPE_OAUTH:
        if redirect_uris is not None:
            if len(redirect_uris) == 0:
                return {"success": False, "error": "At least one redirect URI is required"}
            update_data["redirect_uris"] = json.dumps(redirect_uris)
        if allowed_scopes is not None:
            update_data["allowed_scopes"] = json.dumps(allowed_scopes)
        if skip_consent_screen is not None:
            update_data["skip_consent_screen"] = bool(skip_consent_screen)
    else:
        if skip_consent_screen is not None:
            return {"success": False, "error": "skip_consent_screen is not supported for SAML apps"}
        if redirect_uris is not None:
            return {"success": False, "error": "redirect_uris is not supported for SAML apps"}
        if allowed_scopes is not None:
            return {"success": False, "error": "allowed_scopes is not supported for SAML apps"}

    saml_fields = {
        "saml_metadata_url": saml_metadata_url,
        "saml_entity_id": saml_entity_id,
        "saml_acs_url": saml_acs_url,
        "saml_acs_binding": saml_acs_binding,
        "saml_slo_url": saml_slo_url,
        "saml_nameid_format": saml_nameid_format,
        "saml_attribute_mapping": saml_attribute_mapping,
        "saml_require_signed_authn_request": saml_require_signed_authn_request,
        "saml_enabled": saml_enabled,
        "saml_sp_signing_certs_json": saml_sp_signing_certs_json,
        "saml_metadata_etag": saml_metadata_etag,
        "saml_metadata_last_fetched_at": saml_metadata_last_fetched_at,
        "saml_metadata_last_applied_at": saml_metadata_last_applied_at,
        "saml_metadata_pending_diff_json": saml_metadata_pending_diff_json,
        "saml_metadata_sync_error": saml_metadata_sync_error,
    }

    if target_type == APP_TYPE_OAUTH:
        for key, value in saml_fields.items():
            if value is not None:
                return {"success": False, "error": f"{key} is only supported for SAML apps"}
    else:
        for key, value in saml_fields.items():
            if value is None:
                continue
            if key in {
                "saml_require_signed_authn_request",
                "saml_enabled",
            }:
                update_data[key] = bool(value)
            else:
                update_data[key] = value

        effective_saml_enabled = (
            update_data.get("saml_enabled")
            if "saml_enabled" in update_data
            else bool(existing.get("saml_enabled"))
        )
        effective_entity = update_data.get("saml_entity_id", existing.get("saml_entity_id", ""))
        effective_acs = update_data.get("saml_acs_url", existing.get("saml_acs_url", ""))
        if effective_saml_enabled and (not effective_entity or not effective_acs):
            return {
                "success": False,
                "error": "saml_entity_id and saml_acs_url are required when SAML is enabled",
            }

    if not update_data:
        return {"success": False, "error": "No fields to update"}

    try:
        apps_field_names = _ensure_optional_app_fields()
        for key in list(update_data.keys()):
            if key in OPTIONAL_APP_FIELDS and key not in apps_field_names:
                return {
                    "success": False,
                    "error": f"Apps table is missing required field '{key}'. Please run migration/bootstrap.",
                }
        update_record("apps", app_id, update_data)
        return {"success": True}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}


def regenerate_client_secret(app_id: str) -> Dict[str, Any]:
    """Regenerate client_secret for an OAuth app."""
    app = get_app_by_id(app_id)
    if not app:
        return {"success": False, "error": "App not found"}
    if app.get("app_type") == APP_TYPE_SAML:
        return {"success": False, "error": "SAML apps do not use client_secret"}

    try:
        new_secret = secrets.token_urlsafe(32)
        update_record("apps", app_id, {"client_secret": new_secret})
        return {"success": True, "client_secret": new_secret}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}


def delete_app(app_id: str) -> Dict[str, Any]:
    """Soft delete an app (set is_active to FALSE)."""
    try:
        update_record("apps", app_id, {"is_active": False})
        return {"success": True}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}


def reactivate_app(app_id: str) -> Dict[str, Any]:
    """Reactivate a deleted app."""
    try:
        update_record("apps", app_id, {"is_active": True})
        return {"success": True}
    except Exception as exc:  # noqa: BLE001
        return {"success": False, "error": str(exc)}


def has_app_permission(admin_email: str, app_id: str, access_level: str = "read") -> bool:
    """
    LEGACY helper.

    Check if admin has permission to access an app.
    access_level can be 'read' or 'write'.
    """
    from models.admin import get_admin_permissions, is_system_admin

    def _level_allows(perm_level: str) -> bool:
        return perm_level == access_level or (
            perm_level == "write" and access_level == "read"
        )

    if is_system_admin(admin_email):
        return True

    all_permissions = get_admin_permissions(admin_email)
    for perm in all_permissions:
        ptype = perm.get("permission_type")
        pvalue = perm.get("permission_value")
        plevel = perm.get("access_level")

        if ptype == "*" and pvalue == "*" and _level_allows(plevel):
            return True
        if ptype == "app" and pvalue == "*" and _level_allows(plevel):
            return True
        if ptype == "app" and pvalue == str(app_id) and _level_allows(plevel):
            return True

    return False
