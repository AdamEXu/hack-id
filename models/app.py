"""App models and database operations for OAuth 2.0 enabled external applications using Teable."""

import re
import json
import secrets
from typing import Dict, List, Any, Optional
from utils.teable import (
    create_record,
    get_records,
    update_record,
    find_record_by_field,
    get_table_field_names,
    create_table_field,
)

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
                {"name": "oauth", "color": "blue"},
                {"name": "saml", "color": "green"},
            ]
        },
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


def get_app_by_client_id(client_id: str) -> Optional[Dict[str, Any]]:
    """Get app by client_id."""
    apps = get_records('apps', limit=1000)

    for app_record in apps:
        app = app_record['fields']
        if app.get('client_id') == client_id:
            return {
                "id": app_record['id'],
                **app
            }

    return None


def validate_app_redirect(redirect_url: str) -> Optional[Dict[str, Any]]:
    """
    LEGACY: Validate that a redirect URL matches a registered app's template.
    This is for backward compatibility with old token-based flow.
    Returns the app dict if valid, None otherwise.
    """
    apps = get_records('apps', limit=1000)

    for app_record in apps:
        app = app_record['fields']
        if not app.get('is_active'):
            continue

        # Check if app has old redirect_url_template (legacy)
        template = app.get("redirect_url_template", "")
        if template and "{token}" in template:
            # Convert template to regex pattern
            pattern = re.escape(template).replace(r"\{token\}", r"[A-Za-z0-9_-]+")
            pattern = f"^{pattern}$"

            if re.match(pattern, redirect_url):
                return {
                    "id": app_record['id'],
                    **app
                }

    return None


def get_all_apps() -> List[Dict[str, Any]]:
    """Get all apps."""
    records = get_records('apps', limit=1000)

    apps = []
    for record in records:
        app_dict = {
            "id": record['id'],
            **record['fields']
        }
        app_dict.setdefault("skip_consent_screen", False)
        app_dict.setdefault("app_type", "oauth")
        apps.append(app_dict)

    # Sort by most recent first
    apps.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    return apps


def get_app_by_id(app_id: str) -> Optional[Dict[str, Any]]:
    """Get app by Teable record ID."""
    all_apps = get_all_apps()
    for app in all_apps:
        if app['id'] == app_id:
            return app
    return None


def _ensure_optional_app_fields() -> set[str]:
    """
    Ensure optional fields needed by the modern apps UI exist.
    Returns current field names after best-effort provisioning.
    """
    field_names = get_table_field_names("apps")
    for field_name, field_config in OPTIONAL_APP_FIELDS.items():
        if field_name in field_names:
            continue
        create_table_field("apps", field_config)

    return get_table_field_names("apps")


def create_app(
    name: str,
    redirect_uris: List[str],
    created_by: str,
    icon: Optional[str] = None,
    allowed_scopes: Optional[List[str]] = None,
    allow_anyone: bool = False,
    skip_consent_screen: bool = False,
    app_type: str = "oauth",
) -> Dict[str, Any]:
    """Create a new OAuth 2.0 app with client credentials."""
    if not redirect_uris or len(redirect_uris) == 0:
        return {
            "success": False,
            "error": "At least one redirect URI is required"
        }

    # Generate OAuth 2.0 credentials
    client_id, client_secret = generate_client_credentials()

    # Default scopes if not provided
    if allowed_scopes is None:
        allowed_scopes = ["profile", "email"]

    try:
        apps_field_names = _ensure_optional_app_fields()

        record_data = {
            "name": name,
            "icon": icon or "",
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uris": json.dumps(redirect_uris),
            "allowed_scopes": json.dumps(allowed_scopes),
            "created_by": created_by,
            "allow_anyone": allow_anyone,
            "is_active": True
        }

        if "skip_consent_screen" in apps_field_names:
            record_data["skip_consent_screen"] = skip_consent_screen
        elif skip_consent_screen:
            return {
                "success": False,
                "error": "Apps table is missing skip_consent_screen. Please run migration/bootstrap.",
            }

        if "app_type" in apps_field_names:
            record_data["app_type"] = app_type
        elif app_type and app_type != "oauth":
            return {
                "success": False,
                "error": "Apps table is missing app_type. Please run migration/bootstrap.",
            }

        result = create_record('apps', record_data)
        if result and 'records' in result and len(result['records']) > 0:
            return {
                "success": True,
                "app_id": result['records'][0]['id'],
                "client_id": client_id,
                "client_secret": client_secret
            }
        return {"success": False, "error": "Failed to create app record"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def update_app(
    app_id: str,
    name: Optional[str] = None,
    icon: Optional[str] = None,
    redirect_uris: Optional[List[str]] = None,
    allowed_scopes: Optional[List[str]] = None,
    allow_anyone: Optional[bool] = None,
    skip_consent_screen: Optional[bool] = None,
    app_type: Optional[str] = None,
) -> Dict[str, Any]:
    """Update an existing OAuth 2.0 app."""
    # Build update data
    update_data = {}

    if name is not None:
        update_data["name"] = name

    if icon is not None:
        update_data["icon"] = icon

    if redirect_uris is not None:
        if len(redirect_uris) == 0:
            return {
                "success": False,
                "error": "At least one redirect URI is required"
            }
        update_data["redirect_uris"] = json.dumps(redirect_uris)

    if allowed_scopes is not None:
        update_data["allowed_scopes"] = json.dumps(allowed_scopes)

    if allow_anyone is not None:
        update_data["allow_anyone"] = allow_anyone

    if skip_consent_screen is not None:
        update_data["skip_consent_screen"] = skip_consent_screen

    if app_type is not None:
        update_data["app_type"] = app_type

    if not update_data:
        return {"success": False, "error": "No fields to update"}

    try:
        apps_field_names = _ensure_optional_app_fields()

        if "skip_consent_screen" not in apps_field_names and "skip_consent_screen" in update_data:
            return {
                "success": False,
                "error": "Apps table is missing skip_consent_screen. Please run migration/bootstrap.",
            }

        if "app_type" not in apps_field_names and "app_type" in update_data:
            return {
                "success": False,
                "error": "Apps table is missing app_type. Please run migration/bootstrap.",
            }

        if "skip_consent_screen" not in apps_field_names:
            update_data.pop("skip_consent_screen", None)
        if "app_type" not in apps_field_names:
            update_data.pop("app_type", None)

        update_record('apps', app_id, update_data)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def regenerate_client_secret(app_id: str) -> Dict[str, Any]:
    """Regenerate client_secret for an app."""
    try:
        # Generate new secret
        new_secret = secrets.token_urlsafe(32)

        # Update in Teable
        update_record('apps', app_id, {"client_secret": new_secret})

        return {
            "success": True,
            "client_secret": new_secret
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def delete_app(app_id: str) -> Dict[str, Any]:
    """Soft delete an app (set is_active to FALSE)."""
    try:
        update_record('apps', app_id, {"is_active": False})
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def reactivate_app(app_id: str) -> Dict[str, Any]:
    """Reactivate a deleted app."""
    try:
        update_record('apps', app_id, {"is_active": True})
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def has_app_permission(admin_email: str, app_id: str, access_level: str = "read") -> bool:
    """
    LEGACY helper.

    Check if admin has permission to access an app.
    access_level can be 'read' or 'write'.
    """
    from models.admin import is_system_admin, get_admin_permissions

    def _level_allows(perm_level: str) -> bool:
        """Return True if perm_level satisfies the requested access_level.

        Mirrors has_page_permission/has_event_permission semantics: a
        'write' permission implies 'read', but not vice versa.
        """
        return perm_level == access_level or (
            perm_level == "write" and access_level == "read"
        )

    # System admin has all permissions
    if is_system_admin(admin_email):
        return True

    all_permissions = get_admin_permissions(admin_email)

    for perm in all_permissions:
        ptype = perm.get('permission_type')
        pvalue = perm.get('permission_value')
        plevel = perm.get('access_level')

        # Check for universal permission (*)
        if ptype == '*' and pvalue == '*' and _level_allows(plevel):
            return True

        # Check for wildcard permission (all apps)
        if ptype == 'app' and pvalue == '*' and _level_allows(plevel):
            return True

        # Check for specific app permission
        if ptype == 'app' and pvalue == str(app_id) and _level_allows(plevel):
            return True

    return False
