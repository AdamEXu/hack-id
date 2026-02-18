"""Admin routes for user and API key management."""
from flask import (
    Blueprint,
    render_template,
    redirect,
    request,
    session,
    jsonify,
    make_response,
)

# CSRF exemption will be handled in app.py
from models.user import get_all_users
from models.api_key import (
    get_all_api_keys,
    create_api_key,
    update_api_key,
    delete_api_key,
    get_api_key_logs,
)
from utils.events import get_all_events, get_current_event
from models.admin import (
    is_admin,
    get_all_admins,
    add_admin,
    remove_admin,
    get_admin_permissions,
    grant_permission,
    revoke_permission,
    has_page_permission,
)
from models.app import (
    get_all_apps,
    create_app,
    update_app,
    delete_app,
    get_app_by_id,
    regenerate_client_secret,
)
from services.app_access_service import (
    get_acl_entries_for_admin,
    replace_app_acl_entries,
    log_if_restricted_app_acl_empty,
)
from services.universal_admin_snapshot import write_universal_admin_snapshot

admin_bp = Blueprint("admin", __name__)


def refresh_universal_admin_snapshot():
    """Refresh universal-write admin snapshot for fail-open eligibility."""
    if "user_email" not in session:
        return
    write_universal_admin_snapshot(session["user_email"], session)


def require_admin(f):
    """Decorator to require admin authentication."""

    def wrapper(*args, **kwargs):
        if "user_email" not in session:
            return jsonify({"success": False, "error": "Not authenticated"}), 401

        if not is_admin(session["user_email"]):
            return jsonify({"success": False, "error": "Unauthorized"}), 403

        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper


def get_admin_page_permissions():
    """Get page permissions for current admin user."""
    if "user_email" not in session:
        return {}

    email = session["user_email"]
    pages = ["attendees", "events", "keys", "admins", "apps"]
    permissions = {}

    for page in pages:
        permissions[page] = {
            "read": has_page_permission(email, page, "read"),
            "write": has_page_permission(email, page, "write")
        }

    return permissions


def get_admin_layout_context():
    """Common template context for admin layout pages."""
    return {
        "admin_name": session.get("user_name", "Admin"),
        "permissions": get_admin_page_permissions(),
        "acl_fail_open_used": bool(session.get("acl_fail_open_used")),
    }


def require_page_permission(page_name, access_level="read"):
    """Decorator to require specific page permission."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            if "user_email" not in session:
                return jsonify({"success": False, "error": "Not authenticated"}), 401

            if not is_admin(session["user_email"]):
                return jsonify({"success": False, "error": "Unauthorized"}), 403

            # Check if user has permission for this page
            if not has_page_permission(session["user_email"], page_name, access_level):
                return jsonify({
                    "success": False,
                    "error": f"You don't have permission to access this page. Required: {page_name} ({access_level})"
                }), 403

            result = f(*args, **kwargs)
            response = make_response(result)
            if access_level == "write" and response.status_code < 400:
                refresh_universal_admin_snapshot()
            return result

        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


def require_page_permission_html(page_name, access_level="read"):
    """Decorator to require page permission and render HTML 403 on denial."""
    def decorator(f):
        def wrapper(*args, **kwargs):
            if "user_email" not in session:
                return redirect("/")

            if not is_admin(session["user_email"]):
                return render_template(
                    "admin_forbidden.html",
                    required_page=page_name,
                    required_access=access_level,
                ), 403

            if not has_page_permission(session["user_email"], page_name, access_level):
                return render_template(
                    "admin_forbidden.html",
                    required_page=page_name,
                    required_access=access_level,
                ), 403

            result = f(*args, **kwargs)
            response = make_response(result)
            if access_level == "write" and response.status_code < 400:
                refresh_universal_admin_snapshot()
            return result

        wrapper.__name__ = f.__name__
        return wrapper
    return decorator


@admin_bp.route("/admin/")
@require_admin
def admin_redirect():
    return redirect("/admin")


@admin_bp.route("/admin")
@require_admin
def admin_dashboard():
    """Admin dashboard - new layout."""
    return render_template("admin_layout.html", **get_admin_layout_context())


@admin_bp.route("/admin/attendees")
@require_admin
def admin_attendees():
    """Admin attendees page - new layout."""
    return render_template("admin_layout.html", **get_admin_layout_context())


@admin_bp.route("/admin/users/data", methods=["GET"])
@require_page_permission("attendees", "read")
def get_users_data():
    """Get all users data for DataTables."""
    try:
        # Get all users from Teable
        users = get_all_users()

        # Get all admins to create admin lookup
        admins = get_all_admins()
        admin_lookup = {admin['email']: admin for admin in admins}

        # Merge user and admin data
        users_data = []
        for user in users:
            # Check if user is an admin
            admin_info = admin_lookup.get(user['email'])
            user['is_admin'] = admin_info is not None
            if admin_info:
                user['added_by'] = admin_info.get('added_by')
                user['added_at'] = admin_info.get('added_at')
                user['is_active'] = admin_info.get('is_active')

            users_data.append(user)

        # Sort by most recent first (by id)
        users_data.sort(key=lambda x: x.get('id', ''), reverse=True)

        return jsonify({"success": True, "data": users_data})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/events")
@require_admin
def admin_events():
    """Admin events page - new layout."""
    return render_template("admin_layout.html", **get_admin_layout_context())


@admin_bp.route("/admin/events/data", methods=["GET"])
@require_page_permission("events", "read")
def get_events_data():
    """Get events data for DataTables - requires events read permission."""
    try:
        from utils.events import get_all_events
        from models.user import get_users_by_event

        events = get_all_events()
        events_list = []

        for event_id, event_data in events.items():
            # Skip config
            if event_id.startswith('_'):
                continue

            # Get user count for this event
            users = get_users_by_event(event_id)
            user_count = len(users)

            events_list.append({
                "id": event_id,
                "name": event_data.get("name", event_id),
                "description": event_data.get("description", ""),
                "color": event_data.get("color", "00CCFF"),
                "discord_role_id": event_data.get("discord-role-id", ""),
                "discord_name": event_data.get("discord-name", ""),
                "legacy": event_data.get("legacy", False),
                "user_count": user_count
            })

        # Sort by user count descending
        events_list.sort(key=lambda x: x["user_count"], reverse=True)

        return jsonify({"data": events_list})

    except Exception as e:
        if DEBUG_MODE:
            print(f"Error in get_events_data: {e}")
        return jsonify({"data": [], "error": str(e)})


@admin_bp.route("/admin/keys")
@require_admin
def admin_keys():
    """Admin API keys page - new layout."""
    return render_template("admin_layout.html", **get_admin_layout_context())


@admin_bp.route("/admin/update-user", methods=["POST"])
@require_page_permission("attendees", "write")
def update_user_route():
    """Update user data - requires attendees write permission."""
    try:
        from models.user import get_user_by_email, update_user

        data = request.get_json()
        email = data.get("email")
        field = data.get("field")
        value = data.get("value")

        if not email:
            return jsonify({"success": False, "error": "Email is required"})

        if not field:
            return jsonify({"success": False, "error": "Field is required"})

        # Get user by email to get the ID
        user = get_user_by_email(email)
        if not user:
            return jsonify({"success": False, "error": "User not found"})

        # Handle events field specially (it's an array)
        if field == "events":
            if not isinstance(value, list):
                return jsonify({"success": False, "error": "Events must be an array"})
            update_value = value
        else:
            # Handle text fields (empty strings should remain as empty strings for Teable)
            update_value = value if value and value.strip() else ""

        # Execute update using model
        update_user(user['id'], **{field: update_value})

        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# Admin API Key Routes
@admin_bp.route("/admin/api_keys", methods=["GET"])
@require_page_permission("keys", "read")
def admin_api_keys():
    """Get all API keys for admin interface."""
    keys_data = get_all_api_keys()

    # Don't include the actual key in the response for security
    for key in keys_data:
        key.pop("key", None)
        key.pop("key_hash", None)

    return jsonify({"success": True, "keys": keys_data})


@admin_bp.route("/admin/api_keys", methods=["POST"])
@require_page_permission("keys", "write")
def create_api_key_route():
    """Create a new API key."""
    try:
        data = request.get_json()
        name = data.get("name")
        permissions = data.get("permissions", [])
        rate_limit_rpm = data.get("rate_limit_rpm", 60)

        if not name:
            return jsonify({"success": False, "error": "Name is required"})

        # Validate rate limit
        if not isinstance(rate_limit_rpm, int) or rate_limit_rpm < 0:
            return jsonify({"success": False, "error": "Invalid rate limit"})

        # Generate new API key
        api_key = create_api_key(
            name,
            session["user_email"],
            permissions,
            metadata=None,
            rate_limit_rpm=rate_limit_rpm,
        )

        return jsonify(
            {
                "success": True,
                "key": api_key,  # Only return the key on creation
                "name": name,
                "permissions": permissions,
                "rate_limit_rpm": rate_limit_rpm,
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/api_keys/<key_id>", methods=["PATCH"])
@require_page_permission("keys", "write")
def update_api_key_route(key_id):
    """Update an API key's name and permissions."""
    try:
        data = request.get_json()
        name = data.get("name")
        permissions = data.get("permissions")
        rate_limit_rpm = data.get("rate_limit_rpm")

        update_data = {}
        if name is not None:
            update_data["name"] = name
        if permissions is not None:
            update_data["permissions"] = permissions
        if rate_limit_rpm is not None:
            if not isinstance(rate_limit_rpm, int) or rate_limit_rpm < 0:
                return jsonify({"success": False, "error": "Invalid rate limit"})
            update_data["rate_limit_rpm"] = rate_limit_rpm

        if not update_data:
            return jsonify({"success": False, "error": "No fields to update"})

        update_api_key(key_id, **update_data)
        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/api_keys/<key_id>", methods=["DELETE"])
@require_page_permission("keys", "write")
def delete_api_key_route(key_id):
    """Delete an API key."""
    try:
        delete_api_key(key_id)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/api_keys/<key_id>/logs", methods=["GET"])
@require_page_permission("keys", "read")
def get_api_key_logs_route(key_id):
    """Get usage logs for an API key."""
    try:
        from models.api_key import get_all_api_keys

        limit = request.args.get("limit", "10")
        limit = int(limit) if limit != "0" else None

        logs_data = get_api_key_logs(key_id, limit)

        # Get key name for display from Teable
        all_keys = get_all_api_keys()
        key_check = next((k for k in all_keys if k['id'] == key_id), None)

        if not key_check:
            return jsonify({"success": False, "error": "API key not found"})

        return jsonify(
            {"success": True, "logs": logs_data, "key_name": key_check["name"]}
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@admin_bp.route("/admin/admins", methods=["GET"])
@require_admin
def admin_admins():
    """Admin admins page - new layout."""
    return render_template("admin_layout.html", **get_admin_layout_context())

@admin_bp.route("/admin/admins/data", methods=["GET"])
@require_page_permission("admins", "read")
def get_admins_route():
    """Get all admin users."""
    try:
        admins = get_all_admins()
        return jsonify({"success": True, "admins": admins})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/admins/data", methods=["POST"])
@require_page_permission("admins", "write")
def add_admin_route():
    """Add a new admin user."""
    try:
        data = request.get_json()
        email = data.get("email")

        if not email:
            return jsonify({"success": False, "error": "Email is required"})

        result = add_admin(email, session["user_email"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/admins/data/<email>", methods=["DELETE"])
@require_page_permission("admins", "write")
def remove_admin_route(email):
    """Remove admin privileges."""
    try:
        # Prevent self-removal: admins cannot remove their own admin privileges
        if session["user_email"] == email:
            return jsonify({
                "success": False,
                "error": "You cannot remove your own admin privileges. Please ask another admin."
            }), 403

        result = remove_admin(email, session["user_email"])
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/admins/<email>/permissions", methods=["GET"])
@require_page_permission("admins", "read")
def get_admin_permissions_route(email):
    """Get permissions for a specific admin."""
    try:
        permissions = get_admin_permissions(email)
        return jsonify({"success": True, "permissions": permissions})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/admins/<email>/permissions", methods=["POST"])
@require_page_permission("admins", "write")
def grant_permission_route(email):
    """Update all permissions for an admin (replaces existing permissions)."""
    try:
        from utils.teable import get_records, delete_record

        # Prevent self-escalation: admins cannot modify their own permissions
        if session["user_email"] == email:
            return jsonify({
                "success": False,
                "error": "You cannot modify your own permissions. Please ask another admin."
            }), 403

        data = request.get_json()
        permissions = data.get("permissions", [])

        # First, remove all existing permissions for this admin
        all_permissions = get_records('admin_permissions', limit=1000)
        for perm in all_permissions:
            if perm['fields'].get('admin_email') == email:
                delete_record('admin_permissions', perm['id'])

        # Then add all the new permissions
        for perm in permissions:
            permission_type = perm.get("permission_type")
            permission_value = perm.get("permission_value")
            access_level = perm.get("access_level", "read")

            if not permission_type or not permission_value:
                continue

            if access_level not in ["read", "write"]:
                continue

            grant_permission(
                email,
                permission_type,
                permission_value,
                access_level,
                session["user_email"]
            )

        return jsonify({"success": True, "message": "Permissions updated successfully"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/admins/<email>/permissions", methods=["DELETE"])
@require_page_permission("admins", "write")
def revoke_permission_route(email):
    """Revoke a permission from an admin."""
    try:
        # Prevent self-escalation: admins cannot modify their own permissions
        if session["user_email"] == email:
            return jsonify({
                "success": False,
                "error": "You cannot modify your own permissions. Please ask another admin."
            }), 403

        data = request.get_json()
        permission_type = data.get("permission_type")
        permission_value = data.get("permission_value")
        access_level = data.get("access_level", "read")

        if not permission_type or not permission_value:
            return jsonify({"success": False, "error": "Missing required fields"})

        result = revoke_permission(email, permission_type, permission_value, access_level)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# Apps Routes
@admin_bp.route("/admin/apps/data", methods=["GET"])
@require_page_permission("apps", "read")
def get_apps_route():
    """Get all apps."""
    try:
        apps = get_all_apps()
        return jsonify({"success": True, "data": apps})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/apps/<app_id>/access", methods=["GET"])
@require_page_permission("apps", "read")
def get_app_access_route(app_id):
    """Get ACL entries for a single app."""
    try:
        app = get_app_by_id(app_id)
        if not app:
            return jsonify({"success": False, "error": "App not found"}), 404

        entries = get_acl_entries_for_admin(app_id)
        return jsonify({"success": True, "entries": entries})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/admin/apps/<app_id>/access", methods=["PUT"])
@require_page_permission("apps", "write")
def put_app_access_route(app_id):
    """Replace ACL entries for a single app."""
    try:
        app = get_app_by_id(app_id)
        if not app:
            return jsonify({"success": False, "error": "App not found"}), 404

        data = request.get_json() or {}
        entries = data.get("entries", [])

        result = replace_app_acl_entries(
            app=app,
            entries=entries,
            actor_email=session["user_email"],
        )
        status = 200 if result.get("success") else 400
        return jsonify(result), status
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@admin_bp.route("/admin/apps")
@require_page_permission_html("apps", "read")
def admin_apps():
    """Admin apps page - new layout."""
    return render_template("admin_layout.html", **get_admin_layout_context())

@admin_bp.route("/admin/apps", methods=["POST"])
@require_page_permission("apps", "write")
def create_app_route():
    """Create a new OAuth 2.0 app."""
    try:
        data = request.get_json()
        name = data.get("name")
        redirect_uris = data.get("redirect_uris", [])
        icon = data.get("icon")
        allowed_scopes = data.get("allowed_scopes", ["profile", "email"])
        allow_anyone = data.get("allow_anyone", False)
        skip_consent_screen = data.get("skip_consent_screen", False)
        app_type = data.get("app_type", "oauth")

        if not name:
            return jsonify({"success": False, "error": "Name is required"})

        if not redirect_uris or len(redirect_uris) == 0:
            return jsonify({"success": False, "error": "At least one redirect URI is required"})

        result = create_app(
            name=name,
            redirect_uris=redirect_uris,
            created_by=session["user_email"],
            icon=icon,
            allowed_scopes=allowed_scopes,
            allow_anyone=allow_anyone,
            skip_consent_screen=skip_consent_screen,
            app_type=app_type,
        )
        if result.get("success"):
            created_app = get_app_by_id(result.get("app_id"))
            if created_app:
                log_if_restricted_app_acl_empty(
                    app=created_app,
                    actor_email=session["user_email"],
                    path=request.path,
                )
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/apps/<app_id>", methods=["PUT"])
@require_page_permission("apps", "write")
def update_app_route(app_id):
    """Update an OAuth 2.0 app."""
    try:
        data = request.get_json()
        result = update_app(
            app_id,
            name=data.get("name"),
            icon=data.get("icon"),
            redirect_uris=data.get("redirect_uris"),
            allowed_scopes=data.get("allowed_scopes"),
            allow_anyone=data.get("allow_anyone"),
            skip_consent_screen=data.get("skip_consent_screen"),
            app_type=data.get("app_type"),
        )
        if result.get("success"):
            updated_app = get_app_by_id(app_id)
            if updated_app:
                log_if_restricted_app_acl_empty(
                    app=updated_app,
                    actor_email=session["user_email"],
                    path=request.path,
                )
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/apps/<app_id>/regenerate-secret", methods=["POST"])
@require_page_permission("apps", "write")
def regenerate_app_secret_route(app_id):
    """Regenerate client_secret for an app."""
    try:
        result = regenerate_client_secret(app_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@admin_bp.route("/admin/apps/<app_id>", methods=["DELETE"])
@require_page_permission("apps", "write")
def delete_app_route(app_id):
    """Delete (deactivate) an app."""
    try:
        result = delete_app(app_id)
        return jsonify(result)
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# Current Event Data Routes
@admin_bp.route("/admin/current-event")
@require_page_permission("events", "read")
def admin_current_event():
    """Current event data page - requires events read permission."""
    current_event = get_current_event()
    if not current_event:
        return (
            render_template("admin/error.html", error="No current event configured"),
            404,
        )

    return render_template("admin/current_event.html", event=current_event)


@admin_bp.route("/admin/current-event/data", methods=["GET"])
@require_page_permission("events", "read")
def get_current_event_data():
    """Get current event attendee data - requires events read permission."""
    try:
        from models.user import get_users_by_event

        current_event = get_current_event()
        if not current_event:
            return jsonify({"success": False, "error": "No current event configured"})

        # Get users registered for current event using model function
        attendees = get_users_by_event(current_event["id"])

        # Format attendee data (remove events field from output)
        attendees_data = []
        for attendee in attendees:
            attendee_dict = {
                "id": attendee["id"],
                "email": attendee["email"],
                "legal_name": attendee.get("legal_name"),
                "preferred_name": attendee.get("preferred_name"),
                "pronouns": attendee.get("pronouns")
            }
            attendees_data.append(attendee_dict)

        return jsonify(
            {
                "success": True,
                "attendees": attendees_data,
                "event": current_event,
                "count": len(attendees_data),
            }
        )

    except Exception as e:
        return jsonify({"success": False, "error": str(e)})
