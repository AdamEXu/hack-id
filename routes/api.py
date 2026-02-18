"""API routes for event registration and temporary info submission."""

from flask import Blueprint, request, jsonify
from services.event_service import (
    register_user_for_event,
    get_user_event_status,
)
from utils.events import get_current_event, get_event_info, get_all_events
from utils.validation import validate_api_request
from utils.error_handling import handle_api_error, handle_validation_error
from utils.rate_limiter import rate_limit_api_key
from models.api_key import get_key_permissions, log_api_key_usage
from models.user import (
    get_user_by_email,
    get_user_by_discord_id,
    update_user,
    get_all_users,
)
from models.auth import save_verification_token, get_verification_token, mark_token_used
from models.admin import is_admin
from config import DEBUG_MODE
import json
from datetime import datetime

api_bp = Blueprint("api", __name__)


def require_api_key(required_permissions=None):
    """Decorator to require API key authentication with specific permissions."""

    def decorator(f):
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return (
                    jsonify({"error": "Missing or invalid Authorization header"}),
                    401,
                )

            api_key = auth_header[7:]  # Remove "Bearer " prefix
            permissions = get_key_permissions(api_key)

            if not permissions:  # Key doesn't exist or has no permissions
                return jsonify({"error": "Invalid API key"}), 403

            # Check required permissions
            if required_permissions is not None:
                required_perms = required_permissions
                if isinstance(required_perms, str):
                    required_perms = [required_perms]

                if not any(perm in permissions for perm in required_perms):
                    return jsonify({"error": "Insufficient permissions"}), 403

            # Log the API usage
            log_api_key_usage(
                api_key,
                f.__name__,
                {
                    "endpoint": request.endpoint,
                    "method": request.method,
                    "ip": request.remote_addr,
                },
            )

            return f(*args, **kwargs)

        wrapper.__name__ = f.__name__
        return wrapper

    return decorator


@api_bp.route("/api/current-event", methods=["GET"])
def api_current_event():
    """Get current event information."""
    try:
        # Get current event data directly
        current_event_data = get_current_event()
        if not current_event_data:
            return (
                jsonify({"success": False, "error": "No current event available"}),
                404,
            )

        return jsonify(
            {
                "success": True,
                "current_event": {
                    "id": current_event_data["id"],
                    "name": current_event_data.get("name", current_event_data["id"]),
                    "description": current_event_data.get("description", ""),
                    "discord_role_id": current_event_data.get("discord-role-id"),
                },
            }
        )

    except Exception as e:
        if DEBUG_MODE:
            print(f"Error in api_current_event: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500


@api_bp.route("/api/events", methods=["GET"])
def api_all_events():
    """Get all available events."""
    try:
        events = get_all_events()
        current_event_data = get_current_event()
        current_event_id = current_event_data["id"] if current_event_data else None

        events_list = []
        for event_id, event_data in events.items():
            events_list.append(
                {
                    "id": event_id,
                    "name": event_data.get("name", event_id),
                    "description": event_data.get("description", ""),
                    "discord_role_id": event_data.get("discord-role-id"),
                    "is_current": event_id == current_event_id,
                }
            )

        return jsonify(
            {
                "success": True,
                "events": events_list,
                "current_event": current_event_data,
            }
        )

    except Exception as e:
        if DEBUG_MODE:
            print(f"Error in api_all_events: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500


@api_bp.route("/api/register-event", methods=["POST"])
@require_api_key(["events.register"])
@rate_limit_api_key
def api_register_event():
    """Register user for an event and optionally submit temporary info."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "JSON data required"}), 400

        # Validate input data - only user_email is required
        validation_result = validate_api_request(data, ["user_email"])
        if not validation_result["valid"]:
            return handle_validation_error(validation_result)

        validated_data = validation_result["data"]
        user_email = validated_data["user_email"]

        # Optional fields
        event_id = validated_data.get("event_id")  # Defaults to current event
        phone_number = validated_data.get("phone_number")
        address = validated_data.get("address")
        emergency_contact_name = validated_data.get("emergency_contact_name")
        emergency_contact_email = validated_data.get("emergency_contact_email")
        emergency_contact_phone = validated_data.get("emergency_contact_phone")
        dietary_restrictions = validated_data.get("dietary_restrictions")
        tshirt_size = validated_data.get("tshirt_size")

        # Register user for event (with optional temporary info)
        result = register_user_for_event(
            user_email=user_email,
            event_id=event_id,
            phone_number=phone_number,
            address=address,
            emergency_contact_name=emergency_contact_name,
            emergency_contact_email=emergency_contact_email,
            emergency_contact_phone=emergency_contact_phone,
            dietary_restrictions=dietary_restrictions,
            tshirt_size=tshirt_size,
        )

        if result["success"]:
            return jsonify(result), 200
        else:
            return jsonify(result), 400

    except Exception as e:
        return handle_api_error(e, "api_register_event")


@api_bp.route("/api/user-status", methods=["GET"])
@require_api_key(["users.read"])
@rate_limit_api_key
def api_user_status():
    """Get user's event registration and temporary info status."""
    try:
        user_email = request.args.get("user_email")
        event_id = request.args.get("event_id")  # Optional

        if not user_email:
            return (
                jsonify(
                    {"success": False, "error": "user_email parameter is required"}
                ),
                400,
            )

        result = get_user_event_status(user_email, event_id)

        if result["success"]:
            return jsonify(result), 200
        else:
            return jsonify(result), 400

    except Exception as e:
        if DEBUG_MODE:
            print(f"Error in api_user_status: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500


# OAuth 2.0 user info endpoint
@api_bp.route("/api/oauth/user-info", methods=["GET"])
def oauth2_user_info():
    """
    OAuth 2.0 user info endpoint.
    Requires Bearer token in Authorization header.
    Returns user data based on granted scopes.
    """
    try:
        # Get Bearer token from Authorization header
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "invalid_request", "error_description": "Missing or invalid Authorization header"}), 401

        token = auth_header[7:]  # Remove "Bearer " prefix

        # Verify access token
        from models.oauth import verify_access_token
        token_data = verify_access_token(token)

        if not token_data:
            return jsonify({"error": "invalid_token", "error_description": "Token is invalid, expired, or revoked"}), 401

        # Get user information
        user = get_user_by_email(token_data["user_email"])
        if not user:
            return jsonify({"error": "not_found", "error_description": "User not found"}), 404

        # Build response based on scopes
        scopes = token_data["scope"]
        user_info = {}

        # profile scope (always included if granted)
        if "profile" in scopes:
            user_info["legal_name"] = user.get("legal_name")
            user_info["preferred_name"] = user.get("preferred_name")
            user_info["pronouns"] = user.get("pronouns")

        # email scope
        if "email" in scopes:
            user_info["email"] = user["email"]

        # dob scope
        if "dob" in scopes:
            user_info["dob"] = user.get("dob")

        # events scope
        if "events" in scopes:
            user_info["events"] = user.get("events", [])

        # discord scope
        if "discord" in scopes:
            user_info["discord_id"] = user.get("discord_id")
            user_info["discord_username"] = user.get("discord_username")

        # Always include is_admin (not sensitive, needed for authorization)
        user_info["is_admin"] = is_admin(user.get("email"))

        return jsonify(user_info), 200

    except Exception as e:
        if DEBUG_MODE:
            print(f"Error in oauth2_user_info: {e}")
        return jsonify({"error": "server_error", "error_description": "Internal server error"}), 500


# Legacy OAuth user info endpoint (for backward compatibility)
@api_bp.route("/api/oauth/user-info", methods=["POST"])
def oauth_user_info_legacy():
    """LEGACY endpoint removed in favor of OAuth 2.0 authorization code flow."""
    return (
        jsonify(
            {
                "success": False,
                "error": "gone",
                "message": "Legacy OAuth token exchange is deprecated. Use /oauth/authorize + /oauth/token + GET /api/oauth/user-info.",
            }
        ),
        410,
    )


# Test endpoint (requires API key)
@api_bp.route("/api/test", methods=["GET"])
@require_api_key(["users.read"])
def api_test():
    """Test endpoint that requires API key with users.read permission."""
    from datetime import datetime

    return jsonify(
        {
            "success": True,
            "message": "API key authentication successful!",
            "timestamp": datetime.now().isoformat(),
        }
    )


# ===== DISCORD API ENDPOINTS =====


@api_bp.route("/api/discord/user/<discord_id>", methods=["GET"])
@require_api_key(["discord.manage"])
@rate_limit_api_key
def api_discord_user(discord_id):
    """Get user data by Discord ID."""
    try:
        user = get_user_by_discord_id(discord_id)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        # Check if user is admin
        from models.admin import is_admin

        user_is_admin = is_admin(user["email"])

        # Return user data with events
        return (
            jsonify(
                {
                    "success": True,
                    "user": {
                        "id": user["id"],
                        "email": user["email"],
                        "legal_name": user["legal_name"],
                        "preferred_name": user["preferred_name"],
                        "pronouns": user["pronouns"],
                        "dob": user.get("dob"),
                        "discord_id": user["discord_id"],
                        "events": user["events"],
                        "verified": True,  # If user exists with discord_id, they're verified
                        "is_admin": user_is_admin,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return handle_api_error(e, "api_discord_user")


@api_bp.route("/api/discord/verification-token", methods=["POST"])
@require_api_key(["discord.manage"])
@rate_limit_api_key
def api_create_verification_token():
    """Create a new Discord verification token."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "JSON data required"}), 400

        # Validate required fields
        required_fields = ["discord_id", "discord_username"]
        for field in required_fields:
            if field not in data:
                return (
                    jsonify({"success": False, "error": f"Missing field: {field}"}),
                    400,
                )

        discord_id = str(data["discord_id"])
        discord_username = data["discord_username"]
        message_id = data.get("message_id")

        # Create verification token
        token = save_verification_token(discord_id, discord_username, message_id)

        return jsonify({"success": True, "token": token, "expires_in_minutes": 10}), 200

    except Exception as e:
        return handle_api_error(e, "api_create_verification_token")


@api_bp.route("/api/discord/verification-token/<token>", methods=["GET"])
@require_api_key(["discord.manage"])
@rate_limit_api_key
def api_get_verification_token(token):
    """Get verification token details."""
    try:
        token_data = get_verification_token(token)
        if not token_data:
            return (
                jsonify({"success": False, "error": "Token not found or expired"}),
                404,
            )

        return (
            jsonify(
                {
                    "success": True,
                    "token_data": {
                        "token": token_data["token"],
                        "discord_id": token_data["discord_id"],
                        "discord_username": token_data["discord_username"],
                        "message_id": token_data["message_id"],
                        "expires_at": token_data["expires_at"],
                        "used": bool(token_data["used"]),
                    },
                }
            ),
            200,
        )

    except Exception as e:
        return handle_api_error(e, "api_get_verification_token")


@api_bp.route("/api/discord/verification-token/<token>", methods=["DELETE"])
@require_api_key(["discord.manage"])
@rate_limit_api_key
def api_mark_token_used(token):
    """Mark verification token as used."""
    try:
        # Check if token exists first
        token_data = get_verification_token(token)
        if not token_data:
            return (
                jsonify({"success": False, "error": "Token not found or expired"}),
                404,
            )

        # Mark as used
        mark_token_used(token)

        return jsonify({"success": True, "message": "Token marked as used"}), 200

    except Exception as e:
        return handle_api_error(e, "api_mark_token_used")


@api_bp.route("/api/discord/role-mappings", methods=["GET"])
@require_api_key(["discord.manage"])
@rate_limit_api_key
def api_discord_role_mappings():
    """Get event to Discord role ID mappings."""
    try:
        events = get_all_events()
        role_mappings = {}

        for event_id, event_data in events.items():
            if "discord-role-id" in event_data:
                role_mappings[event_id] = event_data["discord-role-id"]

        return jsonify({"success": True, "role_mappings": role_mappings}), 200

    except Exception as e:
        return handle_api_error(e, "api_discord_role_mappings")


@api_bp.route("/api/discord/user-roles/<discord_id>", methods=["GET"])
@require_api_key(["discord.manage"])
@rate_limit_api_key
def api_discord_user_roles(discord_id):
    """Get roles a user should have based on their events."""
    try:
        user = get_user_by_discord_id(discord_id)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        events = get_all_events()
        user_events = user["events"]
        roles_to_assign = []

        for event_id in user_events:
            if event_id in events and "discord-role-id" in events[event_id]:
                role_id = events[event_id]["discord-role-id"]
                roles_to_assign.append(
                    {
                        "event_id": event_id,
                        "role_id": role_id,
                        "event_name": events[event_id].get("name", event_id),
                    }
                )

        return (
            jsonify(
                {
                    "success": True,
                    "discord_id": discord_id,
                    "user_events": user_events,
                    "roles_to_assign": roles_to_assign,
                }
            ),
            200,
        )

    except Exception as e:
        return handle_api_error(e, "api_discord_user_roles")


@api_bp.route("/api/discord/verified-users", methods=["GET"])
@require_api_key(["discord.manage"])
@rate_limit_api_key
def api_discord_verified_users():
    """Get all users with Discord IDs for role checking."""
    try:
        all_users = get_all_users()
        verified_users = []

        for user in all_users:
            if user.get("discord_id"):
                verified_users.append(
                    {
                        "id": user["id"],
                        "email": user["email"],
                        "discord_id": user["discord_id"],
                        "events": user["events"],
                        "preferred_name": user.get("preferred_name"),
                        "legal_name": user.get("legal_name"),
                    }
                )

        return (
            jsonify(
                {
                    "success": True,
                    "verified_users": verified_users,
                    "count": len(verified_users),
                }
            ),
            200,
        )

    except Exception as e:
        return handle_api_error(e, "api_discord_verified_users")


@api_bp.route("/api/discord/complete-verification", methods=["POST"])
@require_api_key(["discord.manage"])
@rate_limit_api_key
def api_discord_complete_verification():
    """Complete Discord verification by linking Discord ID to user account."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "JSON data required"}), 400

        # Validate required fields
        required_fields = ["discord_id", "user_email"]
        for field in required_fields:
            if field not in data:
                return (
                    jsonify({"success": False, "error": f"Missing field: {field}"}),
                    400,
                )

        discord_id = str(data["discord_id"])
        user_email = data["user_email"]

        # Get user by email
        user = get_user_by_email(user_email)
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        # Check if Discord ID is already linked to another user
        existing_user = get_user_by_discord_id(discord_id)
        if existing_user and existing_user["email"] != user_email:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Discord ID already linked to another account",
                    }
                ),
                400,
            )

        # Update user with Discord ID
        from models.user import update_user

        try:
            update_user(user["id"], discord_id=discord_id)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        return (
            jsonify(
                {
                    "success": True,
                    "message": "Discord verification completed",
                    "user_email": user_email,
                    "discord_id": discord_id,
                }
            ),
            200,
        )

    except Exception as e:
        return handle_api_error(e, "api_discord_complete_verification")


@api_bp.route("/api/discord/remove-roles", methods=["POST"])
@require_api_key(["discord.manage"])
@rate_limit_api_key
def api_discord_remove_roles():
    """Remove Discord roles from a user."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "JSON data required"}), 400

        # Support both discord_id and user_email
        discord_id = data.get("discord_id")
        user_email = data.get("user_email")

        if not discord_id and not user_email:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Either discord_id or user_email is required",
                    }
                ),
                400,
            )

        # If user_email provided, get discord_id from database
        if user_email and not discord_id:
            user = get_user_by_email(user_email)
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404
            discord_id = user.get("discord_id")
            if not discord_id:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "User has no Discord account linked",
                        }
                    ),
                    404,
                )

        # Remove roles using Discord utilities
        from utils.discord import remove_all_event_roles

        removal_result = remove_all_event_roles(str(discord_id))

        if removal_result["success"]:
            return (
                jsonify(
                    {
                        "success": True,
                        "discord_id": str(discord_id),
                        "roles_removed": removal_result["roles_removed"],
                        "total_removed": removal_result["total_removed"],
                        "message": f"Successfully removed {removal_result['total_removed']} Discord roles",
                    }
                ),
                200,
            )
        else:
            return (
                jsonify(
                    {
                        "success": False,
                        "discord_id": str(discord_id),
                        "error": removal_result.get("error", "Failed to remove roles"),
                        "roles_removed": removal_result.get("roles_removed", []),
                        "roles_failed": removal_result.get("roles_failed", []),
                    }
                ),
                500,
            )

    except Exception as e:
        return handle_api_error(e, "api_discord_remove_roles")


@api_bp.route("/api/discord/unlink", methods=["POST"])
@require_api_key(["discord.manage"])
@rate_limit_api_key
def api_discord_unlink():
    """Unlink Discord account from user."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "JSON data required"}), 400

        # Support both discord_id and user_email
        discord_id = data.get("discord_id")
        user_email = data.get("user_email")

        if not discord_id and not user_email:
            return (
                jsonify(
                    {
                        "success": False,
                        "error": "Either discord_id or user_email is required",
                    }
                ),
                400,
            )

        user = None

        # Get user by discord_id or user_email
        if discord_id:
            user = get_user_by_discord_id(str(discord_id))
            if not user:
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "No user found with that Discord ID",
                        }
                    ),
                    404,
                )
        elif user_email:
            user = get_user_by_email(user_email)
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404

            if not user.get("discord_id"):
                return (
                    jsonify(
                        {
                            "success": False,
                            "error": "User has no Discord account linked",
                        }
                    ),
                    400,
                )

        # Use the service function that handles role removal
        from services.auth_service import unlink_discord_account

        result = unlink_discord_account(user["email"])

        if result["success"]:
            return (
                jsonify(
                    {
                        "success": True,
                        "message": "Discord account successfully unlinked",
                        "user_email": result["user_email"],
                        "previous_discord_id": result["previous_discord_id"],
                        "roles_removed": result.get("roles_removed", []),
                        "roles_failed": result.get("roles_failed", []),
                        "total_roles_removed": result.get("total_roles_removed", 0),
                        "total_roles_failed": result.get("total_roles_failed", 0),
                        "role_removal_success": result.get(
                            "role_removal_success", False
                        ),
                    }
                ),
                200,
            )
        else:
            return jsonify({"success": False, "error": result["error"]}), 400

    except Exception as e:
        return handle_api_error(e, "api_discord_unlink")
