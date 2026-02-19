"""Dashboard service for user profile and event information."""

import json
import logging
from typing import Dict, List, Any, Optional
from models.app import APP_TYPE_SAML, get_all_apps
from models.user import get_user_by_email
from services.app_access_service import AppAclEvaluationError, evaluate_app_acl_strict
from utils.events import get_all_events, get_current_event
from utils.discord import get_discord_user_info

logger = logging.getLogger(__name__)


def get_user_dashboard_data(user_email: str) -> Dict[str, Any]:
    """
    Get comprehensive dashboard data for a user.

    Returns:
        Dict containing user profile, enrolled events, Discord info, etc.
    """
    dashboard_data = {
        "user": None,
        "enrolled_events": [],
        "saml_apps": [],
        "discord": {
            "linked": False,
            "username": None,
            "discriminator": None,
            "display_name": None,
            "error": None,
        },
        "profile_complete": False,
    }

    # Get user data
    user = get_user_by_email(user_email)
    if not user:
        return dashboard_data

    dashboard_data["user"] = {
        "email": user["email"],
        "legal_name": user.get("legal_name"),
        "preferred_name": user.get("preferred_name"),
        "display_name": user.get("preferred_name") or user.get("legal_name") or "User",
        "pronouns": user.get("pronouns"),
        "dob": user.get("dob"),
        "discord_id": user.get("discord_id"),
    }

    # Check if profile is complete
    dashboard_data["profile_complete"] = bool(
        user.get("legal_name") and user.get("pronouns") and user.get("dob")
    )

    # Get enrolled events
    events_data = get_all_events()
    events_field = user.get("events", "[]")

    # Handle both string and list formats
    if isinstance(events_field, str):
        user_events = json.loads(events_field)
    elif isinstance(events_field, list):
        user_events = events_field
    else:
        user_events = []

    for event_id in user_events:
        if event_id in events_data:
            event_info = events_data[event_id].copy()
            event_info["id"] = event_id
            dashboard_data["enrolled_events"].append(event_info)

    # Get Discord information
    if user.get("discord_id"):
        dashboard_data["discord"]["linked"] = True

        try:
            discord_info = get_discord_user_info(user["discord_id"])
            if discord_info:
                # Discord API returns user info in the 'user' field for guild member info
                discord_user = discord_info.get("user", discord_info)

                dashboard_data["discord"].update(
                    {
                        "username": discord_user.get("username"),
                        "discriminator": discord_user.get("discriminator"),
                        "display_name": discord_info.get("nick")
                        or discord_user.get("global_name")
                        or discord_user.get("username"),
                        "avatar": discord_user.get("avatar"),
                    }
                )
            else:
                dashboard_data["discord"][
                    "error"
                ] = "Could not fetch Discord information"

        except Exception as e:
            dashboard_data["discord"]["error"] = f"Discord API error: {str(e)}"

    # Discover launchable SAML apps using strict ACL reads.
    dashboard_data["saml_apps"] = get_launchable_saml_apps(user["email"])

    return dashboard_data


def get_launchable_saml_apps(user_email: str) -> List[Dict[str, Any]]:
    """Return active SAML apps visible to a user for dashboard launch."""
    apps = get_all_apps()
    launchable: List[Dict[str, Any]] = []
    for app in apps:
        if app.get("app_type") != APP_TYPE_SAML:
            continue
        if not app.get("is_active") or not app.get("saml_enabled"):
            continue

        try:
            acl_result = evaluate_app_acl_strict(
                app=app,
                user_email=user_email,
                path="/dashboard",
            )
        except AppAclEvaluationError as exc:
            logger.warning("SAML launcher ACL strict read failed for app=%s: %s", app.get("id"), exc)
            continue

        if not acl_result.get("allowed"):
            continue

        launchable.append(
            {
                "id": app.get("id"),
                "name": app.get("name"),
                "icon": app.get("icon") or "🔐",
                "saml_entity_id": app.get("saml_entity_id"),
                "relay_state_hint": "",
            }
        )

    launchable.sort(key=lambda item: (item.get("name") or "").lower())
    return launchable


def get_user_pronoun_display(
    user_data: Dict[str, Any], context: str = "subject"
) -> str:
    """
    Get the appropriate pronoun or name to use for a user.

    Args:
        user_data: User data dict with pronouns and preferred_name
        context: "subject" (they/he/she), "object" (them/him/her), "possessive" (their/his/her)

    Returns:
        Appropriate pronoun or preferred name
    """
    pronouns = user_data.get("pronouns", "")
    preferred_name = (
        user_data.get("preferred_name") or user_data.get("legal_name") or "User"
    )

    # If pronouns are "other", always use preferred name
    if pronouns == "other":
        return preferred_name

    # Map pronouns to different contexts
    pronoun_map = {
        "he/him/his": {"subject": "he", "object": "him", "possessive": "his"},
        "she/her/hers": {"subject": "she", "object": "her", "possessive": "her"},
        "they/them/theirs": {
            "subject": "they",
            "object": "them",
            "possessive": "their",
        },
    }

    if pronouns in pronoun_map and context in pronoun_map[pronouns]:
        return pronoun_map[pronouns][context]

    # Fallback to preferred name if pronouns not recognized
    return preferred_name


def format_user_greeting(user_data: Dict[str, Any]) -> str:
    """
    Generate a personalized greeting for the user.

    Args:
        user_data: User data dict

    Returns:
        Formatted greeting string
    """
    display_name = user_data.get("display_name", "User")
    pronouns = user_data.get("pronouns", "")

    if pronouns == "other":
        return f"Welcome back, {display_name}!"
    elif pronouns:
        return f"Welcome back, {display_name}! ({pronouns})"
    else:
        return f"Welcome back, {display_name}!"


def get_event_participation_summary(user_email: str) -> Dict[str, Any]:
    """
    Get a summary of user's event participation.

    Returns:
        Dict with participation statistics
    """
    user = get_user_by_email(user_email)
    if not user:
        return {"total_events": 0, "registered_events": 0, "completed_events": 0}

    events_field = user.get("events", "[]")
    if isinstance(events_field, str):
        user_events = json.loads(events_field)
    elif isinstance(events_field, list):
        user_events = events_field
    else:
        user_events = []

    return {
        "total_events": len(user_events),
        "enrolled_events": len(user_events),
    }
