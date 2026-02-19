"""Comprehensive user data deletion service for privacy compliance."""

import logging
from typing import Dict, List, Any, Optional
from utils.database import get_db_connection
from models.user import get_user_by_email
from config import DEBUG_MODE
from services.listmonk_service import delete_subscriber_by_email
from services.app_access_service import (
    delete_acl_entries_for_email,
    count_acl_entries_for_email,
)
from services.saml_audit_service import (
    anonymize_saml_audit_email,
    count_saml_artifacts_for_email,
    delete_saml_sp_sessions_for_email,
)
from utils.validation import normalize_email

# Configure logging
logger = logging.getLogger(__name__)


def get_user_data_summary(user_email: str) -> Dict[str, Any]:
    """
    Get a summary of all data associated with a user.
    Used to show users what will be deleted.
    """
    user_email = normalize_email(user_email)
    conn = get_db_connection()

    summary = {
        "user_found": False,
        "tables_with_data": [],
        "discord_linked": False,
        "event_registrations": 0,
        "api_usage_logs": 0,
        "opt_out_tokens": 0,
        "saml_sp_sessions": 0,
        "saml_audit_events": 0,
    }

    # Check if user exists
    user = get_user_by_email(user_email)
    if not user:
        conn.close()
        return summary

    summary["user_found"] = True
    summary["user_id"] = user["id"]
    summary["discord_linked"] = bool(user.get("discord_id"))

    # Check users table
    summary["tables_with_data"].append("users")

    # Skip API key logs for now (no direct user_email field)

    # Check opt-out tokens
    opt_tokens = conn.execute(
        "SELECT COUNT(*) as count FROM opt_out_tokens WHERE user_email = ?",
        (user_email,),
    ).fetchone()
    if opt_tokens and opt_tokens["count"] > 0:
        summary["opt_out_tokens"] = opt_tokens["count"]
        summary["tables_with_data"].append("opt_out_tokens")

    saml_sessions = conn.execute(
        "SELECT COUNT(*) as count FROM saml_sp_sessions WHERE user_email = ?",
        (user_email,),
    ).fetchone()
    if saml_sessions and saml_sessions["count"] > 0:
        summary["saml_sp_sessions"] = saml_sessions["count"]
        summary["tables_with_data"].append("saml_sp_sessions")

    saml_audit = conn.execute(
        "SELECT COUNT(*) as count FROM saml_audit_events WHERE user_email = ?",
        (user_email,),
    ).fetchone()
    if saml_audit and saml_audit["count"] > 0:
        summary["saml_audit_events"] = saml_audit["count"]
        summary["tables_with_data"].append("saml_audit_events")

    conn.close()
    return summary


def remove_discord_roles(user_email: str) -> Dict[str, Any]:
    """
    Remove Discord roles for a user.
    Returns result with success status and details.
    """
    result = {"success": False, "discord_id": None, "roles_removed": [], "error": None}

    try:
        # Get user's Discord ID
        user = get_user_by_email(user_email)
        if not user or not user.get("discord_id"):
            result["error"] = "No Discord account linked"
            return result

        discord_id = user["discord_id"]
        result["discord_id"] = discord_id

        # Use the Discord utilities to remove roles
        try:
            from utils.discord import remove_all_event_roles

            # Remove all event-related roles
            removal_result = remove_all_event_roles(discord_id)

            if removal_result["success"]:
                result["success"] = True
                result["roles_removed"] = removal_result["roles_removed"]
                result["total_removed"] = removal_result["total_removed"]

                if DEBUG_MODE:
                    print(
                        f"Successfully removed {removal_result['total_removed']} Discord roles for {user_email}"
                    )
            else:
                result["error"] = removal_result.get(
                    "error", "Failed to remove Discord roles"
                )
                result["roles_removed"] = removal_result.get("roles_removed", [])
                result["roles_failed"] = removal_result.get("roles_failed", [])

                if DEBUG_MODE:
                    print(
                        f"Partial Discord role removal for {user_email}: {result['error']}"
                    )

        except ImportError:
            result["error"] = "Discord utilities not available"
        except Exception as e:
            result["error"] = f"Discord role removal failed: {str(e)}"
            logger.error(f"Discord role removal error for {user_email}: {e}")

    except Exception as e:
        result["error"] = f"Error accessing user data: {str(e)}"
        logger.error(f"Error in remove_discord_roles for {user_email}: {e}")

    return result


def delete_user_data(user_email: str, include_discord: bool = True, include_listmonk: bool = True) -> Dict[str, Any]:
    """
    Permanently delete all user data from all tables and external services.

    Args:
        user_email: Email of user to delete
        include_discord: Whether to remove Discord roles
        include_listmonk: Whether to delete from Listmonk mailing list

    Returns:
        Dict with deletion results and summary
    """
    normalized_email = normalize_email(user_email)

    result = {
        "success": False,
        "user_email": normalized_email,
        "deleted_from_tables": [],
        "deletion_counts": {},
        "discord_result": None,
        "listmonk_result": None,
        "errors": [],
        "total_records_deleted": 0,
    }

    try:
        # Get user data summary first
        summary = get_user_data_summary(normalized_email)

        if not summary["user_found"]:
            result["errors"].append("User not found")
            return result

        # Remove Discord roles FIRST (before deleting user data from database)
        if include_discord and summary.get("discord_linked"):
            discord_result = remove_discord_roles(normalized_email)
            result["discord_result"] = discord_result

            if (
                not discord_result["success"]
                and discord_result["error"] != "No Discord account linked"
            ):
                result["errors"].append(f"Discord: {discord_result['error']}")

        # Delete from Listmonk mailing list
        if include_listmonk:
            listmonk_result = delete_subscriber_by_email(normalized_email)
            result["listmonk_result"] = listmonk_result

            if not listmonk_result["success"] and not listmonk_result.get("skipped", False):
                result["errors"].append(f"Listmonk: {listmonk_result['error']}")
            elif listmonk_result["success"]:
                logger.info(f"Successfully deleted {user_email} from Listmonk mailing list")

        # Delete from SQLite (ephemeral data only)
        conn = get_db_connection()
        total_deleted = 0

        # Delete from ephemeral tables in SQLite
        ephemeral_tables = [
            ("opt_out_tokens", "user_email", normalized_email),
        ]

        for table_name, column_name, value in ephemeral_tables:
            try:
                cursor = conn.execute(
                    f"DELETE FROM {table_name} WHERE {column_name} = ?", (value,)
                )
                deleted_count = cursor.rowcount

                if deleted_count > 0:
                    result["deleted_from_tables"].append(table_name)
                    result["deletion_counts"][table_name] = deleted_count
                    total_deleted += deleted_count

                    logger.info(
                        f"Deleted {deleted_count} records from {table_name} for {user_email}"
                    )

            except Exception as e:
                error_msg = f"Error deleting from {table_name}: {str(e)}"
                result["errors"].append(error_msg)
                logger.error(
                    f"Data deletion error for {user_email} in {table_name}: {e}"
                )

        conn.commit()
        conn.close()

        # Delete ACL principals tied to this email
        acl_deleted = delete_acl_entries_for_email(normalized_email)
        if acl_deleted > 0:
            result["deleted_from_tables"].append("app_access_entries")
            result["deletion_counts"]["app_access_entries"] = acl_deleted
            total_deleted += acl_deleted
            logger.info(
                f"Deleted {acl_deleted} ACL records from app_access_entries for {normalized_email}"
            )

        # Delete SAML SP sessions and anonymize SAML audit references.
        saml_sessions_deleted = delete_saml_sp_sessions_for_email(normalized_email)
        if saml_sessions_deleted > 0:
            result["deleted_from_tables"].append("saml_sp_sessions")
            result["deletion_counts"]["saml_sp_sessions"] = saml_sessions_deleted
            total_deleted += saml_sessions_deleted

        saml_audit_anonymized = anonymize_saml_audit_email(normalized_email)
        if saml_audit_anonymized > 0:
            result["deleted_from_tables"].append("saml_audit_events")
            result["deletion_counts"]["saml_audit_events"] = saml_audit_anonymized

        # Delete from Teable (persistent data)
        try:
            from models.user import delete_user

            user = get_user_by_email(normalized_email)
            if user:
                delete_user(user['id'])
                result["deleted_from_tables"].append("users")
                result["deletion_counts"]["users"] = 1
                total_deleted += 1
                logger.info(f"Deleted user from Teable for {normalized_email}")
        except Exception as e:
            error_msg = f"Error deleting from Teable users: {str(e)}"
            result["errors"].append(error_msg)
            logger.error(f"Data deletion error for {user_email} in Teable: {e}")

        result["total_records_deleted"] = total_deleted

        # Consider successful if we deleted something or user wasn't found in main table
        result["success"] = total_deleted > 0 or len(result["errors"]) == 0

        if result["success"]:
            logger.info(f"Successfully deleted all data for user {normalized_email}")
        else:
            logger.warning(
                f"Data deletion completed with errors for {normalized_email}: {result['errors']}"
            )

    except Exception as e:
        error_msg = f"Critical error during data deletion: {str(e)}"
        result["errors"].append(error_msg)
        logger.error(f"Critical data deletion error for {normalized_email}: {e}")

    return result


def verify_user_deletion(user_email: str) -> Dict[str, Any]:
    """
    Verify that user data has been completely deleted.
    Returns verification results.
    """
    normalized_email = normalize_email(user_email)

    verification = {
        "completely_deleted": True,
        "remaining_data": {},
        "tables_checked": [],
    }

    # Check SQLite (ephemeral data)
    conn = get_db_connection()

    sqlite_tables = [
        ("opt_out_tokens", "user_email"),
    ]

    for table_name, column_name in sqlite_tables:
        try:
            count = conn.execute(
                f"SELECT COUNT(*) as count FROM {table_name} WHERE {column_name} = ?",
                (normalized_email,),
            ).fetchone()["count"]

            verification["tables_checked"].append(table_name)

            if count > 0:
                verification["completely_deleted"] = False
                verification["remaining_data"][table_name] = count

        except Exception as e:
            logger.error(f"Error checking {table_name} during verification: {e}")

    conn.close()

    # Check Teable (persistent data)
    try:
        user = get_user_by_email(normalized_email)
        verification["tables_checked"].append("users")

        if user:
            verification["completely_deleted"] = False
            verification["remaining_data"]["users"] = 1

    except Exception as e:
        logger.error(f"Error checking Teable users during verification: {e}")

    # Check ACL table (Teable)
    try:
        acl_count = count_acl_entries_for_email(normalized_email)
        verification["tables_checked"].append("app_access_entries")
        if acl_count > 0:
            verification["completely_deleted"] = False
            verification["remaining_data"]["app_access_entries"] = acl_count
    except Exception as e:
        logger.error(f"Error checking app_access_entries during verification: {e}")

    # Check SAML-linked artifacts (SQLite)
    try:
        saml_counts = count_saml_artifacts_for_email(normalized_email)
        verification["tables_checked"].extend(["saml_audit_events", "saml_sp_sessions"])
        for table_name, count in saml_counts.items():
            if count > 0:
                verification["completely_deleted"] = False
                verification["remaining_data"][table_name] = count
    except Exception as e:
        logger.error(f"Error checking SAML artifacts during verification: {e}")

    return verification


def get_deletion_preview(user_email: str) -> Dict[str, Any]:
    """
    Get a preview of what will be deleted for a user.
    Used to show users before they confirm deletion.
    """
    summary = get_user_data_summary(user_email)

    if not summary["user_found"]:
        return {
            "user_found": False,
            "message": "No account found with this email address.",
        }

    preview = {
        "user_found": True,
        "user_email": user_email,
        "items_to_delete": [],
        "discord_warning": summary["discord_linked"],
    }

    # Build list of items that will be deleted
    preview["items_to_delete"].extend(
        [
            "Account information (name, email, date of birth, etc.)",
            "All authentication data",
            "Privacy preferences",
        ]
    )

    if summary["discord_linked"]:
        preview["items_to_delete"].append("Discord verification status and roles")

    return preview
    normalized_email = normalize_email(user_email)
