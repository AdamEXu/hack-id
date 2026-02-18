"""Admin models and database operations using Teable."""

from typing import Dict, List, Any, Optional
from utils.validation import normalize_email
from utils.teable import (
    create_record,
    get_records,
    update_record,
    delete_record,
    find_record_by_field,
    count_records
)


def is_admin(email: str) -> bool:
    """Check if user is an admin."""
    normalized_email = normalize_email(email)
    record = find_record_by_field('admins', 'email', normalized_email)

    if not record:
        # Backward-compatible fallback for legacy mixed-case rows.
        all_admin_rows = get_records('admins', limit=1000)
        for admin_row in all_admin_rows:
            candidate_email = admin_row.get('fields', {}).get('email', '')
            if normalize_email(candidate_email) == normalized_email:
                record = admin_row
                break

    if record:
        return record['fields'].get('is_active', False)
    return False


def get_all_admins() -> List[Dict[str, Any]]:
    """Get all admin users."""
    records = get_records('admins', limit=1000)

    admins = []
    for record in records:
        admin_dict = {
            "id": record['id'],
            **record['fields']
        }
        admins.append(admin_dict)

    # Sort by most recent first (if added_at exists)
    admins.sort(key=lambda x: x.get('added_at', ''), reverse=True)
    return admins


def add_admin(email: str, added_by: str) -> Dict[str, Any]:
    """Add a new admin user."""
    email = normalize_email(email)
    added_by = normalize_email(added_by)

    # Check if already exists
    existing = find_record_by_field('admins', 'email', email)
    if existing:
        return {"success": False, "error": "User is already an admin"}

    try:
        record_data = {
            "email": email,
            "added_by": added_by,
            "is_active": True
        }

        result = create_record('admins', record_data)
        if result and 'records' in result and len(result['records']) > 0:
            return {"success": True, "admin_id": result['records'][0]['id']}
        return {"success": False, "error": "Failed to create admin record"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def remove_admin(email: str, removed_by: str) -> Dict[str, Any]:
    """Remove admin privileges (deactivate)."""
    email = normalize_email(email)
    removed_by = normalize_email(removed_by)

    # Get all admins sorted by creation (first one is system admin)
    all_admins = get_all_admins()
    if not all_admins:
        return {"success": False, "error": "No admins found"}

    # Sort by ID to find first admin
    all_admins.sort(key=lambda x: x.get('id', ''))
    first_admin = all_admins[0] if all_admins else None

    # Don't allow removing the first admin (system admin)
    if first_admin and email == first_admin.get('email'):
        return {
            "success": False,
            "error": "Cannot remove the first system administrator",
        }

    # Find the admin to deactivate
    admin_record = find_record_by_field('admins', 'email', email)
    if not admin_record or not admin_record['fields'].get('is_active'):
        return {"success": False, "error": "Admin not found or already inactive"}

    try:
        update_record('admins', admin_record['id'], {"is_active": False})
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def reactivate_admin(email: str, reactivated_by: str) -> Dict[str, Any]:
    """Reactivate an admin user."""
    email = normalize_email(email)
    reactivated_by = normalize_email(reactivated_by)

    admin_record = find_record_by_field('admins', 'email', email)
    if not admin_record:
        return {"success": False, "error": "Admin not found"}

    try:
        update_record('admins', admin_record['id'], {"is_active": True})
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def get_admin_stats() -> Dict[str, Any]:
    """Get admin-related statistics."""
    all_admins = get_all_admins()

    total_admins = sum(1 for a in all_admins if a.get('is_active'))
    inactive_admins = sum(1 for a in all_admins if not a.get('is_active'))

    return {"total_admins": total_admins, "inactive_admins": inactive_admins}


def is_system_admin(email: str) -> bool:
    """Check if user is the first system administrator."""
    email = normalize_email(email)
    all_admins = get_all_admins()
    if not all_admins:
        return False

    # Sort by ID to find first admin
    all_admins.sort(key=lambda x: x.get('id', ''))
    first_admin = all_admins[0] if all_admins else None

    return first_admin and email == normalize_email(first_admin.get('email', ''))


def get_admin_permissions(email: str) -> List[Dict[str, Any]]:
    """Get all permissions for an admin."""
    email = normalize_email(email)
    all_permissions = get_records('admin_permissions', limit=1000)

    admin_permissions = []
    for perm in all_permissions:
        if normalize_email(perm['fields'].get('admin_email', '')) == email:
            perm_dict = {
                "id": perm['id'],
                **perm['fields']
            }
            admin_permissions.append(perm_dict)

    # Sort by permission type and value
    admin_permissions.sort(
        key=lambda x: (
            x.get('permission_type', ''),
            x.get('permission_value', ''),
            x.get('access_level', '')
        )
    )

    return admin_permissions


def grant_permission(
    admin_email: str,
    permission_type: str,
    permission_value: str,
    access_level: str,
    granted_by: str
) -> Dict[str, Any]:
    """
    Grant a permission to an admin.
    permission_type: 'event', 'page', 'app', or '*'
    permission_value: event_id, page_name, app_id, or '*'
    access_level: 'read' or 'write'
    """
    # Check if permission already exists
    all_permissions = get_records('admin_permissions', limit=1000)
    for perm in all_permissions:
        fields = perm['fields']
        if (normalize_email(fields.get('admin_email', '')) == admin_email and
            fields.get('permission_type') == permission_type and
            fields.get('permission_value') == permission_value and
            fields.get('access_level') == access_level):
            return {"success": True, "message": "Permission already exists"}

    try:
        record_data = {
            "admin_email": admin_email,
            "permission_type": permission_type,
            "permission_value": permission_value,
            "access_level": access_level,
            "granted_by": granted_by
        }

        create_record('admin_permissions', record_data)
        return {"success": True}
    except Exception as e:
        return {"success": False, "error": str(e)}


def revoke_permission(
    admin_email: str,
    permission_type: str,
    permission_value: str,
    access_level: str
) -> Dict[str, Any]:
    """Revoke a specific permission from an admin."""
    admin_email = normalize_email(admin_email)
    all_permissions = get_records('admin_permissions', limit=1000)

    try:
        for perm in all_permissions:
            fields = perm['fields']
            if (normalize_email(fields.get('admin_email', '')) == admin_email and
                fields.get('permission_type') == permission_type and
                fields.get('permission_value') == permission_value and
                fields.get('access_level') == access_level):
                delete_record('admin_permissions', perm['id'])
                return {"success": True}

        return {"success": False, "error": "Permission not found"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def has_event_permission(admin_email: str, event_id: str, access_level: str = "read") -> bool:
    """
    Check if admin has permission to access an event.
    access_level can be 'read' or 'write'.
    """
    def _level_allows(perm_level: str) -> bool:
        return perm_level == access_level or (perm_level == "write" and access_level == "read")

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

        # Check for wildcard permission (all events)
        if ptype == 'event' and pvalue == '*' and _level_allows(plevel):
            return True

        # Check for specific event permission
        if ptype == 'event' and pvalue == event_id and _level_allows(plevel):
            return True

    return False


def has_page_permission(admin_email: str, page_name: str, access_level: str = "read") -> bool:
    """
    Check if admin has permission to access a page.
    access_level can be 'read' or 'write'.
    """
    def _level_allows(perm_level: str) -> bool:
        return perm_level == access_level or (perm_level == "write" and access_level == "read")

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

        # Check for specific page permission
        if ptype == 'page' and pvalue == page_name and _level_allows(plevel):
            return True

    return False


def has_universal_write_permission(admin_email: str) -> bool:
    """Return True when admin has universal */* write permission."""
    admin_email = normalize_email(admin_email)
    if is_system_admin(admin_email):
        return True

    all_permissions = get_admin_permissions(admin_email)
    for perm in all_permissions:
        if (
            perm.get("permission_type") == "*"
            and perm.get("permission_value") == "*"
            and perm.get("access_level") == "write"
        ):
            return True
    return False
    admin_email = normalize_email(admin_email)
    granted_by = normalize_email(granted_by)

    admin_email = normalize_email(admin_email)
    admin_email = normalize_email(admin_email)
