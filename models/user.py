"""User models and database operations using Teable."""

import json
from typing import Optional, Dict, List, Any
from utils.validation import normalize_email
from utils.teable import (
    create_record,
    get_records,
    update_record,
    delete_record,
    find_record_by_field,
    count_records
)


def create_user(
    email,
    legal_name=None,
    preferred_name=None,
    pronouns=None,
    dob=None,
    discord_id=None,
    events=None,
):
    """Create a new user."""
    email = normalize_email(email)

    # Check if user already exists
    existing = find_record_by_field('users', 'email', email)
    if existing:
        return None

    events_json = json.dumps(events or [])

    record_data = {
        "email": email,
        "legal_name": legal_name or "",
        "preferred_name": preferred_name or "",
        "pronouns": pronouns or "",
        "dob": dob or "",
        "discord_id": discord_id or "",
        "events": events_json,
    }

    result = create_record('users', record_data)
    if result and 'records' in result and len(result['records']) > 0:
        return result['records'][0]['id']
    return None


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Get user by email address."""
    normalized_email = normalize_email(email)
    record = find_record_by_field('users', 'email', normalized_email)

    # Backward-compatible fallback for legacy mixed-case rows.
    if not record:
        all_records = get_records('users', limit=1000)
        for candidate in all_records:
            candidate_email = candidate.get('fields', {}).get('email', '')
            if normalize_email(candidate_email) == normalized_email:
                record = candidate
                break

    if record:
        user_dict = {
            "id": record['id'],
            **record['fields']
        }
        # Parse events JSON
        user_dict["events"] = json.loads(user_dict.get("events", "[]"))
        return user_dict
    return None


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Get user by Teable record ID."""
    # Get all records and filter by ID (Teable doesn't have a get-by-ID endpoint)
    # This is a limitation - we could cache this or implement better lookups
    records = get_records('users', limit=1000)

    for record in records:
        if record['id'] == user_id:
            user_dict = {
                "id": record['id'],
                **record['fields']
            }
            user_dict["events"] = json.loads(user_dict.get("events", "[]"))
            return user_dict
    return None


def get_user_by_discord_id(discord_id: str) -> Optional[Dict[str, Any]]:
    """Get user by Discord ID."""
    record = find_record_by_field('users', 'discord_id', discord_id)

    if record:
        user_dict = {
            "id": record['id'],
            **record['fields']
        }
        user_dict["events"] = json.loads(user_dict.get("events", "[]"))
        return user_dict
    return None


def update_user(user_id: str, **kwargs):
    """Update user with given fields."""
    # Define allowed fields
    allowed_fields = {
        "email",
        "legal_name",
        "preferred_name",
        "pronouns",
        "dob",
        "discord_id",
        "events",
    }

    # Build update data
    update_data = {}
    for field, value in kwargs.items():
        if field not in allowed_fields:
            raise ValueError(f"Invalid field name: {field}")

        if field == "email" and isinstance(value, str):
            value = normalize_email(value)

        if field == "events" and isinstance(value, list):
            value = json.dumps(value)

        update_data[field] = value

    if update_data:
        update_record('users', user_id, update_data)


def delete_user(user_id: str):
    """Delete user by ID."""
    delete_record('users', user_id)


def get_all_users() -> List[Dict[str, Any]]:
    """Get all users from database."""
    records = get_records('users', limit=1000)

    users_data = []
    for record in records:
        user_dict = {
            "id": record['id'],
            **record['fields']
        }
        user_dict["events"] = json.loads(user_dict.get("events", "[]"))
        users_data.append(user_dict)

    return users_data


def get_users_by_event(event_id: str) -> List[Dict[str, Any]]:
    """Get all users registered for a specific event."""
    all_users = get_all_users()

    event_users = []
    for user in all_users:
        if event_id in user.get("events", []):
            event_users.append(user)

    return event_users


def add_user_to_event(user_id: str, event_id: str) -> bool:
    """Add user to an event."""
    user = get_user_by_id(user_id)
    if not user:
        return False

    events = user.get("events", [])
    if event_id not in events:
        events.append(event_id)
        update_user(user_id, events=events)

    return True


def remove_user_from_event(user_id: str, event_id: str) -> bool:
    """Remove user from an event."""
    user = get_user_by_id(user_id)
    if not user:
        return False

    events = user.get("events", [])
    if event_id in events:
        events.remove(event_id)
        update_user(user_id, events=events)

    return True


def get_users_stats() -> Dict[str, Any]:
    """Get user statistics."""
    total_users = count_records('users')

    # Count users by event
    all_users = get_all_users()
    event_counts = {}

    for user in all_users:
        events = user.get("events", [])
        for event in events:
            event_counts[event] = event_counts.get(event, 0) + 1

    return {"total_users": total_users, "event_counts": event_counts}
