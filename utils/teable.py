"""Teable database integration utilities."""

import os
import requests
from typing import Dict, List, Any, Optional, Set
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Teable configuration
TEABLE_API_URL = os.getenv('TEABLE_API_URL', 'https://app.teable.ai/api')
TEABLE_ACCESS_TOKEN = os.getenv('TEABLE_ACCESS_TOKEN')
TEABLE_BASE_ID = os.getenv('TEABLE_BASE_ID')

# Table IDs from environment
TEABLE_TABLE_IDS = {
    'users': os.getenv('TEABLE_TABLE_USERS'),
    'admins': os.getenv('TEABLE_TABLE_ADMINS'),
    'admin_permissions': os.getenv('TEABLE_TABLE_ADMIN_PERMISSIONS'),
    'api_keys': os.getenv('TEABLE_TABLE_API_KEYS'),
    'apps': os.getenv('TEABLE_TABLE_APPS'),
    'app_access_entries': os.getenv('TEABLE_TABLE_APP_ACCESS_ENTRIES'),
    'app_access_audit': os.getenv('TEABLE_TABLE_APP_ACCESS_AUDIT'),
}


def get_headers():
    """Get API headers for Teable requests."""
    return {
        'Authorization': f'Bearer {TEABLE_ACCESS_TOKEN}',
        'Content-Type': 'application/json'
    }


def check_teable_config() -> Dict[str, Any]:
    """
    Check if Teable is properly configured.
    Returns dict with 'configured' boolean and list of missing items.
    """
    missing = []

    if not TEABLE_ACCESS_TOKEN:
        missing.append('TEABLE_ACCESS_TOKEN')
    if not TEABLE_BASE_ID:
        missing.append('TEABLE_BASE_ID')

    for table_name, table_id in TEABLE_TABLE_IDS.items():
        if not table_id:
            missing.append(f'TEABLE_TABLE_{table_name.upper()}')

    return {
        'configured': len(missing) == 0,
        'missing': missing
    }


def create_record(table_name: str, record: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Create a single record in a Teable table.

    Args:
        table_name: Name of the table (e.g., 'users', 'admins')
        record: Dictionary with field names and values

    Returns:
        Created record data or None if failed
    """
    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    url = f"{TEABLE_API_URL}/table/{table_id}/record"

    payload = {
        "records": [{"fields": record}]
    }

    response = requests.post(url, headers=get_headers(), json=payload)

    if response.status_code in [200, 201]:
        return response.json()
    else:
        print(f"❌ Failed to create record in {table_name}")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        return None


def create_records_batch(table_name: str, records: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Create multiple records in a Teable table in a single request.

    Args:
        table_name: Name of the table (e.g., 'users', 'admins')
        records: List of dictionaries with field names and values

    Returns:
        Response data or None if failed
    """
    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    url = f"{TEABLE_API_URL}/table/{table_id}/record"

    # Format records for Teable API
    formatted_records = [{"fields": record} for record in records]

    payload = {
        "records": formatted_records
    }

    response = requests.post(url, headers=get_headers(), json=payload)

    if response.status_code in [200, 201]:
        return response.json()
    else:
        print(f"❌ Failed to create records in {table_name}")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        return None


def get_records(table_name: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """
    Get records from a Teable table.

    Args:
        table_name: Name of the table
        limit: Maximum number of records to retrieve
        offset: Number of records to skip

    Returns:
        List of records
    """
    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    url = f"{TEABLE_API_URL}/table/{table_id}/record"
    params = {
        'take': limit,
        'skip': offset
    }

    response = requests.get(url, headers=get_headers(), params=params)

    if response.status_code == 200:
        data = response.json()
        return data.get('records', [])
    else:
        print(f"❌ Failed to get records from {table_name}")
        print(f"   Status: {response.status_code}")
        try:
            print(f"   Response: {response.text}")
        except:
            pass
        return []


def get_records_strict(table_name: str, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
    """
    Get records from a Teable table and raise on failure.

    This is intended for security-sensitive read paths that must distinguish
    empty result sets from transport/API failures.
    """
    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    url = f"{TEABLE_API_URL}/table/{table_id}/record"
    params = {
        'take': limit,
        'skip': offset
    }

    try:
        response = requests.get(url, headers=get_headers(), params=params, timeout=10)
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to get records from {table_name}: {exc}") from exc

    if response.status_code != 200:
        raise RuntimeError(
            f"Failed to get records from {table_name}: status={response.status_code} body={response.text}"
        )

    return response.json().get('records', [])


def count_records(table_name: str) -> int:
    """
    Count total number of records in a Teable table.

    Args:
        table_name: Name of the table

    Returns:
        Number of records or 0 if failed
    """
    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    # Get first page to get total count from response
    url = f"{TEABLE_API_URL}/table/{table_id}/record"
    params = {'take': 1}

    response = requests.get(url, headers=get_headers(), params=params)

    if response.status_code == 200:
        data = response.json()
        # Teable API should return 'total' but some versions don't
        # Fall back to getting all records and counting them
        if 'total' in data:
            return data['total']
        else:
            # Get all records to count (inefficient but works)
            all_records_response = requests.get(
                f"{TEABLE_API_URL}/table/{table_id}/record",
                headers=get_headers(),
                params={'take': 10000}  # Max records
            )
            if all_records_response.status_code == 200:
                all_data = all_records_response.json()
                return len(all_data.get('records', []))
            return 0
    else:
        return 0


def update_record(table_name: str, record_id: str, fields: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Update a record in a Teable table.

    Args:
        table_name: Name of the table
        record_id: ID of the record to update
        fields: Dictionary with field names and new values

    Returns:
        Updated record data or None if failed
    """
    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    url = f"{TEABLE_API_URL}/table/{table_id}/record"

    payload = {
        "records": [{
            "id": record_id,
            "fields": fields
        }]
    }

    response = requests.patch(url, headers=get_headers(), json=payload)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ Failed to update record in {table_name}")
        print(f"   Status: {response.status_code}")
        return None


def update_records_batch(table_name: str, updates: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Update multiple records in a Teable table in a single request.

    Args:
        table_name: Name of the table
        updates: List of dicts with 'id' and 'fields' keys

    Returns:
        Response data or None if failed
    """
    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    url = f"{TEABLE_API_URL}/table/{table_id}/record"

    payload = {
        "records": updates
    }

    response = requests.patch(url, headers=get_headers(), json=payload)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"❌ Failed to update records in {table_name}")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        return None


def delete_record(table_name: str, record_id: str) -> bool:
    """
    Delete a record from a Teable table.

    Args:
        table_name: Name of the table
        record_id: ID of the record to delete

    Returns:
        True if successful, False otherwise
    """
    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    headers = get_headers()
    delete_by_id_url = f"{TEABLE_API_URL}/table/{table_id}/record/{record_id}"

    # Preferred single-record endpoint.
    try:
        response = requests.delete(delete_by_id_url, headers=headers, timeout=10)
        if response.status_code in (200, 204):
            return True
        # Deleting an already-missing record is idempotent success.
        if response.status_code == 404:
            return True
    except requests.RequestException:
        pass

    # Backward-compatible fallback to query-array style.
    url = f"{TEABLE_API_URL}/table/{table_id}/record"
    try:
        response = requests.delete(
            url,
            headers=headers,
            params=[("recordIds[]", record_id)],
            timeout=10,
        )
        if response.status_code in (200, 204, 404):
            return True
    except requests.RequestException:
        pass

    return False


def delete_records_batch(table_name: str, record_ids: List[str]) -> bool:
    """Delete multiple records in one call, with compatibility fallbacks."""
    normalized_ids = [str(record_id).strip() for record_id in record_ids if str(record_id).strip()]
    # Preserve order but remove duplicates.
    normalized_ids = list(dict.fromkeys(normalized_ids))

    if not normalized_ids:
        return True

    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    url = f"{TEABLE_API_URL}/table/{table_id}/record"
    headers = get_headers()

    # Strategy 1: query-array style (documented).
    try:
        array_params = [("recordIds[]", record_id) for record_id in normalized_ids]
        response = requests.delete(
            url,
            headers=headers,
            params=array_params,
            timeout=10,
        )
        if response.status_code in (200, 204):
            return True
        # Teable can return 404 when some IDs are already deleted.
        if response.status_code == 404:
            return True
    except requests.RequestException:
        pass

    # Strategy 2: comma-separated query param.
    try:
        response = requests.delete(
            url,
            headers=headers,
            params={"recordIds": ",".join(normalized_ids)},
            timeout=10,
        )
        if response.status_code in (200, 204):
            return True
        if response.status_code == 404:
            return True
    except requests.RequestException:
        pass

    # Strategy 3: repeated query params.
    try:
        repeated_params = [("recordIds", record_id) for record_id in normalized_ids]
        response = requests.delete(
            url,
            headers=headers,
            params=repeated_params,
            timeout=10,
        )
        if response.status_code in (200, 204):
            return True
        if response.status_code == 404:
            return True
    except requests.RequestException:
        pass

    # Strategy 4: JSON body with recordIds array.
    try:
        response = requests.delete(
            url,
            headers=headers,
            json={"recordIds": normalized_ids},
            timeout=10,
        )
        if response.status_code in (200, 204):
            return True
        if response.status_code == 404:
            return True
    except requests.RequestException:
        pass

    # Strategy 5: per-record fallback to maximize successful cleanup.
    all_deleted = True
    for record_id in normalized_ids:
        if not delete_record(table_name, record_id):
            all_deleted = False

    if not all_deleted:
        print(f"❌ Failed to delete one or more records in {table_name}")
        print(f"   Record IDs: {normalized_ids}")

    return all_deleted


def find_record_by_field(table_name: str, field_name: str, value: Any) -> Optional[Dict[str, Any]]:
    """
    Find a record by a specific field value.

    Args:
        table_name: Name of the table
        field_name: Name of the field to search
        value: Value to search for

    Returns:
        First matching record or None
    """
    # Get all records and filter (Teable may have better filtering in the future)
    records = get_records(table_name, limit=1000)

    for record in records:
        if record.get('fields', {}).get(field_name) == value:
            return record

    return None


def get_table_fields(table_name: str) -> List[Dict[str, Any]]:
    """Get field definitions for a Teable table."""
    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    url = f"{TEABLE_API_URL}/table/{table_id}/field"
    response = requests.get(url, headers=get_headers(), timeout=10)
    if response.status_code != 200:
        print(f"❌ Failed to get fields from {table_name}")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        return []

    data = response.json()
    if isinstance(data, list):
        return data
    return data.get("fields", [])


def get_table_field_names(table_name: str) -> Set[str]:
    """Get existing field names for a Teable table."""
    fields = get_table_fields(table_name)
    return {
        field.get("name")
        for field in fields
        if isinstance(field, dict) and field.get("name")
    }


def create_table_field(table_name: str, field_config: Dict[str, Any]) -> bool:
    """Create a field in a Teable table (idempotent-friendly)."""
    table_id = TEABLE_TABLE_IDS.get(table_name)
    if not table_id:
        raise ValueError(f"Unknown table: {table_name}")

    url = f"{TEABLE_API_URL}/table/{table_id}/field"
    response = requests.post(url, headers=get_headers(), json=field_config, timeout=10)
    if response.status_code in [200, 201]:
        return True

    # Existing field responses vary by Teable version; treat common duplicates as success.
    if response.status_code in [400, 409]:
        body = (response.text or "").lower()
        if "exist" in body or "duplicate" in body or "already" in body:
            return True

    print(f"❌ Failed to create field in {table_name}")
    print(f"   Status: {response.status_code}")
    print(f"   Response: {response.text}")
    return False
