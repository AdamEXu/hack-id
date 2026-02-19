"""Input validation and sanitization utilities."""

import re
import html
from typing import Any, Dict, List, Optional, Union


def normalize_email(email: str) -> str:
    """Normalize email with lowercase + trim only."""
    if not isinstance(email, str):
        return ""
    return email.strip().lower()


def sanitize_string(value: str, max_length: int = 255) -> str:
    """Sanitize string input by escaping HTML and limiting length."""
    if not isinstance(value, str):
        return ""
    
    # Strip whitespace and escape HTML
    sanitized = html.escape(value.strip())
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized


def validate_email(email: str) -> bool:
    """Validate email format."""
    if not isinstance(email, str):
        return False
    
    # Basic email regex pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, normalize_email(email)))


def validate_discord_id(discord_id: str) -> bool:
    """Validate Discord ID format (18-19 digit number)."""
    if not isinstance(discord_id, str):
        return False
    
    # Discord IDs are 18-19 digit numbers
    pattern = r'^\d{18,19}$'
    return bool(re.match(pattern, discord_id.strip()))


def validate_phone_number(phone: str) -> bool:
    """Validate phone number format."""
    if not isinstance(phone, str):
        return False
    
    # Remove all non-digit characters
    digits_only = re.sub(r'\D', '', phone)
    
    # Check if it's a valid length (10-15 digits)
    return 10 <= len(digits_only) <= 15


def validate_tshirt_size(size: str) -> bool:
    """Validate t-shirt size."""
    if not isinstance(size, str):
        return False
    
    valid_sizes = {'XS', 'S', 'M', 'L', 'XL', 'XXL', 'XXXL'}
    return size.upper().strip() in valid_sizes


def validate_pronouns(pronouns: str) -> bool:
    """Validate pronouns format."""
    if not isinstance(pronouns, str):
        return False
    
    # Allow common pronoun formats
    pattern = r'^[a-zA-Z/\s]{1,50}$'
    return bool(re.match(pattern, pronouns.strip()))


def validate_dob(dob: str) -> bool:
    """Validate date of birth format (MM/DD/YYYY)."""
    if not isinstance(dob, str):
        return False

    # Basic date format validation for MM/DD/YYYY
    pattern = r'^\d{2}/\d{2}/\d{4}$'
    if not re.match(pattern, dob.strip()):
        return False

    # Additional validation - check if it's a valid date
    try:
        from datetime import datetime
        datetime.strptime(dob.strip(), "%m/%d/%Y")
        return True
    except ValueError:
        return False


def validate_event_id(event_id: str) -> bool:
    """Validate event ID format."""
    if not isinstance(event_id, str):
        return False
    
    # Event IDs should be alphanumeric with underscores
    pattern = r'^[a-zA-Z0-9_]{1,50}$'
    return bool(re.match(pattern, event_id.strip()))


def validate_api_key_name(name: str) -> bool:
    """Validate API key name."""
    if not isinstance(name, str):
        return False
    
    # API key names should be reasonable length and safe characters
    pattern = r'^[a-zA-Z0-9\s\-_.]{1,100}$'
    return bool(re.match(pattern, name.strip()))


def validate_user_input(data: Dict[str, Any]) -> Dict[str, Union[str, List[str]]]:
    """
    Validate and sanitize user input data.
    Returns a dict with 'valid' boolean and 'errors' list.
    """
    errors = []
    sanitized_data = {}
    
    # Email validation
    if 'email' in data:
        email = data['email']
        if not validate_email(email):
            errors.append("Invalid email format")
        else:
            sanitized_data['email'] = email.strip().lower()
    
    # Name validations
    for field in ['legal_name', 'preferred_name']:
        if field in data:
            value = sanitize_string(data[field], max_length=100)
            if len(value) < 1:
                errors.append(f"{field.replace('_', ' ').title()} is required")
            else:
                sanitized_data[field] = value
    
    # Pronouns validation
    if 'pronouns' in data:
        pronouns = data['pronouns']
        if pronouns and not validate_pronouns(pronouns):
            errors.append("Invalid pronouns format")
        else:
            sanitized_data['pronouns'] = sanitize_string(pronouns, max_length=50)
    
    # Date of birth validation
    if 'dob' in data:
        dob = data['dob']
        if dob and not validate_dob(dob):
            errors.append("Invalid date of birth format (use YYYY-MM-DD)")
        else:
            sanitized_data['dob'] = dob.strip() if dob else None
    
    # Discord ID validation
    if 'discord_id' in data:
        discord_id = data['discord_id']
        if discord_id and not validate_discord_id(discord_id):
            errors.append("Invalid Discord ID format")
        else:
            sanitized_data['discord_id'] = discord_id.strip() if discord_id else None
    
    # Phone number validation
    if 'phone_number' in data:
        phone = data['phone_number']
        if phone and not validate_phone_number(phone):
            errors.append("Invalid phone number format")
        else:
            sanitized_data['phone_number'] = sanitize_string(phone, max_length=20)
    
    # T-shirt size validation
    if 'tshirt_size' in data:
        size = data['tshirt_size']
        if size and not validate_tshirt_size(size):
            errors.append("Invalid t-shirt size")
        else:
            sanitized_data['tshirt_size'] = size.upper().strip() if size else None
    
    # Address validation (basic)
    if 'address' in data:
        address = sanitize_string(data['address'], max_length=500)
        sanitized_data['address'] = address
    
    # Emergency contact validations
    for field in ['emergency_contact_name', 'emergency_contact_email', 'emergency_contact_phone']:
        if field in data:
            value = data[field]
            if field.endswith('_email') and value:
                if not validate_email(value):
                    errors.append(f"Invalid {field.replace('_', ' ')}")
                else:
                    sanitized_data[field] = value.strip().lower()
            elif field.endswith('_phone') and value:
                if not validate_phone_number(value):
                    errors.append(f"Invalid {field.replace('_', ' ')}")
                else:
                    sanitized_data[field] = sanitize_string(value, max_length=20)
            else:
                sanitized_data[field] = sanitize_string(value, max_length=100)
    
    # Event ID validation
    if 'event_id' in data:
        event_id = data['event_id']
        if event_id and not validate_event_id(event_id):
            errors.append("Invalid event ID")
        else:
            sanitized_data['event_id'] = event_id.strip() if event_id else None
    
    return {
        'valid': len(errors) == 0,
        'errors': errors,
        'data': sanitized_data
    }


def validate_api_request(data: Dict[str, Any], required_fields: List[str]) -> Dict[str, Union[str, List[str]]]:
    """Validate API request data with required fields."""
    validation_result = validate_user_input(data)
    
    # Check required fields
    missing_fields = []
    for field in required_fields:
        if field not in validation_result['data'] or not validation_result['data'][field]:
            missing_fields.append(field)
    
    if missing_fields:
        validation_result['errors'].extend([f"Missing required field: {field}" for field in missing_fields])
        validation_result['valid'] = False
    
    return validation_result
