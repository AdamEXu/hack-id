"""Authentication service with business logic."""

import requests
from urllib.parse import urlencode
from models.auth import (
    generate_verification_code, 
    save_verification_code, 
    verify_code,
    save_verification_token,
    get_verification_token,
    mark_token_used
)
from models.user import get_user_by_email, create_user, update_user, get_user_by_discord_id
from utils.email import send_verification_email
from utils.discord import assign_discord_role
from config import (
    GOOGLE_CLIENT_ID, 
    GOOGLE_CLIENT_SECRET, 
    REDIRECT_URI, 
    DEBUG_MODE
)

def send_email_verification(email):
    """Send email verification code to user."""
    code = generate_verification_code()
    save_verification_code(email, code)
    
    # In debug mode, just print the code
    if DEBUG_MODE:
        print(f"\n==== DEBUG EMAIL ====")
        print(f"To: {email}")
        print(f"Subject: Your Hack ID Verification Code")
        print(f"Verification Code: {code}")
        print(f"This code will expire in 10 minutes.")
        print(f"====================\n")
        return True
    
    return send_verification_email(email, code)

def verify_email_code(email, code):
    """Verify email verification code."""
    return verify_code(email, code)

def handle_google_oauth_callback(auth_code):
    """Handle Google OAuth callback and return user info."""
    try:
        if DEBUG_MODE:
            print(f"DEBUG: Received code: {auth_code[:20]}...")
            print(f"DEBUG: Using CLIENT_ID: {GOOGLE_CLIENT_ID}")
            print(f"DEBUG: Using CLIENT_SECRET: {GOOGLE_CLIENT_SECRET[:10]}...")
            print(f"DEBUG: Using REDIRECT_URI: {REDIRECT_URI}")

        token_data = {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": REDIRECT_URI,
        }

        if DEBUG_MODE:
            print(f"DEBUG: Token request data: {token_data}")

        token_response = requests.post(
            "https://oauth2.googleapis.com/token",
            data=token_data,
        ).json()

        if DEBUG_MODE:
            print(f"DEBUG: Token response: {token_response}")

        if "error" in token_response or "access_token" not in token_response:
            error_msg = f"Failed to authenticate with Google. Error: {token_response.get('error', 'Unknown error')} - {token_response.get('error_description', 'No description')}"
            return {"success": False, "error": error_msg}

        user_response = requests.get(
            "https://www.googleapis.com/oauth2/v2/userinfo",
            headers={"Authorization": f"Bearer {token_response['access_token']}"},
        ).json()

        if "error" in user_response or "email" not in user_response:
            return {
                "success": False,
                "error": "Failed to get user information from Google."
            }

        return {
            "success": True,
            "user": {
                "email": user_response["email"],
                "name": user_response.get("name", "")
            }
        }

    except Exception as e:
        return {"success": False, "error": f"Authentication error: {str(e)}"}

def create_discord_verification_token(discord_id, discord_username, message_id=None):
    """Create Discord verification token."""
    return save_verification_token(discord_id, discord_username, message_id)

def verify_discord_token(token):
    """Verify Discord token and return token info."""
    return get_verification_token(token)

def complete_discord_verification(token, user_email):
    """Complete Discord verification by linking user account."""
    token_info = get_verification_token(token)
    if not token_info:
        return {"success": False, "error": "Invalid or expired token"}
    
    # Get user by email
    user = get_user_by_email(user_email)
    if not user:
        return {"success": False, "error": "User not found"}
    
    # Update user with Discord ID
    update_user(user["id"], discord_id=token_info["discord_id"])
    
    # Mark token as used
    mark_token_used(token)
    
    return {
        "success": True,
        "discord_id": token_info["discord_id"],
        "discord_username": token_info["discord_username"]
    }

def get_google_auth_url():
    """Get Google OAuth authorization URL."""
    return "https://accounts.google.com/o/oauth2/auth?" + urlencode({
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": "email profile",
    })
