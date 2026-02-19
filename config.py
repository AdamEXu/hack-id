"""Configuration module for the Flask application."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Try to load .env file explicitly
if os.path.exists(".env"):
    print("DEBUG: .env file found")
    load_dotenv(".env")
    print("DEBUG: Explicitly loaded .env file")
else:
    print("DEBUG: .env file NOT found")
    load_dotenv()  # Try default loading

# Environment configuration
PROD = os.getenv("PROD", "").upper() == "TRUE"
DEBUG_MODE = not PROD

# Base URL configuration
_DEFAULT_BASE_URL = "https://id.hack.sv" if PROD else "http://127.0.0.1:3000"
BASE_URL = (os.getenv("BASE_URL", _DEFAULT_BASE_URL) or _DEFAULT_BASE_URL).strip().rstrip("/")

# Flask configuration
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    print("CRITICAL ERROR: SECRET_KEY environment variable is not set!")
    print("Please set a strong, random SECRET_KEY in your .env file.")
    print(
        "You can generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
    )
    exit(1)

# WorkOS Configuration
WORKOS_API_KEY = os.getenv("WORKOS_API_KEY")
WORKOS_CLIENT_ID = os.getenv("WORKOS_CLIENT_ID")

# OAuth Redirect URIs
GOOGLE_REDIRECT_URI = f"{BASE_URL}/auth/google/callback"
EMAIL_REDIRECT_URI = f"{BASE_URL}/auth/email/callback"

# AWS SES SMTP configuration
MAIL_HOST = os.getenv("MAIL_HOST", "email-smtp.us-west-1.amazonaws.com")
MAIL_PORT = int(os.getenv("MAIL_PORT", "587"))
MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
EMAIL_SENDER = os.getenv("EMAIL_SENDER", "adam@hack.sv")
EMAIL_SENDER_NAME = os.getenv("EMAIL_SENDER_NAME", "Adam Xu")

# Discord configuration
DISCORD_BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN")
DISCORD_GUILD_ID = int(os.getenv("DISCORD_GUILD_ID", "0"))

# PostHog Configuration
POSTHOG_API_KEY = os.getenv("POSTHOG_API_KEY")
POSTHOG_HOST = os.getenv("POSTHOG_HOST", "https://us.i.posthog.com")
POSTHOG_ENABLED = os.getenv("POSTHOG_ENABLED", "true").lower() == "true"

# Listmonk Configuration
LISTMONK_URL = os.getenv("LISTMONK_URL", "https://mail.hack.sv")
LISTMONK_API_KEY = os.getenv("LISTMONK_API_KEY")
LISTMONK_ENABLED = os.getenv("LISTMONK_ENABLED", "true").lower() == "true" and LISTMONK_API_KEY is not None

# Database configuration
DATABASE = "users.db"

# Server-side session storage (SQLite via Flask-Session + SQLAlchemy)
SESSION_SQLALCHEMY_URI = f"sqlite:///{DATABASE}"

# Teable configuration
TEABLE_API_URL = os.getenv('TEABLE_API_URL', 'https://app.teable.ai/api')
TEABLE_ACCESS_TOKEN = os.getenv('TEABLE_ACCESS_TOKEN')
TEABLE_BASE_ID = os.getenv('TEABLE_BASE_ID')
TEABLE_TABLE_USERS = os.getenv('TEABLE_TABLE_USERS')
TEABLE_TABLE_ADMINS = os.getenv('TEABLE_TABLE_ADMINS')
TEABLE_TABLE_ADMIN_PERMISSIONS = os.getenv('TEABLE_TABLE_ADMIN_PERMISSIONS')
TEABLE_TABLE_API_KEYS = os.getenv('TEABLE_TABLE_API_KEYS')
TEABLE_TABLE_APPS = os.getenv('TEABLE_TABLE_APPS')
TEABLE_TABLE_APP_ACCESS_ENTRIES = os.getenv('TEABLE_TABLE_APP_ACCESS_ENTRIES')
TEABLE_TABLE_APP_ACCESS_AUDIT = os.getenv('TEABLE_TABLE_APP_ACCESS_AUDIT')
APP_ACL_MAX_ENTRIES = int(os.getenv("APP_ACL_MAX_ENTRIES", "500"))

# SAML IdP configuration
SAML_ENABLED = os.getenv("SAML_ENABLED", "false").lower() == "true"
SAML_IDP_ENTITY_ID = os.getenv("SAML_IDP_ENTITY_ID", f"{BASE_URL}/saml/metadata")
SAML_IDP_KEY_ACTIVE_PATH = os.getenv("SAML_IDP_KEY_ACTIVE_PATH", "")
SAML_IDP_CERT_ACTIVE_PATH = os.getenv("SAML_IDP_CERT_ACTIVE_PATH", "")
SAML_IDP_KEY_NEXT_PATH = os.getenv("SAML_IDP_KEY_NEXT_PATH", "")
SAML_IDP_CERT_NEXT_PATH = os.getenv("SAML_IDP_CERT_NEXT_PATH", "")
SAML_XMLSEC_BINARY = os.getenv("SAML_XMLSEC_BINARY", "/usr/bin/xmlsec1")
SAML_METADATA_SYNC_ENABLED = os.getenv("SAML_METADATA_SYNC_ENABLED", "true").lower() == "true"
SAML_METADATA_SYNC_TIMEOUT_SEC = int(os.getenv("SAML_METADATA_SYNC_TIMEOUT_SEC", "10"))
SAML_METADATA_SYNC_MAX_BYTES = int(os.getenv("SAML_METADATA_SYNC_MAX_BYTES", "262144"))
SAML_METADATA_SYNC_USER_AGENT = os.getenv("SAML_METADATA_SYNC_USER_AGENT", "hack-id-saml-sync/1.0")


def print_debug_info():
    """Print debug information about environment variables."""
    if DEBUG_MODE:
        print("=== ENVIRONMENT VARIABLES DEBUG ===")
        print(f"PROD: {PROD}")
        print(f"DEBUG_MODE: {DEBUG_MODE}")
        print(f"BASE_URL: {BASE_URL}")
        print(f"WORKOS_API_KEY: {'[SET]' if WORKOS_API_KEY else '[NOT SET]'}")
        print(f"WORKOS_CLIENT_ID: {'[SET]' if WORKOS_CLIENT_ID else '[NOT SET]'}")
        print(f"SECRET_KEY: {'[SET]' if SECRET_KEY else '[NOT SET]'}")
        print(f"MAIL_HOST: {MAIL_HOST}")
        print(f"MAIL_PORT: {MAIL_PORT}")
        print(f"MAIL_USERNAME: {'[SET]' if MAIL_USERNAME else '[NOT SET]'}")
        print(f"MAIL_PASSWORD: {'[SET]' if MAIL_PASSWORD else '[NOT SET]'}")
        print(f"DISCORD_BOT_TOKEN: {'[SET]' if DISCORD_BOT_TOKEN else '[NOT SET]'}")
        print(f"GOOGLE_REDIRECT_URI: {GOOGLE_REDIRECT_URI}")
        print(f"EMAIL_REDIRECT_URI: {EMAIL_REDIRECT_URI}")
        print(f"TEABLE_ACCESS_TOKEN: {'[SET]' if TEABLE_ACCESS_TOKEN else '[NOT SET]'}")
        print(f"TEABLE_BASE_ID: {'[SET]' if TEABLE_BASE_ID else '[NOT SET]'}")
        print(f"TEABLE_TABLE_USERS: {'[SET]' if TEABLE_TABLE_USERS else '[NOT SET]'}")
        print(f"TEABLE_TABLE_ADMINS: {'[SET]' if TEABLE_TABLE_ADMINS else '[NOT SET]'}")
        print(f"TEABLE_TABLE_ADMIN_PERMISSIONS: {'[SET]' if TEABLE_TABLE_ADMIN_PERMISSIONS else '[NOT SET]'}")
        print(f"TEABLE_TABLE_API_KEYS: {'[SET]' if TEABLE_TABLE_API_KEYS else '[NOT SET]'}")
        print(f"TEABLE_TABLE_APPS: {'[SET]' if TEABLE_TABLE_APPS else '[NOT SET]'}")
        print(f"TEABLE_TABLE_APP_ACCESS_ENTRIES: {'[SET]' if TEABLE_TABLE_APP_ACCESS_ENTRIES else '[NOT SET]'}")
        print(f"TEABLE_TABLE_APP_ACCESS_AUDIT: {'[SET]' if TEABLE_TABLE_APP_ACCESS_AUDIT else '[NOT SET]'}")
        print(f"APP_ACL_MAX_ENTRIES: {APP_ACL_MAX_ENTRIES}")
        print(f"SAML_ENABLED: {SAML_ENABLED}")
        print(f"SAML_IDP_ENTITY_ID: {SAML_IDP_ENTITY_ID}")
        print(f"SAML_IDP_KEY_ACTIVE_PATH: {'[SET]' if SAML_IDP_KEY_ACTIVE_PATH else '[NOT SET]'}")
        print(f"SAML_IDP_CERT_ACTIVE_PATH: {'[SET]' if SAML_IDP_CERT_ACTIVE_PATH else '[NOT SET]'}")
        print(f"SAML_IDP_KEY_NEXT_PATH: {'[SET]' if SAML_IDP_KEY_NEXT_PATH else '[NOT SET]'}")
        print(f"SAML_IDP_CERT_NEXT_PATH: {'[SET]' if SAML_IDP_CERT_NEXT_PATH else '[NOT SET]'}")
        print(f"SAML_XMLSEC_BINARY: {SAML_XMLSEC_BINARY}")
        print(f"SAML_METADATA_SYNC_ENABLED: {SAML_METADATA_SYNC_ENABLED}")
        print(f"SAML_METADATA_SYNC_TIMEOUT_SEC: {SAML_METADATA_SYNC_TIMEOUT_SEC}")
        print(f"SAML_METADATA_SYNC_MAX_BYTES: {SAML_METADATA_SYNC_MAX_BYTES}")
        print(f"SAML_METADATA_SYNC_USER_AGENT: {SAML_METADATA_SYNC_USER_AGENT}")
        print("===================================")


def validate_config():
    """Validate that required configuration is present."""
    errors = []

    # Check WorkOS configuration
    if not WORKOS_API_KEY or not WORKOS_CLIENT_ID:
        errors.append("WorkOS credentials missing (WORKOS_API_KEY and WORKOS_CLIENT_ID)")

    # Check Teable configuration
    if not TEABLE_ACCESS_TOKEN:
        errors.append("TEABLE_ACCESS_TOKEN not set")
    if not TEABLE_BASE_ID:
        errors.append("TEABLE_BASE_ID not set")

    # Check all Teable table IDs
    teable_tables = {
        'TEABLE_TABLE_USERS': TEABLE_TABLE_USERS,
        'TEABLE_TABLE_ADMINS': TEABLE_TABLE_ADMINS,
        'TEABLE_TABLE_ADMIN_PERMISSIONS': TEABLE_TABLE_ADMIN_PERMISSIONS,
        'TEABLE_TABLE_API_KEYS': TEABLE_TABLE_API_KEYS,
        'TEABLE_TABLE_APPS': TEABLE_TABLE_APPS,
        'TEABLE_TABLE_APP_ACCESS_ENTRIES': TEABLE_TABLE_APP_ACCESS_ENTRIES,
        'TEABLE_TABLE_APP_ACCESS_AUDIT': TEABLE_TABLE_APP_ACCESS_AUDIT,
    }

    for table_var, table_id in teable_tables.items():
        if not table_id:
            errors.append(f"{table_var} not set")

    if SAML_ENABLED:
        if not SAML_IDP_ENTITY_ID:
            errors.append("SAML_IDP_ENTITY_ID not set")
        if not SAML_IDP_KEY_ACTIVE_PATH:
            errors.append("SAML_IDP_KEY_ACTIVE_PATH not set")
        if not SAML_IDP_CERT_ACTIVE_PATH:
            errors.append("SAML_IDP_CERT_ACTIVE_PATH not set")
        if not Path(SAML_XMLSEC_BINARY).exists():
            errors.append(f"SAML_XMLSEC_BINARY does not exist: {SAML_XMLSEC_BINARY}")

        for name, path in (
            ("SAML_IDP_KEY_ACTIVE_PATH", SAML_IDP_KEY_ACTIVE_PATH),
            ("SAML_IDP_CERT_ACTIVE_PATH", SAML_IDP_CERT_ACTIVE_PATH),
        ):
            if path and not Path(path).exists():
                errors.append(f"{name} does not exist: {path}")

    if errors:
        print("\n" + "="*60)
        print("❌ CONFIGURATION ERRORS DETECTED")
        print("="*60)
        for error in errors:
            print(f"  • {error}")
        print("\nPlease check your .env file and ensure all required variables are set.")
        print("\nFor Teable setup:")
        print("  1. Run: python teable_setup.py")
        print("  2. Add the table IDs it outputs to your .env file")
        print("="*60 + "\n")
        exit(1)
