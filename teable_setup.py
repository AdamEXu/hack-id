"""
Teable Database Setup Script
Creates all necessary tables in Teable for HackID migration

Run this script ONCE to set up your Teable database structure.
It will create 7 tables (persistent data only) and output the table IDs you'll need.

Tables created in Teable:
- users, admins, admin_permissions, api_keys, apps, app_access_entries, app_access_audit

Tables remaining in SQLite (ephemeral/temporary):
- email_codes, verification_tokens, opt_out_tokens, oauth_tokens, api_key_logs
"""

import os
import requests
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

TEABLE_API_URL = os.getenv('TEABLE_API_URL', 'https://app.teable.ai/api')
TEABLE_ACCESS_TOKEN = os.getenv('TEABLE_ACCESS_TOKEN')
TEABLE_BASE_ID = os.getenv('TEABLE_BASE_ID')

if not TEABLE_ACCESS_TOKEN or not TEABLE_BASE_ID:
    raise Exception("Missing TEABLE_ACCESS_TOKEN or TEABLE_BASE_ID in .env file")

headers = {
    'Authorization': f'Bearer {TEABLE_ACCESS_TOKEN}',
    'Content-Type': 'application/json'
}

def get_existing_tables():
    """Get all existing tables in the base"""
    url = f"{TEABLE_API_URL}/base/{TEABLE_BASE_ID}/table"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        tables = response.json()
        return {table['name']: table['id'] for table in tables}
    return {}

def create_table(table_config):
    """Create a table in Teable"""
    url = f"{TEABLE_API_URL}/base/{TEABLE_BASE_ID}/table"

    response = requests.post(url, headers=headers, json=table_config)

    if response.status_code in [200, 201]:
        data = response.json()
        print(f"✅ Created table: {table_config['name']} (ID: {data['id']})")
        return data
    else:
        print(f"❌ Failed to create table {table_config['name']}")
        print(f"   Status: {response.status_code}")
        print(f"   Response: {response.text}")
        return None

# Table configurations
TABLES = [
    {
        "name": "users",
        "description": "Core user profile information",
        "icon": "👤",
        "fields": [
            {
                "name": "email",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "legal_name",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "preferred_name",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "pronouns",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "dob",
                "type": "date",
                "options": {
                    "formatting": {
                        "date": "YYYY-MM-DD",
                        "time": "None",
                        "timeZone": "UTC"
                    }
                }
            },
            {
                "name": "discord_id",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "events",
                "type": "longText",
                "options": {}
            }
        ]
    },
    {
        "name": "admins",
        "description": "Admin user accounts",
        "icon": "👑",
        "fields": [
            {
                "name": "email",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "added_by",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "is_active",
                "type": "checkbox",
                "options": {}
            }
        ]
    },
    {
        "name": "admin_permissions",
        "description": "Fine-grained admin permissions",
        "icon": "🔐",
        "fields": [
            {
                "name": "admin_email",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "permission_type",
                "type": "singleSelect",
                "options": {
                    "choices": [
                        {"name": "event", "color": "blue"},
                        {"name": "page", "color": "green"},
                        {"name": "app", "color": "yellow"},
                        {"name": "*", "color": "red"}
                    ]
                }
            },
            {
                "name": "permission_value",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "access_level",
                "type": "singleSelect",
                "options": {
                    "choices": [
                        {"name": "read", "color": "cyan"},
                        {"name": "write", "color": "orange"}
                    ]
                }
            },
            {
                "name": "granted_by",
                "type": "singleLineText",
                "options": {}
            }
        ]
    },
    {
        "name": "api_keys",
        "description": "API keys for external integrations",
        "icon": "🔑",
        "fields": [
            {
                "name": "name",
                "type": "singleLineText",
                "options": {}
            },
            {
                # Stores SHA-256 hash of the API key (plaintext is never persisted)
                "name": "key",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "created_by",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "last_used_at",
                "type": "date",
                "options": {
                    "formatting": {
                        "date": "YYYY-MM-DD",
                        "time": "HH:mm",
                        "timeZone": "UTC"
                    }
                }
            },
            {
                "name": "permissions",
                "type": "longText",
                "options": {}
            },
            {
                "name": "metadata",
                "type": "longText",
                "options": {}
            },
            {
                "name": "rate_limit_rpm",
                "type": "number",
                "options": {
                    "formatting": {
                        "type": "decimal",
                        "precision": 0
                    }
                }
            }
        ]
    },
    {
        "name": "apps",
        "description": "OAuth 2.0 enabled external applications",
        "icon": "📱",
        "fields": [
            {
                "name": "name",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "icon",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "client_id",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "client_secret",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "redirect_uris",
                "type": "longText",
                "options": {}
            },
            {
                "name": "allowed_scopes",
                "type": "longText",
                "options": {}
            },
            {
                "name": "created_by",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "allow_anyone",
                "type": "checkbox",
                "options": {}
            },
            {
                "name": "skip_consent_screen",
                "type": "checkbox",
                "options": {}
            },
            {
                "name": "is_active",
                "type": "checkbox",
                "options": {}
            },
            {
                "name": "app_type",
                "type": "singleSelect",
                "options": {
                    "choices": [
                        {"name": "oauth", "color": "blue"},
                        {"name": "saml", "color": "green"}
                    ]
                }
            }
        ]
    },
    {
        "name": "app_access_entries",
        "description": "Application ACL principals",
        "icon": "🛡️",
        "fields": [
            {
                "name": "app_id",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "principal_type",
                "type": "singleSelect",
                "options": {
                    "choices": [
                        {"name": "email", "color": "blue"},
                        {"name": "group_admins", "color": "green"},
                        {"name": "group_event_attendees", "color": "orange"}
                    ]
                }
            },
            {
                "name": "principal_ref",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "role",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "created_by",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "created_at",
                "type": "date",
                "options": {
                    "formatting": {
                        "date": "YYYY-MM-DD",
                        "time": "HH:mm",
                        "timeZone": "UTC"
                    }
                }
            }
        ]
    },
    {
        "name": "app_access_audit",
        "description": "Audit history for ACL changes",
        "icon": "🧾",
        "fields": [
            {
                "name": "app_id",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "actor_email",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "action",
                "type": "singleLineText",
                "options": {}
            },
            {
                "name": "before_json",
                "type": "longText",
                "options": {}
            },
            {
                "name": "after_json",
                "type": "longText",
                "options": {}
            },
            {
                "name": "created_at",
                "type": "date",
                "options": {
                    "formatting": {
                        "date": "YYYY-MM-DD",
                        "time": "HH:mm",
                        "timeZone": "UTC"
                    }
                }
            }
        ]
    }
]

def main():
    print("\n🚀 Starting Teable Database Setup for HackID")
    print(f"📍 Base ID: {TEABLE_BASE_ID}")
    print(f"📍 API URL: {TEABLE_API_URL}\n")

    # Get existing tables
    print("🔍 Checking for existing tables...")
    existing_tables = get_existing_tables()
    if existing_tables:
        print(f"📋 Found {len(existing_tables)} existing tables:")
        for name, table_id in existing_tables.items():
            print(f"   - {name} ({table_id})")
    print()

    table_ids = {}

    for table_config in TABLES:
        table_name = table_config['name']

        # Check if table already exists
        if table_name in existing_tables:
            print(f"⏭️  Skipping {table_name} (already exists)")
            table_ids[table_name] = existing_tables[table_name]
        else:
            result = create_table(table_config)
            if result:
                table_ids[table_config['name']] = result['id']

    print("\n" + "="*60)
    print("✅ Setup Complete!")
    print("="*60)

    if table_ids:
        print("\n📝 Add these table IDs to your .env file:\n")
        for table_name, table_id in table_ids.items():
            env_var_name = f"TEABLE_TABLE_{table_name.upper()}"
            print(f"{env_var_name}={table_id}")

    print("\n🎉 You can now run the migration script!")

if __name__ == "__main__":
    main()
