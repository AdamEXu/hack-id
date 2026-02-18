"""Main Flask application - refactored and modular."""

import os
import secrets
from flask import Flask, request, jsonify, g
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from config import (
    SECRET_KEY,
    DEBUG_MODE,
    PROD,
    APP_ACL_MAX_ENTRIES,
    print_debug_info,
    validate_config,
    POSTHOG_API_KEY,
    POSTHOG_HOST,
    POSTHOG_ENABLED,
)
from utils.db_init import init_db, check_table_exists, list_all_tables
from utils.database import get_db_connection
from utils.rate_limiter import rate_limit_api_key, start_cleanup_thread
from utils.censoring import register_censoring_filters
from routes.auth import auth_bp, oauth_bp
from routes.admin import admin_bp
# from routes.admin_database import admin_database_bp  # DEPRECATED: Database swap feature obsolete with Teable migration
from routes.opt_out import opt_out_bp
from models.api_key import get_key_permissions, log_api_key_usage

# Create Flask app
app = Flask(__name__)
app.secret_key = SECRET_KEY

# Configure secure session cookies
app.config.update(
    SESSION_COOKIE_SECURE=PROD,  # Only send over HTTPS in production
    SESSION_COOKIE_HTTPONLY=True,  # Prevent XSS access to cookies
    SESSION_COOKIE_SAMESITE="Lax",  # CSRF protection
    PERMANENT_SESSION_LIFETIME=3600,  # 1 hour session timeout
)

# Register censoring filters for templates
register_censoring_filters(app)

# Initialize CSRF protection
csrf = CSRFProtect(app)


# Generate a unique nonce for each request for CSP
@app.before_request
def set_csp_nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


# PostHog context processor
@app.context_processor
def inject_posthog():
    """Inject PostHog configuration and user data into all templates."""
    from flask import session
    from models.user import get_user_by_email

    context = {
        'posthog_enabled': POSTHOG_ENABLED,
        'posthog_api_key': POSTHOG_API_KEY,
        'posthog_host': POSTHOG_HOST,
        'user_logged_in': 'user_email' in session,
    }

    # Add user data if logged in
    if 'user_email' in session:
        user = get_user_by_email(session['user_email'])
        if user:
            context.update({
                'user_email': user['email'],
                'user_preferred_name': user.get('preferred_name') or user.get('legal_name'),
                'user_events': user.get('events', []),
                'user_discord_id': user.get('discord_id'),
            })

    return context

# Initialize rate limiter (disabled in development)
if not DEBUG_MODE:
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"],
        storage_uri="memory://",
    )

    # Apply stricter rate limits to auth endpoints
    limiter.limit("5 per minute")(auth_bp)
else:
    # No rate limiting in development mode
    print("DEBUG: Rate limiting disabled in development mode")

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
# app.register_blueprint(admin_database_bp)  # DEPRECATED: Database swap feature obsolete with Teable
app.register_blueprint(opt_out_bp)

# Admin routes keep CSRF protection for security

# Import and register API blueprint
from routes.api import api_bp

app.register_blueprint(api_bp)

# Exempt API endpoints from CSRF protection (they use API key auth)
csrf.exempt(api_bp)

# Register OAuth 2.0 blueprint and exempt from CSRF (uses client_secret auth)
app.register_blueprint(oauth_bp)
csrf.exempt(oauth_bp)

# Import and register event admin blueprint
from routes.event_admin import event_admin_bp

app.register_blueprint(event_admin_bp)


# Security headers middleware
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    # Content Security Policy
    nonce = g.get("csp_nonce", "")
    csp = (
        "default-src 'self'; "
        f"script-src 'self' https://cdn.jsdelivr.net https://us-assets.i.posthog.com https://code.jquery.com https://cdn.datatables.net 'nonce-{nonce}'; "
        f"style-src 'self' https://cdn.jsdelivr.net https://fonts.googleapis.com https://cdn.datatables.net 'nonce-{nonce}'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://fonts.gstatic.com; "
        "connect-src 'self' https://us.i.posthog.com; "
        "frame-ancestors 'none';"
    )
    response.headers["Content-Security-Policy"] = csp

    # Other security headers
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

    # HSTS for production
    if PROD:
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

    return response


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


# Health check endpoint (for Docker/Kubernetes)
@app.route("/health", methods=["GET"])
def health_check():
    """Health check endpoint for container orchestration."""
    try:
        # Check database connectivity
        conn = get_db_connection()
        conn.execute("SELECT 1").fetchone()
        conn.close()

        return jsonify({
            "status": "healthy",
            "service": "hack-id",
            "database": "connected"
        }), 200
    except Exception as e:
        return jsonify({
            "status": "unhealthy",
            "error": str(e)
        }), 503


# Test API endpoint
@app.route("/api/test", methods=["GET"])
@require_api_key(["users.read"])
@rate_limit_api_key
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


def verify_teable_tables():
    """Verify Teable tables are accessible and print record counts."""
    from utils.teable import count_records, TEABLE_TABLE_IDS

    print("\n" + "="*60)
    print("🔍 VERIFYING TEABLE TABLES")
    print("="*60)

    all_accessible = True
    for table_name, table_id in TEABLE_TABLE_IDS.items():
        if not table_id:
            print(f"  ❌ {table_name}: Not configured")
            all_accessible = False
            continue

        try:
            count = count_records(table_name)
            print(f"  ✅ {table_name}: {count} records")
        except Exception as e:
            print(f"  ❌ {table_name}: Error - {str(e)}")
            all_accessible = False

    print("="*60 + "\n")

    if not all_accessible:
        print("⚠️  Some Teable tables are not accessible!")
        print("Please ensure:")
        print("  1. You've run: python teable_setup.py")
        print("  2. All table IDs are in your .env file")
        print("  3. Your TEABLE_ACCESS_TOKEN has access to these tables\n")
        exit(1)

    try:
        acl_count = count_records("app_access_entries")
        if acl_count >= 900:
            print(
                f"⚠️  ACL table has {acl_count} rows. Pagination is deferred; "
                "auth-path ACL reads currently assume <1000 rows."
            )
        if APP_ACL_MAX_ENTRIES >= 1000:
            print(
                "⚠️  APP_ACL_MAX_ENTRIES should remain below 1000 until paginated ACL reads are implemented."
            )
    except Exception as exc:
        print(f"⚠️  Unable to check ACL table count: {exc}")

    print("✅ All Teable tables are accessible!\n")


if __name__ == "__main__":
    # Print debug information
    print_debug_info()

    # Validate configuration
    validate_config()

    # Verify Teable tables
    verify_teable_tables()

    # Initialize database (SQLite for ephemeral tables)
    init_db()

    # Verify critical tables exist
    if DEBUG_MODE:
        list_all_tables()
        check_table_exists("oauth_tokens")

    # Start rate limiter cleanup thread (only in production)
    if not DEBUG_MODE:
        start_cleanup_thread()

    # Determine port based on environment
    port = int(os.getenv("PORT", 3000))
    app.run(debug=DEBUG_MODE, port=port, host="0.0.0.0")
