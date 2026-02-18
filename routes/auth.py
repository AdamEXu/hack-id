"""Authentication routes."""

from flask import (
    Blueprint,
    render_template,
    redirect,
    request,
    session,
    url_for,
    jsonify,
)
from flask import current_app
from services.auth_service import (
    send_email_verification,
    verify_email_code,
    handle_google_oauth_callback,
    get_google_auth_url,
    create_discord_verification_token,
    verify_discord_token,
    complete_discord_verification,
    unlink_discord_account,
)
from models.user import get_user_by_email, create_user, update_user
from models.oauth_token import create_oauth_token
from models.app import validate_app_redirect, has_app_permission, get_app_by_client_id, validate_redirect_uri
from models.oauth import (
    create_authorization_code,
    exchange_code_for_token,
    verify_access_token,
    revoke_access_token
)
from models.admin import is_admin
from config import DEBUG_MODE
from urllib.parse import unquote
import json

auth_bp = Blueprint("auth", __name__)
oauth_bp = Blueprint("oauth", __name__)  # Separate blueprint for OAuth 2.0 endpoints (CSRF exempt)


@auth_bp.route("/")
def index():
    """Home page - redirect to auth or dashboard based on login status."""
    if "user_email" in session:
        from models.admin import is_admin
        from services.dashboard_service import get_user_dashboard_data

        user_is_admin = is_admin(session["user_email"])
        dashboard_data = get_user_dashboard_data(session["user_email"])

        # If user hasn't completed registration, redirect to register
        if not dashboard_data["profile_complete"]:
            return redirect("/register")

        return render_template(
            "dashboard.html", is_admin=user_is_admin, dashboard=dashboard_data
        )
    else:
        return render_template("auth.html", state="email_login")


@auth_bp.route("/auth/google")
def auth_google():
    """Redirect to Google OAuth."""
    if DEBUG_MODE:
        print(f"DEBUG: Redirecting to Google OAuth")

    google_auth_url = get_google_auth_url()
    if DEBUG_MODE:
        print(f"DEBUG: Auth URL = {google_auth_url}")
    return redirect(google_auth_url)


@auth_bp.route("/auth/google/callback")
def auth_google_callback():
    """Handle Google OAuth callback."""
    state = request.args.get("state")
    if state != session.get("oauth_state"):
        return render_template(
            "auth.html", state="error", error="Invalid OAuth state."
        )
    session.pop("oauth_state", None)

    code = request.args.get("code")
    if not code:
        return render_template(
            "auth.html", state="error", error="No authentication code received."
        )

    result = handle_google_oauth_callback(code)

    if not result["success"]:
        return render_template("auth.html", state="error", error=result["error"])

    # Store user info in session
    session.permanent = True
    session["user_email"] = result["user"]["email"]
    session["user_name"] = result["user"]["name"]

    # Check if user needs to complete registration
    user = get_user_by_email(result["user"]["email"])
    if not user or not user.get("legal_name"):
        # User needs to complete registration
        # Keep verification_token in session if it exists for after registration
        return redirect("/register")

    # Check if this is part of Discord verification flow (after user exists)
    if "verification_token" in session:
        return redirect(url_for("auth.verify_complete"))

    # Check if this is part of OAuth 2.0 authorization code flow
    if "oauth2_client_id" in session:
        # Redirect back to /oauth/authorize to continue the flow
        # The OAuth parameters are already in the session
        return redirect("/oauth/authorize")

    # Check if this is part of legacy OAuth token flow
    if "oauth_redirect" in session and "oauth_app_id" in session:
        user_email = result["user"]["email"]
        app_id = session.get("oauth_app_id")
        redirect_url = session.get("oauth_redirect")

        # Get app info to check permissions
        from models.app import get_app_by_id
        app = get_app_by_id(app_id)

        if not app or not app['is_active']:
            session.pop("oauth_redirect", None)
            session.pop("oauth_app_id", None)
            return render_template(
                "auth.html",
                state="error",
                error="This app is no longer available."
            )

        # Check if app allows anyone or if user has permission
        if not app['allow_anyone']:
            if not is_admin(user_email):
                session.pop("oauth_redirect", None)
                session.pop("oauth_app_id", None)
                return render_template(
                    "auth.html",
                    state="error",
                    error="You don't have permission to access this app."
                )

            if not has_app_permission(user_email, app_id, 'read'):
                session.pop("oauth_redirect", None)
                session.pop("oauth_app_id", None)
                return render_template(
                    "auth.html",
                    state="error",
                    error="You don't have permission to access this app."
                )

        # Generate OAuth token and redirect to external app
        token = create_oauth_token(user_email, expires_in_seconds=120)
        session.pop("oauth_redirect", None)
        session.pop("oauth_app_id", None)
        separator = "&" if "?" in redirect_url else "?"
        return redirect(f"{redirect_url}{separator}token={token}")

    return redirect("/")


@auth_bp.route("/oauth/authorize")
def oauth_authorize():
    """
    OAuth 2.0 authorization endpoint.
    Implements the authorization code flow.
    """
    # Check if OAuth parameters are already in session (from previous redirect)
    # This happens when user wasn't logged in and had to authenticate first
    if "oauth2_client_id" in session and "oauth2_redirect_uri" in session:
        client_id = session.get("oauth2_client_id")
        redirect_uri = session.get("oauth2_redirect_uri")
        scope = session.get("oauth2_scope", "profile email")
        state = session.get("oauth2_state", "")
        response_type = "code"  # Always code for OAuth 2.0
    else:
        # Get OAuth 2.0 parameters from request (first time visiting this endpoint)
        client_id = request.args.get("client_id")
        redirect_uri = request.args.get("redirect_uri")
        scope = request.args.get("scope", "profile email")
        state = request.args.get("state", "")
        response_type = request.args.get("response_type", "code")

    # Validate required parameters
    if not client_id or not redirect_uri:
        return render_template(
            "auth.html",
            state="error",
            error="Missing required OAuth parameters (client_id or redirect_uri)"
        )

    # Validate response_type
    if response_type != "code":
        return render_template(
            "auth.html",
            state="error",
            error="Unsupported response_type. Only 'code' is supported."
        )

    # Get app by client_id
    app = get_app_by_client_id(client_id)
    if not app:
        return render_template(
            "auth.html",
            state="error",
            error="Invalid client_id. This app is not registered."
        )

    if not app.get('is_active'):
        return render_template(
            "auth.html",
            state="error",
            error="This app is currently disabled."
        )

    # Validate redirect_uri
    allowed_uris = json.loads(app.get('redirect_uris', '[]'))
    if not validate_redirect_uri(redirect_uri, allowed_uris):
        return render_template(
            "auth.html",
            state="error",
            error="Invalid redirect_uri. This URI is not registered for this app."
        )

    # Validate scopes
    allowed_scopes = json.loads(app.get('allowed_scopes', '["profile", "email"]'))
    requested_scopes = scope.split()
    for requested_scope in requested_scopes:
        if requested_scope not in allowed_scopes:
            return render_template(
                "auth.html",
                state="error",
                error=f"Invalid scope: {requested_scope}"
            )

    # Store OAuth 2.0 authorization parameters in session
    # Use "oauth2_" prefix to avoid conflicts with Google OAuth session vars
    session["oauth2_client_id"] = client_id
    session["oauth2_redirect_uri"] = redirect_uri
    session["oauth2_scope"] = scope
    session["oauth2_state"] = state
    session.permanent = True  # Ensure session persists

    # If user is already logged in, show consent screen or auto-approve
    if "user_email" in session:
        user = get_user_by_email(session["user_email"])
        if user and user.get("legal_name"):  # User has completed registration
            # Check if app allows anyone or if user has permission
            if not app.get('allow_anyone'):
                user_email = session["user_email"]

                # Restricted apps require: admin + explicit app permission
                if not is_admin(user_email) or not has_app_permission(
                    user_email, app["id"], "read"
                ):
                    return render_template(
                        "auth.html",
                        state="error",
                        error="You don't have permission to access this app."
                    )

            # Check if consent screen should be skipped
            if app.get('skip_consent_screen'):
                # Auto-approve: generate authorization code and redirect
                code = create_authorization_code(
                    client_id=client_id,
                    user_email=session["user_email"],
                    redirect_uri=redirect_uri,
                    scope=scope
                )

                # Clear OAuth session data
                session.pop("oauth2_client_id", None)
                session.pop("oauth2_redirect_uri", None)
                session.pop("oauth2_scope", None)
                session.pop("oauth2_state", None)

                # Redirect to app with authorization code
                separator = "&" if "?" in redirect_uri else "?"
                return redirect(f"{redirect_uri}{separator}code={code}&state={state}")

            # Show consent screen
            return render_template(
                "oauth_consent.html",
                app=app,
                scopes=requested_scopes,
                redirect_uri=redirect_uri,
                state=state
            )

    # User is not logged in, show login screen
    return render_template("auth.html", state="email_login")


@auth_bp.route("/oauth/authorize", methods=["POST"])
def oauth_authorize_consent():
    """Handle user consent for OAuth 2.0 authorization."""
    # Verify user is logged in
    if "user_email" not in session:
        return render_template(
            "auth.html",
            state="error",
            error="Session expired. Please log in again."
        )

    # Verify OAuth session data exists
    client_id = session.get("oauth2_client_id")
    redirect_uri = session.get("oauth2_redirect_uri")
    oauth_scope = session.get("oauth2_scope")
    state = session.get("oauth2_state", "")

    if not client_id or not redirect_uri or not oauth_scope:
        return render_template(
            "auth.html",
            state="error",
            error="Invalid OAuth session. Please try again."
        )

    # Get app by client_id and verify it's still active
    app = get_app_by_client_id(client_id)
    if not app or not app.get('is_active'):
        # Clear OAuth session
        session.pop("oauth2_client_id", None)
        session.pop("oauth2_redirect_uri", None)
        session.pop("oauth2_scope", None)
        session.pop("oauth2_state", None)

        # Redirect with error
        separator = "&" if "?" in redirect_uri else "?"
        return redirect(f"{redirect_uri}{separator}error=invalid_client&state={state}")

    # For restricted apps, re-validate permissions before issuing code
    if not app.get('allow_anyone'):
        user_email = session["user_email"]

        # Restricted apps require: admin + explicit app permission
        if not is_admin(user_email) or not has_app_permission(
            user_email, app["id"], "read"
        ):
            # Clear OAuth session
            session.pop("oauth2_client_id", None)
            session.pop("oauth2_redirect_uri", None)
            session.pop("oauth2_scope", None)
            session.pop("oauth2_state", None)

            # Redirect with error
            separator = "&" if "?" in redirect_uri else "?"
            return redirect(f"{redirect_uri}{separator}error=access_denied&error_description=insufficient_permissions&state={state}")

    # Check if user approved
    if request.form.get("action") != "approve":
        # User denied
        # Clear session
        session.pop("oauth2_client_id", None)
        session.pop("oauth2_redirect_uri", None)
        session.pop("oauth2_scope", None)
        session.pop("oauth2_state", None)

        # Redirect with error
        separator = "&" if "?" in redirect_uri else "?"
        return redirect(f"{redirect_uri}{separator}error=access_denied&state={state}")

    # User approved and permissions verified - generate authorization code
    code = create_authorization_code(
        client_id=client_id,
        user_email=session["user_email"],
        redirect_uri=redirect_uri,
        scope=oauth_scope
    )

    redirect_uri = session["oauth2_redirect_uri"]
    state = session.get("oauth2_state", "")

    # Clear OAuth session data
    session.pop("oauth2_client_id", None)
    session.pop("oauth2_redirect_uri", None)
    session.pop("oauth2_scope", None)
    session.pop("oauth2_state", None)

    # Redirect with authorization code
    separator = "&" if "?" in redirect_uri else "?"
    return redirect(f"{redirect_uri}{separator}code={code}&state={state}")


@oauth_bp.route("/oauth/token", methods=["POST"])
def oauth_token():
    """
    OAuth 2.0 token endpoint.
    Exchange authorization code for access token.

    Note: This blueprint (oauth_bp) is exempt from CSRF in app.py
    because OAuth 2.0 uses client_secret for authentication.
    """
    # Get parameters from POST body
    grant_type = request.form.get("grant_type")
    code = request.form.get("code")
    redirect_uri = request.form.get("redirect_uri")
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")

    if DEBUG_MODE:
        code_preview = (code[:20] + "...") if code else "None"
        print(
            f"OAuth token request: grant_type={grant_type}, code={code_preview}, "
            f"client_id={client_id}, redirect_uri={redirect_uri}"
        )

    # Validate grant_type
    if grant_type != "authorization_code":
        return jsonify({
            "error": "unsupported_grant_type",
            "error_description": "Only authorization_code grant type is supported"
        }), 400

    # Validate required parameters
    if not all([code, redirect_uri, client_id, client_secret]):
        return jsonify({
            "error": "invalid_request",
            "error_description": "Missing required parameters"
        }), 400

    # Exchange code for token
    result = exchange_code_for_token(code, client_id, client_secret, redirect_uri)

    if DEBUG_MODE:
        print(f"Token exchange result: {result}")

    if result["success"]:
        return jsonify({
            "access_token": result["access_token"],
            "token_type": result["token_type"],
            "expires_in": result["expires_in"],
            "scope": result["scope"]
        })
    else:
        error_descriptions = {
            "invalid_client": "Invalid client_id or client_secret",
            "invalid_grant": "Invalid, expired, or already used authorization code"
        }
        return jsonify({
            "error": result["error"],
            "error_description": error_descriptions.get(result["error"], "Invalid authorization code or client credentials")
        }), 400


@oauth_bp.route("/oauth/revoke", methods=["POST"])
def oauth_revoke():
    """OAuth 2.0 token revocation endpoint."""
    token = request.form.get("token")

    if not token:
        return jsonify({"error": "invalid_request"}), 400

    # Revoke the token
    revoked = revoke_access_token(token)

    # OAuth 2.0 spec says to return 200 even if token was already invalid
    return jsonify({"success": True}), 200


@auth_bp.route("/oauth")
def oauth_legacy():
    """
    LEGACY OAuth endpoint for backward compatibility.
    Redirects to new OAuth 2.0 flow or handles old token-based flow.
    """
    redirect_url = request.args.get("redirect")

    if not redirect_url:
        return render_template(
            "auth.html", state="error", error="Missing redirect parameter"
        )

    # Decode the redirect URL if it's URL encoded
    redirect_url = unquote(redirect_url)

    # Validate redirect URL against registered apps
    app = validate_app_redirect(redirect_url)

    if not app:
        return render_template(
            "auth.html",
            state="error",
            error="Invalid redirect URL. This app is not registered with Hack ID."
        )

    if not app['is_active']:
        return render_template(
            "auth.html",
            state="error",
            error="This app is currently disabled."
        )

    # Store app info and redirect URL in session for after login
    session["oauth_app_id"] = app['id']
    session["oauth_redirect"] = redirect_url

    # If user is already logged in, check permissions and redirect
    if "user_email" in session:
        user = get_user_by_email(session["user_email"])
        if user and user.get("legal_name"):  # User has completed registration
            user_email = session["user_email"]

            # Check if app allows anyone or if user has permission
            if not app['allow_anyone']:
                # App is restricted - check if user is admin with permission
                if not is_admin(user_email):
                    return render_template(
                        "auth.html",
                        state="error",
                        error="You don't have permission to access this app. Please contact an administrator."
                    )

                if not has_app_permission(user_email, app['id'], 'read'):
                    return render_template(
                        "auth.html",
                        state="error",
                        error="You don't have permission to access this app. Please contact an administrator."
                    )

            # Generate temporary OAuth token
            token = create_oauth_token(user_email, expires_in_seconds=120)

            # Clear the oauth data from session
            session.pop("oauth_app_id", None)
            session.pop("oauth_redirect", None)

            # Redirect to the external application with token
            separator = "&" if "?" in redirect_url else "?"
            return redirect(f"{redirect_url}{separator}token={token}")

    # User is not logged in or hasn't completed registration, show login screen
    return render_template("auth.html", state="email_login")


@auth_bp.route("/logout")
def logout():
    """Log out the user."""
    session.clear()
    return redirect("/")


@auth_bp.route("/send-code", methods=["POST"])
def send_code():
    """Send magic link to email via WorkOS."""
    # Handle both JSON and form data
    if request.is_json:
        data = request.get_json()
        email = data.get("email")
    else:
        email = request.form.get("email")

    if not email:
        if request.is_json:
            return jsonify({"success": False, "error": "Email is required"})
        else:
            return render_template(
                "auth.html", state="email_login", error="Email is required"
            )

    success = send_email_verification(email)

    if success:
        if request.is_json:
            return jsonify({"success": True, "message": "Magic link sent to your email"})
        else:
            # Show a message that they should check their email for the magic link
            return render_template(
                "auth.html",
                state="email_sent",
                email=email,
                message="Check your email for a magic link to sign in"
            )
    else:
        error_msg = "Failed to send magic link"
        if request.is_json:
            return jsonify({"success": False, "error": error_msg})
        else:
            return render_template("auth.html", state="email_login", error=error_msg)


@auth_bp.route("/auth/email/callback")
def email_callback():
    """Handle WorkOS magic link callback."""
    code = request.args.get("code")

    if not code:
        return render_template("auth.html", state="email_login", error="No code provided")

    # Verify the code with WorkOS
    result = verify_email_code(code)

    if not result.get("success"):
        return render_template(
            "auth.html",
            state="email_login",
            error=result.get("error", "Authentication failed"),
        )

    email = result["email"]
    name = result.get("name", "")

    # Check if user exists
    user = get_user_by_email(email)
    if user:
        session.permanent = True
        session["user_email"] = email
        session["user_name"] = user.get("preferred_name") or user.get("legal_name") or name

        # Check if this is part of OAuth 2.0 authorization code flow
        if "oauth2_client_id" in session and user.get("legal_name"):
            # Redirect back to /oauth/authorize to continue the flow
            # The OAuth parameters are already in the session
            return redirect("/oauth/authorize")

        # Check if this is part of legacy OAuth token flow
        if "oauth_redirect" in session and "oauth_app_id" in session and user.get("legal_name"):
            user_email = session["user_email"]
            app_id = session.get("oauth_app_id")
            redirect_url = session.get("oauth_redirect")

            # Get app info to check permissions
            from models.app import get_app_by_id
            app = get_app_by_id(app_id)

            if not app or not app['is_active']:
                session.pop("oauth_redirect", None)
                session.pop("oauth_app_id", None)
                return render_template(
                    "auth.html",
                    state="error",
                    error="This app is no longer available."
                )

            # Check if app allows anyone or if user has permission
            if not app['allow_anyone']:
                if not is_admin(user_email):
                    session.pop("oauth_redirect", None)
                    session.pop("oauth_app_id", None)
                    return render_template(
                        "auth.html",
                        state="error",
                        error="You don't have permission to access this app."
                    )

                if not has_app_permission(user_email, app_id, 'read'):
                    session.pop("oauth_redirect", None)
                    session.pop("oauth_app_id", None)
                    return render_template(
                        "auth.html",
                        state="error",
                        error="You don't have permission to access this app."
                    )

            # Generate OAuth token and redirect to external app
            token = create_oauth_token(user_email, expires_in_seconds=120)
            session.pop("oauth_redirect", None)
            session.pop("oauth_app_id", None)
            separator = "&" if "?" in redirect_url else "?"
            final_redirect = f"{redirect_url}{separator}token={token}"
            return redirect(final_redirect)

        return redirect("/")
    else:
        # User doesn't exist, redirect to registration
        session.permanent = True
        session["user_email"] = email
        session["user_name"] = name
        session["pending_registration"] = True
        return redirect("/register")


@auth_bp.route("/verify-code", methods=["POST"])
def verify_code_route():
    """Legacy route - now just redirects to send magic link."""
    # This route is kept for backwards compatibility but now uses WorkOS
    # The actual verification happens in /email/callback
    return jsonify({
        "success": False,
        "error": "Please use the magic link sent to your email instead"
    })


@auth_bp.route("/verify")
def verify_discord():
    """Discord verification endpoint."""
    token = request.args.get("token")
    if not token:
        return render_template(
            "auth.html", state="error", error="Missing verification token."
        )

    token_info = verify_discord_token(token)

    if not token_info:
        return render_template(
            "auth.html", state="error", error="Invalid or expired verification link."
        )

    # Store token in session for later use
    session.permanent = True
    session["verification_token"] = token
    session["discord_id"] = token_info["discord_id"]
    session["discord_username"] = token_info["discord_username"]

    # If user is already logged in, complete verification
    if "user_email" in session:
        return redirect(url_for("auth.verify_complete"))

    # Store verification token in session for after login/registration
    session["verification_token"] = token

    # Show login options (like OAuth flow) instead of immediately redirecting to Google
    return render_template("auth.html", state="email_login", verification_flow=True)


@auth_bp.route("/verify/complete")
def verify_complete():
    """Complete Discord verification."""
    if "verification_token" not in session:
        return render_template(
            "auth.html", state="error", error="Invalid verification state."
        )

    # If user is not logged in, redirect to login
    if "user_email" not in session:
        return render_template(
            "auth.html",
            state="error",
            error="Please log in first to complete Discord verification.",
        )

    result = complete_discord_verification(
        session["verification_token"], session["user_email"]
    )

    if result["success"]:
        # Get full user data for the success page
        user = get_user_by_email(session["user_email"])

        # Clear verification session data
        session.pop("verification_token", None)
        session.pop("discord_id", None)
        session.pop("discord_username", None)

        return render_template(
            "verify_success.html",
            preferred_name=user.get("preferred_name")
            or user.get("legal_name")
            or "User",
            email=user["email"],
            events=user.get("events", []),
            discord_username=result["discord_username"],
            roles_assigned=result.get("roles_assigned", []),
            roles_failed=result.get("roles_failed", []),
            total_roles_assigned=result.get("total_roles_assigned", 0),
            total_roles_failed=result.get("total_roles_failed", 0),
        )
    else:
        return render_template("auth.html", state="error", error=result["error"])


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    """User registration form to complete profile."""
    if "user_email" not in session:
        return redirect(url_for("auth.index"))

    user_email = session["user_email"]
    user_name = session.get("user_name", "")

    # Check if user already has complete registration
    user = get_user_by_email(user_email)
    if user and user.get("legal_name") and not session.get("pending_registration"):
        return redirect("/")

    if request.method == "GET":
        return render_template(
            "register.html", user_email=user_email, user_name=user_name
        )

    # Handle POST - process registration
    legal_name = request.form.get("legal_name", "").strip()
    preferred_name = request.form.get("preferred_name", "").strip()
    pronouns = request.form.get("pronouns", "").strip()
    dob = request.form.get("dob", "").strip()

    # Validation
    errors = []
    if not legal_name:
        errors.append("Legal name is required")
    if not dob:
        errors.append("Date of birth is required")
    if not pronouns:
        errors.append("Pronouns are required")

    # Validate and convert date format from YYYY-MM-DD to MM/DD/YYYY
    if dob:
        try:
            from datetime import datetime

            # Parse the HTML date input format (YYYY-MM-DD)
            date_obj = datetime.strptime(dob, "%Y-%m-%d")
            # Convert to MM/DD/YYYY format for storage
            dob = date_obj.strftime("%m/%d/%Y")
        except ValueError:
            errors.append("Invalid date format")

    if errors:
        return render_template(
            "register.html",
            user_email=user_email,
            user_name=user_name,
            errors=errors,
            legal_name=legal_name,
            preferred_name=preferred_name,
            pronouns=pronouns,
            dob=dob,
        )

    # Create or update user
    if user:
        # Update existing user
        try:
            update_user(
                user["id"],
                legal_name=legal_name,
                preferred_name=preferred_name or None,
                pronouns=pronouns,
                dob=dob,
            )
        except ValueError as e:
            return render_template(
                "register.html",
                user_email=user_email,
                user_name=user_name,
                errors=[str(e)],
                legal_name=legal_name,
                preferred_name=preferred_name,
                pronouns=pronouns,
                dob=dob,
            )
    else:
        # Create new user
        create_user(
            email=user_email,
            legal_name=legal_name,
            preferred_name=preferred_name or None,
            pronouns=pronouns,
            dob=dob,
        )

    # Clear pending registration flag
    session.pop("pending_registration", None)

    # Check if this is part of Discord verification flow
    if "verification_token" in session:
        return redirect(url_for("auth.verify_complete"))

    # Check if this is part of NEW OAuth 2.0 flow (authorization code flow)
    if "oauth2_client_id" in session:
        # Redirect back to /oauth/authorize to continue the flow
        # This will handle skip_consent_screen and all permission checks
        return redirect("/oauth/authorize")

    # Check if this is part of LEGACY OAuth flow (token-based)
    if "oauth_redirect" in session and "oauth_app_id" in session:
        user_email = session["user_email"]
        app_id = session.get("oauth_app_id")
        redirect_url = session.get("oauth_redirect")

        # Get app info to check permissions
        from models.app import get_app_by_id

        app = get_app_by_id(app_id)

        if not app or not app["is_active"]:
            session.pop("oauth_redirect", None)
            session.pop("oauth_app_id", None)
            return render_template(
                "auth.html",
                state="error",
                error="This app is no longer available."
            )

        # Check if app allows anyone or if user has permission
        if not app["allow_anyone"]:
            if not is_admin(user_email):
                session.pop("oauth_redirect", None)
                session.pop("oauth_app_id", None)
                return render_template(
                    "auth.html",
                    state="error",
                    error="You don't have permission to access this app."
                )

            if not has_app_permission(user_email, app_id, "read"):
                session.pop("oauth_redirect", None)
                session.pop("oauth_app_id", None)
                return render_template(
                    "auth.html",
                    state="error",
                    error="You don't have permission to access this app."
                )

        # Generate OAuth token and redirect to external app
        token = create_oauth_token(user_email, expires_in_seconds=120)
        session.pop("oauth_redirect", None)
        session.pop("oauth_app_id", None)
        separator = "&" if "?" in redirect_url else "?"
        return redirect(f"{redirect_url}{separator}token={token}")

    # If we had an incomplete OAuth session (redirect without app id), clear it
    if "oauth_redirect" in session and "oauth_app_id" not in session:
        session.pop("oauth_redirect", None)

    return redirect("/")


@auth_bp.route("/dashboard/discord/unlink", methods=["POST"])
def unlink_discord_dashboard():
    """Unlink Discord account from dashboard (user-facing, no API key required)."""
    if "user_email" not in session:
        return jsonify({"success": False, "error": "Not logged in"}), 401

    try:
        user_email = session["user_email"]

        # Use the service function that handles role removal
        result = unlink_discord_account(user_email)

        if result["success"]:
            return (
                jsonify(
                    {
                        "success": True,
                        "message": "Discord account successfully unlinked",
                        "roles_removed": result.get("total_roles_removed", 0),
                        "roles_failed": result.get("total_roles_failed", 0),
                        "role_removal_success": result.get(
                            "role_removal_success", False
                        ),
                    }
                ),
                200,
            )
        else:
            return jsonify({"success": False, "error": result["error"]}), 400

    except Exception as e:
        if DEBUG_MODE:
            print(f"Error in unlink_discord_dashboard: {e}")
        return jsonify({"success": False, "error": "Internal server error"}), 500
