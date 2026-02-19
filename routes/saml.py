"""SAML runtime routes (SSO/SLO/metadata)."""

from __future__ import annotations

from urllib.parse import urlparse
from typing import Any, Dict

from flask import Blueprint, Response, g, redirect, render_template, request, session

from config import BASE_URL
from models.app import APP_TYPE_SAML, get_app_by_id
from services.app_access_service import evaluate_app_acl_with_fail_open
from services.saml_audit_service import log_saml_event
from services.saml_service import (
    SamlProtocolError,
    create_idp_initiated_response,
    create_sp_initiated_response,
    ensure_profile_complete,
    generate_idp_metadata_xml,
    parse_and_validate_authn_request,
    process_logout_request,
    process_logout_response,
    resolve_saml_app_for_message,
)

SAML_BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
SAML_BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"

saml_bp = Blueprint("saml", __name__, url_prefix="/saml")
# Separate blueprint to keep launch endpoint CSRF-protected and individually rate-limited.
saml_launch_bp = Blueprint("saml_launch", __name__, url_prefix="/saml")

_PENDING_KEYS = (
    "saml_pending_flow",
    "saml_pending_app_id",
    "saml_pending_request_id",
    "saml_pending_relay_state",
    "saml_pending_return_path",
    "saml_pending_request_binding",
    "saml_pending_request_payload",
    "saml_pending_request_signature_present",
    "saml_pending_request_sigalg_present",
)


def _clear_pending_saml_state() -> None:
    for key in _PENDING_KEYS:
        session.pop(key, None)


def _set_pending_saml_state(
    *,
    flow: str,
    app_id: str,
    request_id: str,
    relay_state: str,
    return_path: str,
    request_binding: str,
    request_payload: str,
    request_signature_present: bool = False,
    request_sigalg_present: bool = False,
) -> None:
    session["saml_pending_flow"] = flow
    session["saml_pending_app_id"] = app_id
    session["saml_pending_request_id"] = request_id
    session["saml_pending_relay_state"] = relay_state
    session["saml_pending_return_path"] = return_path
    session["saml_pending_request_binding"] = request_binding
    session["saml_pending_request_payload"] = request_payload
    session["saml_pending_request_signature_present"] = bool(request_signature_present)
    session["saml_pending_request_sigalg_present"] = bool(request_sigalg_present)
    session.permanent = True


def _same_site_request() -> bool:
    def _normalize_origin(value: str) -> str:
        parsed = urlparse((value or "").strip())
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
        return ""

    origin = _normalize_origin(request.headers.get("Origin", ""))
    referer = _normalize_origin(request.headers.get("Referer", ""))
    allowed_origins = {
        candidate
        for candidate in {
            _normalize_origin(request.host_url),
            _normalize_origin(request.url_root),
            _normalize_origin(BASE_URL),
        }
        if candidate
    }

    forwarded_proto = (request.headers.get("X-Forwarded-Proto") or "").split(",")[0].strip()
    forwarded_host = (request.headers.get("X-Forwarded-Host") or "").split(",")[0].strip()
    if forwarded_proto and forwarded_host:
        forwarded_origin = _normalize_origin(f"{forwarded_proto}://{forwarded_host}")
        if forwarded_origin:
            allowed_origins.add(forwarded_origin)

    if origin:
        return origin in allowed_origins
    if referer:
        return referer in allowed_origins
    return False


def _ensure_user_ready() -> bool:
    if "user_email" not in session:
        return False
    return ensure_profile_complete(session["user_email"])


def _render_saml_post(payload: Dict[str, Any]) -> Response:
    destination = (payload.get("destination") or "").strip()
    form_action_origin = payload.get("form_action_origin")
    if not form_action_origin and destination:
        parsed = urlparse(destination)
        if parsed.scheme and parsed.netloc:
            form_action_origin = f"{parsed.scheme}://{parsed.netloc}"
    if form_action_origin:
        g.saml_form_action_origin = form_action_origin
    form_action_destination = destination
    if form_action_destination:
        g.saml_form_action_destination = form_action_destination
        if form_action_destination.startswith("https://"):
            # Browser/WebView CSP parsers can vary; allow HTTPS form fallback on SAML response pages.
            g.saml_form_action_allow_https = True

    return Response(
        render_template(
            "saml_post_response.html",
            destination=payload["destination"],
            saml_response=payload["saml_response"],
            relay_state=payload.get("relay_state", ""),
        )
    )


def _validate_saml_app_runtime(app: Dict[str, Any]) -> None:
    if app.get("app_type") != APP_TYPE_SAML:
        raise SamlProtocolError("App is not configured as SAML")
    if not app.get("is_active"):
        raise SamlProtocolError("SAML app is disabled")
    if not app.get("saml_enabled"):
        raise SamlProtocolError("SAML app is not enabled")
    if app.get("allow_anyone"):
        raise SamlProtocolError("SAML app is misconfigured: allow_anyone is not permitted")


def _complete_sp_initiated_flow(
    *,
    app: Dict[str, Any],
    saml_request: str,
    binding: str,
    relay_state: str,
    request_signature_present: bool,
    request_sigalg_present: bool,
    path: str,
) -> Response:
    access_result = evaluate_app_acl_with_fail_open(
        app=app,
        user_email=session["user_email"],
        path=path,
        sess=session,
    )
    if not access_result.get("allowed"):
        log_saml_event(
            event_type="sso_denied",
            app_id=app.get("id"),
            user_email=session.get("user_email"),
            sp_entity_id=app.get("saml_entity_id"),
            outcome="denied",
            reason=access_result.get("reason"),
        )
        return Response(
            render_template(
                "auth.html",
                state="error",
                error="You do not have access to this SAML application.",
            ),
            status=403,
        )

    request_hint = parse_and_validate_authn_request(
        app=app,
        saml_request=saml_request,
        binding=binding,
        request_signature_present=request_signature_present,
        request_sigalg_present=request_sigalg_present,
    )

    payload = create_sp_initiated_response(
        app=app,
        user_email=session["user_email"],
        request_hint=request_hint,
        relay_state=relay_state,
    )
    return _render_saml_post(payload)


@saml_bp.route("/metadata", methods=["GET"])
def saml_metadata() -> Response:
    """Public IdP metadata endpoint."""
    return Response(generate_idp_metadata_xml(), mimetype="application/samlmetadata+xml")


@saml_bp.route("/sso", methods=["GET", "POST"])
def saml_sso() -> Response:
    """SP-initiated SSO endpoint."""
    saml_request = request.args.get("SAMLRequest") if request.method == "GET" else request.form.get("SAMLRequest")
    relay_state = request.args.get("RelayState", "") if request.method == "GET" else request.form.get("RelayState", "")

    if not saml_request:
        return Response("Missing SAMLRequest", status=400)

    binding = SAML_BINDING_HTTP_REDIRECT if request.method == "GET" else SAML_BINDING_HTTP_POST
    request_signature_present = bool(request.args.get("Signature")) if request.method == "GET" else False
    request_sigalg_present = bool(request.args.get("SigAlg")) if request.method == "GET" else False

    try:
        app, hint, _xml_text = resolve_saml_app_for_message(saml_request, binding)
        _validate_saml_app_runtime(app)
    except SamlProtocolError as exc:
        return Response(
            render_template("auth.html", state="error", error=str(exc)),
            status=400,
        )

    if not _ensure_user_ready():
        _set_pending_saml_state(
            flow="sp_initiated",
            app_id=app.get("id", ""),
            request_id=hint.request_id,
            relay_state=relay_state,
            return_path="/saml/continue",
            request_binding=binding,
            request_payload=saml_request,
            request_signature_present=request_signature_present,
            request_sigalg_present=request_sigalg_present,
        )

        log_saml_event(
            event_type="sso_pending_auth",
            app_id=app.get("id"),
            user_email=session.get("user_email"),
            sp_entity_id=app.get("saml_entity_id"),
            request_id=hint.request_id,
            outcome="pending",
            reason="login_or_profile_required",
        )

        if "user_email" not in session:
            return redirect("/")
        return redirect("/register")

    try:
        response = _complete_sp_initiated_flow(
            app=app,
            saml_request=saml_request,
            binding=binding,
            relay_state=relay_state,
            request_signature_present=request_signature_present,
            request_sigalg_present=request_sigalg_present,
            path=request.path,
        )
        _clear_pending_saml_state()
        return response
    except SamlProtocolError as exc:
        log_saml_event(
            event_type="sso_sp_initiated",
            app_id=app.get("id"),
            user_email=session.get("user_email"),
            sp_entity_id=app.get("saml_entity_id"),
            request_id=hint.request_id,
            outcome="error",
            reason=str(exc),
        )
        return Response(
            render_template("auth.html", state="error", error=f"SAML request rejected: {exc}"),
            status=400,
        )


@saml_launch_bp.route("/apps/<app_id>/launch", methods=["POST"])
def saml_launch(app_id: str) -> Response:
    """IdP-initiated app launcher endpoint."""
    if not _same_site_request():
        return Response("Invalid launch origin", status=403)

    app = get_app_by_id(app_id)
    if not app:
        return Response("App not found", status=404)

    try:
        _validate_saml_app_runtime(app)
    except SamlProtocolError as exc:
        return Response(str(exc), status=400)

    relay_state = (request.form.get("RelayState") or request.form.get("relay_state") or "").strip()

    if not _ensure_user_ready():
        _set_pending_saml_state(
            flow="idp_initiated",
            app_id=app.get("id", ""),
            request_id="",
            relay_state=relay_state,
            return_path="/saml/continue",
            request_binding=SAML_BINDING_HTTP_POST,
            request_payload="",
        )
        if "user_email" not in session:
            return redirect("/")
        return redirect("/register")

    access_result = evaluate_app_acl_with_fail_open(
        app=app,
        user_email=session["user_email"],
        path=request.path,
        sess=session,
    )
    if not access_result.get("allowed"):
        return Response(
            render_template("auth.html", state="error", error="You do not have access to this SAML application."),
            status=403,
        )

    try:
        payload = create_idp_initiated_response(
            app=app,
            user_email=session["user_email"],
            relay_state=relay_state,
        )
        _clear_pending_saml_state()
        return _render_saml_post(payload)
    except SamlProtocolError as exc:
        log_saml_event(
            event_type="sso_idp_initiated",
            app_id=app.get("id"),
            user_email=session.get("user_email"),
            sp_entity_id=app.get("saml_entity_id"),
            outcome="error",
            reason=str(exc),
        )
        return Response(
            render_template("auth.html", state="error", error=f"SAML launch failed: {exc}"),
            status=400,
        )


@saml_bp.route("/continue", methods=["GET"])
def saml_continue() -> Response:
    """Continue deferred SAML flow after login/registration."""
    flow = session.get("saml_pending_flow")
    if not flow:
        return redirect("/")

    app = get_app_by_id(session.get("saml_pending_app_id", ""))
    if not app:
        _clear_pending_saml_state()
        return Response(
            render_template("auth.html", state="error", error="Pending SAML app no longer exists."),
            status=400,
        )

    try:
        _validate_saml_app_runtime(app)
    except SamlProtocolError as exc:
        _clear_pending_saml_state()
        return Response(
            render_template("auth.html", state="error", error=str(exc)),
            status=400,
        )

    if not _ensure_user_ready():
        if "user_email" not in session:
            return redirect("/")
        return redirect("/register")

    try:
        if flow == "idp_initiated":
            payload = create_idp_initiated_response(
                app=app,
                user_email=session["user_email"],
                relay_state=session.get("saml_pending_relay_state", ""),
            )
            _clear_pending_saml_state()
            return _render_saml_post(payload)

        response = _complete_sp_initiated_flow(
            app=app,
            saml_request=session.get("saml_pending_request_payload", ""),
            binding=session.get("saml_pending_request_binding", SAML_BINDING_HTTP_POST),
            relay_state=session.get("saml_pending_relay_state", ""),
            request_signature_present=bool(session.get("saml_pending_request_signature_present")),
            request_sigalg_present=bool(session.get("saml_pending_request_sigalg_present")),
            path="/saml/continue",
        )
        _clear_pending_saml_state()
        return response
    except SamlProtocolError as exc:
        return Response(
            render_template("auth.html", state="error", error=f"Failed to continue SAML flow: {exc}"),
            status=400,
        )


@saml_bp.route("/slo", methods=["GET", "POST"])
def saml_slo() -> Response:
    """SAML SLO endpoint for LogoutRequest and LogoutResponse."""
    binding = SAML_BINDING_HTTP_REDIRECT if request.method == "GET" else SAML_BINDING_HTTP_POST

    saml_request = request.args.get("SAMLRequest") if request.method == "GET" else request.form.get("SAMLRequest")
    saml_response = request.args.get("SAMLResponse") if request.method == "GET" else request.form.get("SAMLResponse")
    relay_state = request.args.get("RelayState", "") if request.method == "GET" else request.form.get("RelayState", "")

    if saml_request:
        try:
            app, hint, _xml_text = resolve_saml_app_for_message(saml_request, binding)
            _validate_saml_app_runtime(app)
            result = process_logout_request(
                app=app,
                saml_request=saml_request,
                binding=binding,
                relay_state=relay_state,
            )
        except SamlProtocolError as exc:
            return Response(
                render_template("auth.html", state="error", error=f"SLO request failed: {exc}"),
                status=400,
            )

        redirect_url = result.get("redirect_url")
        if redirect_url:
            return redirect(redirect_url)

        html = result.get("html")
        if html:
            destination = result.get("destination", "")
            if destination:
                parsed = destination.split("/")
                if len(parsed) >= 3 and destination.startswith("http"):
                    g.saml_form_action_origin = "/".join(parsed[:3])
            return Response(html)

        return Response(
            render_template(
                "auth.html",
                state="email_login",
                message="Single logout request processed.",
            )
        )

    if saml_response:
        try:
            app, _hint, _xml_text = resolve_saml_app_for_message(saml_response, binding)
            _validate_saml_app_runtime(app)
            process_logout_response(
                app=app,
                saml_response=saml_response,
                binding=binding,
            )
        except SamlProtocolError as exc:
            return Response(
                render_template("auth.html", state="error", error=f"SLO response failed: {exc}"),
                status=400,
            )
        return redirect("/")

    return Response("Missing SAMLRequest or SAMLResponse", status=400)
