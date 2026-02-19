"""Core SAML IdP protocol service helpers."""

from __future__ import annotations

import base64
import json
import os
import tempfile
import time
import urllib.parse
import xml.etree.ElementTree as ET
import zlib
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.sax.saxutils import escape

from config import BASE_URL, SAML_IDP_ENTITY_ID, SAML_XMLSEC_BINARY
from models.app import SAML_DEFAULT_NAMEID_FORMAT, get_app_by_saml_entity_id
from models.user import get_user_by_email
from services.saml_audit_service import log_saml_event
from services.saml_keys import get_active_cert_path, get_active_key_path, get_idp_certificates_for_metadata
from utils.database import get_db_connection
from utils.validation import normalize_email

SAML_SP_SESSION_TTL_SECONDS = 12 * 60 * 60
SAML_REQUEST_REPLAY_TTL_SECONDS = 10 * 60


class SamlProtocolError(RuntimeError):
    """Raised for SAML protocol validation/processing errors."""


@dataclass
class SamlRequestHint:
    issuer: str
    request_id: str
    destination: str
    acs_url: str
    is_logout: bool
    has_xml_signature: bool
    name_id: str = ""
    session_indexes: Optional[List[str]] = None


def _now_epoch() -> int:
    return int(time.time())


def _strip_ns(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _decode_saml_message(raw_value: str, binding: str) -> str:
    try:
        decoded = base64.b64decode(raw_value)
    except Exception as exc:  # noqa: BLE001
        raise SamlProtocolError(f"Invalid SAML message encoding: {exc}") from exc

    if binding.endswith("HTTP-Redirect"):
        for wbits in (-15, zlib.MAX_WBITS):
            try:
                inflated = zlib.decompress(decoded, wbits)
                return inflated.decode("utf-8", errors="replace")
            except Exception:
                continue
        raise SamlProtocolError("Unable to inflate redirect-bound SAML request")

    return decoded.decode("utf-8", errors="replace")


def _extract_request_hint(xml_text: str) -> SamlRequestHint:
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise SamlProtocolError(f"Malformed SAML XML: {exc}") from exc

    root_name = _strip_ns(root.tag)
    is_logout = root_name == "LogoutRequest"
    issuer = ""
    request_id = root.attrib.get("ID", "")
    destination = root.attrib.get("Destination", "")
    acs_url = root.attrib.get("AssertionConsumerServiceURL", "")
    has_xml_signature = False
    name_id = ""
    session_indexes: List[str] = []

    for node in root.iter():
        node_name = _strip_ns(node.tag)
        if node_name == "Issuer" and (node.text or "").strip():
            issuer = (node.text or "").strip()
        elif node_name == "Signature":
            has_xml_signature = True
        elif node_name == "NameID" and (node.text or "").strip():
            name_id = (node.text or "").strip()
        elif node_name == "SessionIndex" and (node.text or "").strip():
            session_indexes.append((node.text or "").strip())

    return SamlRequestHint(
        issuer=issuer,
        request_id=request_id,
        destination=destination,
        acs_url=acs_url,
        is_logout=is_logout,
        has_xml_signature=has_xml_signature,
        name_id=name_id,
        session_indexes=session_indexes,
    )


def resolve_saml_app_for_message(raw_saml_message: str, binding: str) -> Tuple[Dict[str, Any], SamlRequestHint, str]:
    """Resolve SP app by issuer from a SAMLRequest or LogoutRequest payload."""
    xml_text = _decode_saml_message(raw_saml_message, binding)
    hint = _extract_request_hint(xml_text)
    if not hint.issuer:
        raise SamlProtocolError("SAML message missing Issuer")

    app = get_app_by_saml_entity_id(hint.issuer)
    if not app:
        raise SamlProtocolError("No active SAML app configured for Issuer")
    return app, hint, xml_text


def ensure_profile_complete(user_email: str) -> bool:
    user = get_user_by_email(user_email)
    if not user:
        return False
    return bool(user.get("legal_name") and user.get("pronouns") and user.get("dob"))


def _certs_from_app(app: Dict[str, Any]) -> List[str]:
    certs = app.get("saml_sp_signing_certs")
    if isinstance(certs, list):
        return [c for c in certs if isinstance(c, str) and c.strip()]

    raw = app.get("saml_sp_signing_certs_json")
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [c for c in parsed if isinstance(c, str) and c.strip()]
    except (TypeError, ValueError):
        pass
    return []


def _build_sp_metadata_xml(app: Dict[str, Any]) -> str:
    entity_id = escape(app.get("saml_entity_id") or "")
    acs_url = escape(app.get("saml_acs_url") or "")
    acs_binding = escape(app.get("saml_acs_binding") or "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
    slo_url = escape(app.get("saml_slo_url") or "")
    require_signed = "true" if app.get("saml_require_signed_authn_request") else "false"

    key_descriptors = ""
    for cert in _certs_from_app(app):
        key_descriptors += (
            "<md:KeyDescriptor use=\"signing\">"
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
            f"{escape(cert)}"
            "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
            "</md:KeyDescriptor>"
        )

    slo_fragment = ""
    if slo_url:
        slo_fragment = (
            "<md:SingleLogoutService "
            "Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" "
            f"Location=\"{slo_url}\"/>"
        )

    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" "
        "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" "
        f"entityID=\"{entity_id}\">"
        f"<md:SPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" AuthnRequestsSigned=\"{require_signed}\">"
        f"{key_descriptors}"
        f"<md:AssertionConsumerService Binding=\"{acs_binding}\" Location=\"{acs_url}\" index=\"0\" isDefault=\"true\"/>"
        f"{slo_fragment}"
        "</md:SPSSODescriptor>"
        "</md:EntityDescriptor>"
    )


@contextmanager
def _idp_server_for_app(app: Dict[str, Any]):
    """Yield a per-app PySAML2 IdP server with temporary SP metadata."""
    try:
        from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
        from saml2.config import IdPConfig
        from saml2.server import Server
    except Exception as exc:  # noqa: BLE001
        raise SamlProtocolError(f"PySAML2 is not available: {exc}") from exc

    sp_metadata_xml = _build_sp_metadata_xml(app)
    tmp_path: Optional[str] = None
    try:
        fd, tmp_path = tempfile.mkstemp(prefix="hackid-sp-meta-", suffix=".xml")
        os.close(fd)
        with open(tmp_path, "w", encoding="utf-8") as handle:
            handle.write(sp_metadata_xml)

        config_dict = {
            "entityid": SAML_IDP_ENTITY_ID,
            "xmlsec_binary": SAML_XMLSEC_BINARY,
            "key_file": get_active_key_path(),
            "cert_file": get_active_cert_path(),
            "metadata": {"local": [tmp_path]},
            "service": {
                "idp": {
                    "name": "hack-id",
                    "endpoints": {
                        "single_sign_on_service": [
                            (f"{BASE_URL}/saml/sso", BINDING_HTTP_REDIRECT),
                            (f"{BASE_URL}/saml/sso", BINDING_HTTP_POST),
                        ],
                        "single_logout_service": [
                            (f"{BASE_URL}/saml/slo", BINDING_HTTP_REDIRECT),
                            (f"{BASE_URL}/saml/slo", BINDING_HTTP_POST),
                        ],
                    },
                    "policy": {
                        "default": {
                            "lifetime": {"minutes": 10},
                            "attribute_restrictions": None,
                            "name_form": "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
                        }
                    },
                    "name_id_format": [
                        app.get("saml_nameid_format") or SAML_DEFAULT_NAMEID_FORMAT
                    ],
                }
            },
        }

        idp_config = IdPConfig()
        idp_config.load(config_dict)
        server = Server(config=idp_config)
        yield server
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except Exception:
                pass


def is_replay_request(app_id: str, request_id: str) -> bool:
    conn = get_db_connection()
    try:
        row = conn.execute(
            """
            SELECT request_id
            FROM saml_request_replay
            WHERE app_id = ? AND request_id = ? AND expires_at > ?
            """,
            (app_id, request_id, _now_epoch()),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def mark_request_replayed(app_id: str, request_id: str, ttl_seconds: int = SAML_REQUEST_REPLAY_TTL_SECONDS) -> None:
    conn = get_db_connection()
    now_epoch = _now_epoch()
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO saml_request_replay (request_id, app_id, created_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (request_id, app_id, now_epoch, now_epoch + ttl_seconds),
        )
        conn.commit()
    finally:
        conn.close()


def record_sp_session(
    *,
    app_id: str,
    user_email: str,
    name_id: str,
    session_index: str,
    ttl_seconds: int = SAML_SP_SESSION_TTL_SECONDS,
) -> None:
    conn = get_db_connection()
    now_epoch = _now_epoch()
    try:
        conn.execute(
            """
            INSERT INTO saml_sp_sessions (app_id, user_email, name_id, session_index, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                app_id,
                normalize_email(user_email),
                name_id,
                session_index,
                now_epoch,
                now_epoch + ttl_seconds,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def terminate_sp_sessions(
    *,
    app_id: str,
    session_indexes: Optional[Iterable[str]] = None,
    name_id: Optional[str] = None,
) -> int:
    conn = get_db_connection()
    deleted = 0
    try:
        if session_indexes:
            for session_index in session_indexes:
                cursor = conn.execute(
                    "DELETE FROM saml_sp_sessions WHERE app_id = ? AND session_index = ?",
                    (app_id, session_index),
                )
                deleted += int(cursor.rowcount or 0)

        if deleted == 0 and name_id:
            cursor = conn.execute(
                "DELETE FROM saml_sp_sessions WHERE app_id = ? AND name_id = ?",
                (app_id, name_id),
            )
            deleted += int(cursor.rowcount or 0)

        conn.commit()
        return deleted
    finally:
        conn.close()


def _extract_session_index_from_response_xml(response_xml: str) -> str:
    try:
        root = ET.fromstring(response_xml)
    except ET.ParseError:
        return ""

    for node in root.iter():
        if _strip_ns(node.tag) == "AuthnStatement":
            value = node.attrib.get("SessionIndex", "")
            if value:
                return value
    return ""


def _mapping_list(app: Dict[str, Any]) -> List[Dict[str, Any]]:
    value = app.get("saml_attribute_mapping_obj")
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]

    raw = app.get("saml_attribute_mapping")
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [item for item in parsed if isinstance(item, dict)]
    except (TypeError, ValueError):
        pass
    return []


def _apply_transform(values: List[str], transform: str) -> List[str]:
    def _first_word(value: str) -> str:
        parts = value.strip().split()
        return parts[0] if parts else ""

    def _last_word(value: str) -> str:
        parts = value.strip().split()
        return parts[-1] if parts else ""

    def _rest_words(value: str) -> str:
        parts = value.strip().split()
        if len(parts) <= 1:
            return ""
        return " ".join(parts[1:])

    if transform == "lowercase":
        return [value.lower() for value in values]
    if transform == "uppercase":
        return [value.upper() for value in values]
    if transform == "first_word":
        return [_first_word(value) for value in values if _first_word(value)]
    if transform == "last_word":
        return [_last_word(value) for value in values if _last_word(value)]
    if transform == "rest_words":
        return [_rest_words(value) for value in values if _rest_words(value)]
    return values


def build_identity_attributes(app: Dict[str, Any], user: Dict[str, Any]) -> Dict[str, List[str]]:
    mapping = _mapping_list(app)
    identity: Dict[str, List[str]] = {}
    display_name = user.get("preferred_name") or user.get("legal_name") or normalize_email(user.get("email", ""))

    for entry in mapping:
        source_field = entry.get("source_field")
        saml_name = entry.get("saml_name")
        if not source_field or not saml_name:
            continue

        source_value: Any
        if source_field == "display_name":
            source_value = display_name
        else:
            source_value = user.get(source_field)

        multi_valued = bool(entry.get("multi_valued"))
        if multi_valued:
            if isinstance(source_value, list):
                values = [str(item) for item in source_value if item is not None and str(item).strip()]
            elif source_value in (None, ""):
                values = []
            else:
                values = [str(source_value)]
        else:
            if source_value in (None, ""):
                values = []
            else:
                values = [str(source_value)]

        values = _apply_transform(values, entry.get("transform", "identity"))

        if bool(entry.get("required")) and not values:
            raise SamlProtocolError(f"Missing required mapped attribute: {source_field}")

        if values:
            identity[saml_name] = values

    if "email" not in identity:
        identity["email"] = [normalize_email(user.get("email", ""))]

    return identity


def _finalize_response_payload(app: Dict[str, Any], response_xml: str, relay_state: str) -> Dict[str, Any]:
    saml_response = base64.b64encode(response_xml.encode("utf-8")).decode("ascii")
    destination = app.get("saml_acs_url") or ""
    parsed = urllib.parse.urlparse(destination)
    form_action_origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""

    return {
        "destination": destination,
        "saml_response": saml_response,
        "relay_state": relay_state,
        "form_action_origin": form_action_origin,
        "session_index": _extract_session_index_from_response_xml(response_xml),
    }


def _enforce_signed_request_policy(
    *,
    app: Dict[str, Any],
    binding: str,
    xml_hint: SamlRequestHint,
    request_signature_present: bool,
    request_sigalg_present: bool,
) -> None:
    if not app.get("saml_require_signed_authn_request"):
        return

    if binding.endswith("HTTP-Redirect"):
        if not request_signature_present or not request_sigalg_present:
            raise SamlProtocolError("Signed AuthnRequest required for this app")
    else:
        if not xml_hint.has_xml_signature:
            raise SamlProtocolError("Signed AuthnRequest required for this app")


def parse_and_validate_authn_request(
    *,
    app: Dict[str, Any],
    saml_request: str,
    binding: str,
    request_signature_present: bool = False,
    request_sigalg_present: bool = False,
) -> SamlRequestHint:
    """Parse and validate AuthnRequest using PySAML2 and local app trust config."""
    xml_text = _decode_saml_message(saml_request, binding)
    hint = _extract_request_hint(xml_text)

    _enforce_signed_request_policy(
        app=app,
        binding=binding,
        xml_hint=hint,
        request_signature_present=request_signature_present,
        request_sigalg_present=request_sigalg_present,
    )

    if not hint.request_id:
        raise SamlProtocolError("AuthnRequest is missing request ID")

    if is_replay_request(app.get("id", ""), hint.request_id):
        raise SamlProtocolError("AuthnRequest replay detected")

    with _idp_server_for_app(app) as server:
        try:
            req_info = server.parse_authn_request(saml_request, binding)
            authn_req = req_info.message
        except Exception as exc:  # noqa: BLE001
            raise SamlProtocolError(f"Failed to validate AuthnRequest: {exc}") from exc

        # Prefer parser-resolved values when present.
        hint.request_id = getattr(authn_req, "id", hint.request_id) or hint.request_id
        if getattr(authn_req, "assertion_consumer_service_url", None):
            hint.acs_url = authn_req.assertion_consumer_service_url
        if getattr(authn_req, "destination", None):
            hint.destination = authn_req.destination

    mark_request_replayed(app.get("id", ""), hint.request_id)
    return hint


def create_sp_initiated_response(
    *,
    app: Dict[str, Any],
    user_email: str,
    request_hint: SamlRequestHint,
    relay_state: str,
) -> Dict[str, Any]:
    """Create and sign a SAML response for SP-initiated flow."""
    user = get_user_by_email(normalize_email(user_email))
    if not user:
        raise SamlProtocolError("User not found")

    identity = build_identity_attributes(app, user)

    try:
        from saml2 import BINDING_HTTP_POST
        from saml2.saml import NameID
    except Exception as exc:  # noqa: BLE001
        raise SamlProtocolError(f"PySAML2 runtime unavailable: {exc}") from exc

    with _idp_server_for_app(app) as server:
        name_id_text = normalize_email(user.get("email", user_email))
        name_id = NameID(
            text=name_id_text,
            format=app.get("saml_nameid_format") or SAML_DEFAULT_NAMEID_FORMAT,
        )
        try:
            response = server.create_authn_response(
                identity=identity,
                userid=name_id_text,
                name_id=name_id,
                authn=None,
                sign_response=True,
                sign_assertion=True,
                in_response_to=request_hint.request_id,
                destination=app.get("saml_acs_url"),
                sp_entity_id=app.get("saml_entity_id"),
                binding=BINDING_HTTP_POST,
            )
        except Exception as exc:  # noqa: BLE001
            raise SamlProtocolError(f"Failed to create SP-initiated SAML response: {exc}") from exc

    response_xml = str(response)
    payload = _finalize_response_payload(app, response_xml, relay_state)
    session_index = payload.get("session_index") or f"sess-{int(time.time())}"

    record_sp_session(
        app_id=app.get("id", ""),
        user_email=name_id_text,
        name_id=name_id_text,
        session_index=session_index,
    )

    log_saml_event(
        event_type="sso_sp_initiated",
        app_id=app.get("id"),
        user_email=name_id_text,
        sp_entity_id=app.get("saml_entity_id"),
        request_id=request_hint.request_id,
        session_index=session_index,
        outcome="success",
        details={"binding": app.get("saml_acs_binding")},
    )

    return payload


def create_idp_initiated_response(
    *,
    app: Dict[str, Any],
    user_email: str,
    relay_state: str,
) -> Dict[str, Any]:
    """Create and sign unsolicited SAML response for IdP-initiated launch."""
    user = get_user_by_email(normalize_email(user_email))
    if not user:
        raise SamlProtocolError("User not found")

    identity = build_identity_attributes(app, user)

    try:
        from saml2 import BINDING_HTTP_POST
        from saml2.saml import NameID
    except Exception as exc:  # noqa: BLE001
        raise SamlProtocolError(f"PySAML2 runtime unavailable: {exc}") from exc

    with _idp_server_for_app(app) as server:
        name_id_text = normalize_email(user.get("email", user_email))
        name_id = NameID(
            text=name_id_text,
            format=app.get("saml_nameid_format") or SAML_DEFAULT_NAMEID_FORMAT,
        )
        try:
            response = server.create_authn_response(
                identity=identity,
                userid=name_id_text,
                name_id=name_id,
                authn=None,
                sign_response=True,
                sign_assertion=True,
                in_response_to=None,
                destination=app.get("saml_acs_url"),
                sp_entity_id=app.get("saml_entity_id"),
                binding=BINDING_HTTP_POST,
            )
        except Exception as exc:  # noqa: BLE001
            raise SamlProtocolError(f"Failed to create IdP-initiated SAML response: {exc}") from exc

    response_xml = str(response)
    payload = _finalize_response_payload(app, response_xml, relay_state)
    session_index = payload.get("session_index") or f"sess-{int(time.time())}"

    record_sp_session(
        app_id=app.get("id", ""),
        user_email=name_id_text,
        name_id=name_id_text,
        session_index=session_index,
    )

    log_saml_event(
        event_type="sso_idp_initiated",
        app_id=app.get("id"),
        user_email=name_id_text,
        sp_entity_id=app.get("saml_entity_id"),
        session_index=session_index,
        outcome="success",
    )

    return payload


def _extract_binding_result(http_args: Dict[str, Any]) -> Dict[str, Any]:
    headers = http_args.get("headers") or []
    redirect_url = ""
    for key, value in headers:
        if str(key).lower() == "location":
            redirect_url = value
            break

    return {
        "redirect_url": redirect_url,
        "html": http_args.get("data", ""),
    }


def process_logout_request(
    *,
    app: Dict[str, Any],
    saml_request: str,
    binding: str,
    relay_state: str,
) -> Dict[str, Any]:
    """Handle incoming LogoutRequest and create a protocol-safe response."""
    hint_xml = _decode_saml_message(saml_request, binding)
    hint = _extract_request_hint(hint_xml)

    deleted = terminate_sp_sessions(
        app_id=app.get("id", ""),
        session_indexes=hint.session_indexes,
        name_id=hint.name_id,
    )

    with _idp_server_for_app(app) as server:
        try:
            req_info = server.parse_logout_request(saml_request, binding)
            logout_req = req_info.message
            logout_response = server.create_logout_response(logout_req, [binding])
            destination = app.get("saml_slo_url") or ""
            http_args = server.apply_binding(
                binding,
                str(logout_response),
                destination,
                relay_state=relay_state,
                response=True,
            )
            payload = _extract_binding_result(http_args)
        except Exception:
            # Fallback: succeed locally if protocol parsing fails.
            payload = {"redirect_url": "", "html": ""}

    log_saml_event(
        event_type="slo_request",
        app_id=app.get("id"),
        user_email=hint.name_id or None,
        sp_entity_id=app.get("saml_entity_id"),
        request_id=hint.request_id,
        session_index=(hint.session_indexes or [""])[0] or None,
        outcome="success",
        reason="session_terminated",
        details={"terminated_count": deleted},
    )

    return {
        **payload,
        "terminated_count": deleted,
        "destination": app.get("saml_slo_url") or "",
    }


def process_logout_response(
    *,
    app: Dict[str, Any],
    saml_response: str,
    binding: str,
) -> Dict[str, Any]:
    """Parse LogoutResponse best-effort and return safe status."""
    xml_text = _decode_saml_message(saml_response, binding)
    hint = _extract_request_hint(xml_text)

    log_saml_event(
        event_type="slo_response",
        app_id=app.get("id"),
        sp_entity_id=app.get("saml_entity_id"),
        request_id=hint.request_id,
        outcome="success",
    )

    return {"success": True}


def generate_idp_metadata_xml() -> str:
    """Generate public IdP metadata containing active+next signing certs."""
    metadata_url = escape(f"{BASE_URL}/saml/metadata")
    sso_url = escape(f"{BASE_URL}/saml/sso")
    slo_url = escape(f"{BASE_URL}/saml/slo")

    key_descriptors = ""
    for cert in get_idp_certificates_for_metadata():
        key_descriptors += (
            "<md:KeyDescriptor use=\"signing\">"
            "<ds:KeyInfo><ds:X509Data><ds:X509Certificate>"
            f"{escape(cert)}"
            "</ds:X509Certificate></ds:X509Data></ds:KeyInfo>"
            "</md:KeyDescriptor>"
        )

    return (
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
        "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" "
        "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" "
        f"entityID=\"{escape(SAML_IDP_ENTITY_ID)}\">"
        "<md:IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\" WantAuthnRequestsSigned=\"false\">"
        f"{key_descriptors}"
        f"<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{sso_url}\"/>"
        f"<md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"{sso_url}\"/>"
        f"<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"{slo_url}\"/>"
        f"<md:SingleLogoutService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"{slo_url}\"/>"
        "<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>"
        "</md:IDPSSODescriptor>"
        "<md:Organization>"
        "<md:OrganizationName xml:lang=\"en\">hack.sv</md:OrganizationName>"
        "<md:OrganizationDisplayName xml:lang=\"en\">hack.sv identity</md:OrganizationDisplayName>"
        "<md:OrganizationURL xml:lang=\"en\">https://hack.sv</md:OrganizationURL>"
        "</md:Organization>"
        "<md:ContactPerson contactType=\"technical\">"
        "<md:GivenName>hack.sv</md:GivenName>"
        "<md:EmailAddress>mailto:team@hack.sv</md:EmailAddress>"
        "</md:ContactPerson>"
        "</md:EntityDescriptor>"
    )
